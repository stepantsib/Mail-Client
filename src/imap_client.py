import argparse
import base64
import binascii
import getpass
import html
import quopri
import re
import socket
import ssl
from typing import Any, BinaryIO

from validators import parse_hostport


def custom_decode_header(val: str) -> str:
    """
    Декодирует заголовки, корректно склеивая разрезанные многобайтовые
    символы (UTF-8),
    группируя байты перед финальным декодированием в строку.
    """
    if not val:
        return ""

    # Убираем пробелы/переносы между закодированными блоками
    val = re.sub(r"(\?=)\s+(=\?)", r"\1\2", str(val))

    parts = []
    last_end = 0
    pattern = re.compile(r"=\?([^?]+)\?([bBqQ])\?([^?]+)\?=")

    for m in pattern.finditer(val):
        # Добавляем обычный текст, который был до закодированного блока
        if m.start() > last_end:
            parts.append(("ascii", val[last_end : m.start()].encode("ascii", "ignore")))

        charset = m.group(1).lower()
        enc = m.group(2).lower()
        payload = m.group(3)

        try:
            if enc == "b":  # Base64
                b = base64.b64decode(payload + "===")
            elif enc == "q":  # Quoted-Printable
                payload = payload.replace("_", " ").encode("ascii")
                b = re.sub(b"=([0-9A-Fa-f]{2})", lambda x: bytes([int(x.group(1), 16)]), payload)
            else:
                b = m.group(0).encode("ascii", "ignore")
        except Exception:
            b = m.group(0).encode("ascii", "ignore")

        parts.append((charset, b))
        last_end = m.end()

    # Добавляем хвост строки, если он есть
    if last_end < len(val):
        parts.append(("ascii", val[last_end:].encode("ascii", "ignore")))

    # Склеиваем байты с одинаковой кодировкой
    result = ""
    current_charset = None
    current_bytes = b""

    for charset, b in parts:
        if charset == current_charset:
            current_bytes += b
        else:
            if current_charset is not None:
                result += current_bytes.decode(current_charset, errors="replace")
            current_charset = charset
            current_bytes = b

    if current_charset is not None:
        result += current_bytes.decode(current_charset, errors="replace")

    return result


def parse_raw_headers(header_bytes: bytes) -> dict[str, str]:
    """
    Разбирает сырые байты заголовков от сервера и собирает их в словарь.
    Реализует механизм Header Folding (RFC 5322), склеивая строки, разбитые
    переносами '\r\n' с последующим пробелом или табуляцией, чтобы длинные
    заголовки (например, Subject) не обрезались.
    """
    text = re.sub(r"\r\n([ \t]+)", r" \1", header_bytes.decode("utf-8", "ignore"))
    return {k.strip().lower(): v.strip() for k, v in re.findall(r"(?m)^([^:]+):(.*)$", text)}


def parse_imap_bodystructure(s: str) -> list:
    """
    Строит абстрактное синтаксическое дерево (AST) из LISP-подобного
    ответа BODYSTRUCTURE.
    Использует регулярное выражение для токенизации строки (разбиения на
    скобки, слова
    и строки в кавычках) и рекурсивно собирает их во вложенные списки для
    удобной навигации.
    """

    # Разбиваем строку на 3 типа токенов: Строки в кавычках | Скобки | Слова
    # без пробелов
    tokens = re.findall(r'"(?:\\.|[^"\\])*"|[()]|[^\s()]+', s)

    def build(it) -> list[Any]:
        res: list[Any] = []
        for t in it:
            if t == "(":
                res.append(build(it))
            elif t == ")":
                return res
            elif t.upper() == "NIL":
                res.append(None)
            else:
                res.append(t.strip('"').replace('\\"', '"'))  # Убираем кавычки
        return res

    ast = build(iter(tokens))
    return ast[0] if ast else []


def walk_bodystructure(ast: list | str, prefix: str = ""):
    """Генератор: обходит AST BODYSTRUCTURE и выдаёт (part_id, leaf_node).

    leaf_node — это сам список вида ['text', 'plain', ('charset', 'utf-8'), ...].
    Через этот генератор реализованы и поиск вложений, и поиск text-частей —
    раньше каркас обхода дублировался в каждой функции.
    """
    if not isinstance(ast, list) or not ast:
        return
    if isinstance(ast[0], str):  # Конечный узел (MIME-часть)
        yield prefix or "1", ast
        return
    part_num = 1
    for item in ast:
        if isinstance(item, list):
            new_prefix = f"{prefix}.{part_num}" if prefix else str(part_num)
            yield from walk_bodystructure(item, new_prefix)
            part_num += 1


def _find_attachment_name(leaf: list) -> str | None:
    """Ищет name/filename в параметрах MIME-части (RFC 3501 BODYSTRUCTURE)."""

    def search(lst: list | str) -> str | None:
        if not isinstance(lst, list):
            return None
        for i in range(len(lst) - 1):
            if str(lst[i]).lower() in ("name", "filename") and isinstance(lst[i + 1], str):
                return custom_decode_header(lst[i + 1])
        for item in lst:
            res = search(item)
            if res:
                return res
        return None

    return search(leaf)


def extract_attachments(ast: list | str, prefix: str = "") -> list[dict]:
    """Возвращает список вложений в виде ``[{name, size, part_id}, ...]``."""
    out: list[dict] = []
    for part_id, leaf in walk_bodystructure(ast, prefix):
        fname = _find_attachment_name(leaf)
        if fname:
            size = int(leaf[6]) if len(leaf) > 6 and str(leaf[6]).isdigit() else 0
            out.append({"name": fname, "size": size, "part_id": part_id})
    return out


def find_text_part(ast: list | str, prefix: str = "") -> str | None:
    """Возвращает part_id первой text-части в дереве BODYSTRUCTURE (или None)."""
    for part_id, leaf in walk_bodystructure(ast, prefix):
        if str(leaf[0]).lower() == "text":
            return str(part_id)
    return None


def _modutf7_encode(name: str) -> str:
    """RFC 3501 §5.1.3 Modified UTF-7 — обязательная кодировка имён IMAP-папок."""
    out: list[str] = []
    buf: list[str] = []

    def flush() -> None:
        if not buf:
            return
        b64 = base64.b64encode("".join(buf).encode("utf-16-be")).decode("ascii")
        out.append("&" + b64.rstrip("=").replace("/", ",") + "-")
        buf.clear()

    for ch in name:
        if 0x20 <= ord(ch) <= 0x7E:
            flush()
            out.append("&-" if ch == "&" else ch)
        else:
            buf.append(ch)
    flush()
    return "".join(out)


def _sanitize_folder_name(name: str) -> str:
    """Кодирует имя в Modified UTF-7 и экранирует спецсимволы quoted-string."""
    encoded = _modutf7_encode(name)
    return encoded.replace("\\", "\\\\").replace('"', '\\"')


def _imap_literal(value: str) -> bytes:
    """Безопасно сериализует произвольную строку в IMAP-аргумент.

    Для не-ASCII или управляющих символов используется literal ``{N}\\r\\n<bytes>`` —
    это устраняет IMAP-инъекцию через логин/пароль (RFC 3501 §4.3).
    """
    raw = value.encode("utf-8")
    if any(b < 0x20 or b > 0x7E for b in raw):
        return b"{" + str(len(raw)).encode("ascii") + b"}\r\n" + raw
    escaped = raw.replace(b"\\", b"\\\\").replace(b'"', b'\\"')
    return b'"' + escaped + b'"'


_LITERAL_RE = re.compile(rb"\{(\d+)\+?\}\r\n")
_TAG_OK_RE = re.compile(rb"^A\d+ (OK|NO|BAD)\b")


def extract_imap_literal(resp: bytes) -> bytes:
    """Извлекает первый IMAP literal ``{N}\\r\\n<N байтов>`` из ответа сервера.

    Надёжнее, чем ``split('\\r\\n')`` + slice — последнее ломается на коротких
    ответах и на телах писем, начинающихся с ``* `` (RFC 3501 §4.3).
    """
    m = _LITERAL_RE.search(resp)
    return resp[m.end() : m.end() + int(m.group(1))] if m else b""


def imap_response_ok(resp: bytes) -> bool:
    """Возвращает True, если последняя тэг-строка ответа — ``<TAG> OK``.

    Корректно отделяет тэг-строку от untagged data (``* ...``) и от тела письма,
    избегая ложных срабатываний на слово "OK" внутри payload.
    """
    for line in reversed(resp.split(b"\r\n")):
        m = _TAG_OK_RE.match(line)
        if m:
            return m.group(1) == b"OK"
    return False


def decode_cte(content: bytes, mime_headers: str) -> bytes:
    """Декодирует Content-Transfer-Encoding: base64 / quoted-printable.

    При ошибке декодирования возвращает исходные байты — лучше показать сырое,
    чем уронить функцию (раньше один путь молча игнорировал ошибки, другой —
    падал; теперь поведение симметрично).
    """
    h = mime_headers.lower()
    if "content-transfer-encoding: base64" in h:
        try:
            return base64.b64decode(content)
        except (binascii.Error, ValueError):
            return content
    if "content-transfer-encoding: quoted-printable" in h:
        try:
            return quopri.decodestring(content)
        except ValueError:
            return content
    return content


class IMAPClient:
    def __init__(self, host: str, port: int, use_ssl: bool, verbose: bool = False) -> None:
        """
        Инициализирует объект IMAP-клиента.
        Задает базовые параметры подключения и создает счетчик тегов
        tag_counter
        для формирования уникальных идентификаторов команд (A001, A002...).
        """
        self.host: str = host
        self.port: int = port
        self.use_ssl: bool = use_ssl
        self.verbose: bool = verbose
        self.sock: socket.socket | None = None
        self.file: BinaryIO | None = None
        self.tag_counter: int = 1

    def send_command(self, cmd: bytes, is_sensitive: bool = False) -> bytes:
        """
        Отправляет команду на сервер и читает многострочный ответ.
        Автоматически генерирует уникальный тег, прикрепляет его к
        запросу и накапливает
        ответ, корректно обрабатывая IMAP Literals ({размер}\r\n). При
        включенном verbose
        скрывает чувствительные данные (пароли) в логах.
        """
        assert self.sock is not None
        assert self.file is not None
        tag = f"A{self.tag_counter:03d}".encode()
        self.tag_counter += 1
        full_cmd = tag + b" " + cmd + b"\r\n"

        if self.verbose:
            print(
                f'>>> {tag.decode()} LOGIN "***" "***"'
                if is_sensitive
                else f">>> {full_cmd.decode('utf-8', 'replace').strip()}"
            )
        self.sock.sendall(full_cmd)

        lines: list[bytes] = []
        while True:
            line = self.file.readline()
            if not line:
                break
            if self.verbose and not line.startswith((b"* BODY", b"* FETCH")):
                print(f"<<< {line.decode('utf-8', 'replace').strip()}")

            lit_match = _LITERAL_RE.search(line)
            # literal должен стоять в самом конце строки — иначе это просто фигурная
            # скобка где-то в payload, а не маркер `{N}\r\n<bytes>`.
            if lit_match and lit_match.end() == len(line):
                lines.extend([line, self.file.read(int(lit_match.group(1)))])
                continue

            lines.append(line)
            if line.startswith(tag):
                break
        return b"".join(lines)

    def connect(self) -> None:
        """
        Устанавливает TCP-соединение с IMAP-сервером.
        Поддерживает неявный SSL при подключении к порту 993. Для
        стандартных портов
        запрашивает возможности сервера (CAPABILITY) и при наличии
        STARTTLS переводит
        открытое соединение в защищенный TLS-контекст.
        """
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(60)
        if self.use_ssl and self.port == 993:
            self.sock = ssl.create_default_context().wrap_socket(
                self.sock, server_hostname=self.host
            )

        self.sock.connect((self.host, self.port))
        self.file = self.sock.makefile("rb")
        if self.verbose:
            print(f"<<< {self.file.readline().decode('utf-8', 'replace').strip()}")

        if self.use_ssl and self.port != 993:  # Явный STARTTLS
            if b"STARTTLS" in self.send_command(b"CAPABILITY"):
                if imap_response_ok(self.send_command(b"STARTTLS")):
                    self.sock = ssl.create_default_context().wrap_socket(
                        self.sock, server_hostname=self.host
                    )
                    self.file = self.sock.makefile("rb")

    def fetch_info(
        self, start: int, end: int
    ) -> tuple[dict[int, int], dict[int, dict[str, str]], dict[int, list[dict]]]:
        """
        Запрашивает у сервера информацию о диапазоне писем.
        Отправляет три последовательные команды FETCH. Использует
        кастомные парсеры
        для распаковки сырых байтов заголовков, их декодирования и
        извлечения
        данных о файлах вложениях из структуры BODYSTRUCTURE.
        """
        sz: dict[int, int] = {}
        hdrs: dict[int, dict[str, str]] = {}
        atts: dict[int, list[dict]] = {}

        # 1. Запрашиваем размеры
        for m in re.finditer(
            rb"\* (\d+) FETCH .*?RFC822\.SIZE (\d+)",
            self.send_command(f"FETCH {start}:{end} RFC822.SIZE".encode()),
        ):
            sz[int(m.group(1))] = int(m.group(2))

        # 2. Запрашиваем заголовки
        for blk in self.send_command(f"FETCH {start}:{end} BODY.PEEK[HEADER]".encode()).split(
            b"* "
        ):
            m2 = re.search(rb"(\d+)\s+FETCH.*?\{(\d+)\+?\}\r\n", blk)
            if m2:
                mid, size = int(m2.group(1)), int(m2.group(2))
                raw_hdrs = parse_raw_headers(blk[m2.end() : m2.end() + size])
                hdrs[mid] = {
                    k: custom_decode_header(raw_hdrs.get(k.lower(), ""))
                    for k in ("To", "From", "Subject", "Date")
                }

        # 3. Запрашиваем структуру (BODYSTRUCTURE)
        for blk in self.send_command(f"FETCH {start}:{end} BODYSTRUCTURE".encode()).split(b"* "):
            m3 = re.search(rb"(\d+)\s+FETCH", blk)
            idx = blk.find(b"BODYSTRUCTURE")
            if m3 and idx != -1:
                ast = parse_imap_bodystructure(blk[blk.find(b"(", idx) :].decode("utf-8", "ignore"))
                atts[int(m3.group(1))] = extract_attachments(ast)

        return sz, hdrs, atts

    def login(self, user: str, password: str) -> bytes:
        """Аутентифицируется через IMAP literal — закрывает IMAP-инъекцию."""
        cmd = b"LOGIN " + _imap_literal(user) + b" " + _imap_literal(password)
        return self.send_command(cmd, is_sensitive=True)

    def select_folder(self, folder_name: str) -> bytes:
        """Открывает папку с UTF-7 + quoted-string-экранированием.

        Единая точка для всех вызовов SELECT — невозможно забыть санитизацию
        в новом месте использования.
        """
        safe = _sanitize_folder_name(folder_name)
        return self.send_command(f'SELECT "{safe}"'.encode())

    def create_folder(self, folder_name: str) -> None:
        safe_name = _sanitize_folder_name(folder_name)
        resp = self.send_command(f'CREATE "{safe_name}"'.encode())
        if not imap_response_ok(resp):
            raise RuntimeError(f"Ошибка создания папки: {resp.decode('utf-8', 'ignore')}")

    def delete_email(self, msg_id: int) -> None:
        resp = self.send_command(f"STORE {msg_id} +FLAGS (\\Deleted)".encode())
        if not imap_response_ok(resp):
            raise RuntimeError(
                f"Ошибка пометки письма {msg_id} на удаление: {resp.decode('utf-8', 'ignore')}"
            )
        # EXPUNGE без UID удаляет все помеченные \\Deleted письма. Для изоляции желательно
        # UID EXPUNGE (RFC 4315 UIDPLUS), но это расширение и есть не на всех серверах.
        self.send_command(b"EXPUNGE")

    def move_email(self, msg_id: int, folder_name: str) -> None:
        safe_name = _sanitize_folder_name(folder_name)
        resp = self.send_command(f'COPY {msg_id} "{safe_name}"'.encode())
        if not imap_response_ok(resp):
            raise RuntimeError(
                f"Ошибка перемещения письма {msg_id}: {resp.decode('utf-8', 'ignore')}"
            )
        self.delete_email(msg_id)

    def fetch_email_body(self, msg_id: int) -> str:
        """Извлекает и декодирует текстовую часть письма, очищая её от
        HTML-тегов"""

        # 1. Узнаем точный part_id текста из структуры письма
        struct_resp = self.send_command(f"FETCH {msg_id} BODYSTRUCTURE".encode())
        idx = struct_resp.find(b"BODYSTRUCTURE")
        part_id = "1"

        if idx != -1:
            ast_str = struct_resp[struct_resp.find(b"(", idx) :].decode("utf-8", "ignore")
            ast = parse_imap_bodystructure(ast_str)
            found_id = find_text_part(ast)
            if found_id:
                part_id = found_id

        # 2. Запрашиваем MIME-заголовки и тело письма
        mime_resp = self.send_command(f"FETCH {msg_id} BODY.PEEK[{part_id}.MIME]".encode())
        body_resp = self.send_command(f"FETCH {msg_id} BODY.PEEK[{part_id}]".encode())

        # Если сервер вернул NO/BAD на BODY.PEEK[1] — пробуем общий fallback на TEXT.
        if not imap_response_ok(body_resp):
            mime_resp = self.send_command(f"FETCH {msg_id} BODY.PEEK[HEADER]".encode())
            body_resp = self.send_command(f"FETCH {msg_id} BODY.PEEK[TEXT]".encode())

        mime_headers = extract_imap_literal(mime_resp).decode("utf-8", errors="ignore").lower()
        content = extract_imap_literal(body_resp)

        if not mime_headers.strip():
            mime_resp = self.send_command(f"FETCH {msg_id} BODY.PEEK[HEADER]".encode())
            mime_headers = extract_imap_literal(mime_resp).decode("utf-8", errors="ignore").lower()

        # 3. Декодирование Content-Transfer-Encoding (base64 / quoted-printable)
        content = decode_cte(content, mime_headers)

        # 4. Определяем кодировку и переводим в строку. Fallback на utf-8 для
        # несуществующих имён charset (раньше падал LookupError).
        charset = "utf-8"
        charset_match = re.search(r'charset=["\']?([\w-]+)["\']?', mime_headers)
        if charset_match:
            charset = charset_match.group(1)
        try:
            text = content.decode(charset, errors="replace")
        except LookupError:
            text = content.decode("utf-8", errors="replace")

        # 5. Очищаем от HTML-разметки. text.lower() считаем один раз — раньше было ×3.
        lower = text.lower()
        if "<html" in lower or "<body" in lower or "<div" in lower:
            text = re.sub(
                r"<(style|script)[^>]*>.*?</\1>", "", text, flags=re.IGNORECASE | re.DOTALL
            )
            text = re.sub(r"<[^>]+>", "", text)
            text = html.unescape(text)
            text = re.sub(r"\n\s*\n", "\n\n", text.strip())

        return text

    def download_attachment(self, msg_id: int, part_id: str, save_path: str) -> None:
        """Скачивает вложение по его part_id и сохраняет на диск"""
        mime_resp = self.send_command(f"FETCH {msg_id} BODY.PEEK[{part_id}.MIME]".encode())
        body_resp = self.send_command(f"FETCH {msg_id} BODY.PEEK[{part_id}]".encode())

        mime_headers = extract_imap_literal(mime_resp).decode("utf-8", "ignore").lower()
        raw_data = extract_imap_literal(body_resp)
        if not raw_data:
            # Fallback: некоторые серверы возвращают короткие части как
            # quoted-string — `[...] "payload"` — без literal.
            m_quote = re.search(rb'\[.*?\]\s+"([^"]*)"', body_resp)
            if m_quote:
                raw_data = m_quote.group(1)

        raw_data = decode_cte(raw_data, mime_headers)

        with open(save_path, "wb") as f:
            f.write(raw_data)

    def list_folders(self) -> list[str]:
        """Возвращает список всех папок почтового ящика"""
        resp = self.send_command(b'LIST "" "*"')
        folders = []
        for line in resp.split(b"\r\n"):
            # Формат: * LIST (\Flags) "/" "Folder Name"
            m = re.search(rb'\* LIST \([^)]*\) "[^"]*" (.+)$', line)
            if m:
                name = m.group(1).decode("utf-8", "replace").strip().strip('"')
                folders.append(name)
        return folders


def main() -> None:
    """
    Точка входа в программу.
    Обрабатывает аргументы командной строки, скрыто запрашивает пароль,
    устанавливает защищенную сессию с сервером и выводит красиво
    отформатированную
    таблицу со списком писем в консоль.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--server", required=True)
    parser.add_argument("-u", "--user", required=True)
    parser.add_argument("--ssl", action="store_true")
    parser.add_argument("-n", nargs="+", type=int)
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    host, port = parse_hostport(args.server, 143)
    pwd = getpass.getpass("Пароль: ")  # Не trim-аем: пробелы в пароле допустимы.

    client = IMAPClient(host, port, args.ssl, args.verbose)
    try:
        client.connect()
        assert client.sock is not None
        try:
            client.sock.settimeout(120)
            login_resp = client.login(args.user, pwd)
            if not imap_response_ok(login_resp):
                raise RuntimeError("Ошибка авторизации")
            client.sock.settimeout(60)
        except TimeoutError:
            raise RuntimeError("Таймаут авторизации! Google заморозил соединение.")

        m = re.search(rb"\* (\d+) EXISTS", client.send_command(b"SELECT INBOX"))
        total_msgs = int(m.group(1)) if m else 0
        if total_msgs == 0:
            print("В ящике INBOX нет писем.")
            return

        start = max(1, args.n[0] if args.n else 1)
        end = min(
            total_msgs,
            args.n[1] if args.n and len(args.n) > 1 else (start if args.n else total_msgs),
        )
        if start > end:
            print(f"Неверный диапазон. Всего писем: {total_msgs}")
            return

        print("\nПолучение данных с сервера...\n")
        sizes, headers, attachments = client.fetch_info(start, end)

        print(
            f"{'ID':<4} | {'От кого':<25} | {'Кому':<25} | {'Тема':<35} | "
            f"{'Дата':<20} | {'Размер':<8} | Аттачи"
        )
        print("-" * 150)

        def fmt(text: str, length: int) -> str:
            return (text[: length - 3] + "...") if len(text) > length else text

        for i in range(start, end + 1):
            if i not in headers:
                continue
            h, s, a = headers[i], sizes.get(i, 0), attachments.get(i, [])
            att_str = (
                (f"{len(a)} шт. [{', '.join(f'{at["name"]} ({at["size"]}B)' for at in a)}]")
                if a
                else "Нет"
            )
            print(
                f"{i:<4} | {fmt(h['From'], 25):<25} | {fmt(h['To'], 25):<25} | "
                f"{fmt(h['Subject'], 35):<35} | "
                f"{h['Date'][:20]:<20} | {s:<8} | {att_str}"
            )

    except Exception as e:
        print(f"\nОшибка: {e}")


if __name__ == "__main__":
    main()
