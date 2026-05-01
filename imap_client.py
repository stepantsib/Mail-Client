import argparse
import base64
import getpass
import quopri
import re
import socket
import ssl


def custom_decode_header(val: str) -> str:
    """
    Декодирует заголовки, корректно склеивая разрезанные многобайтовые символы (UTF-8),
    группируя байты перед финальным декодированием в строку.
    """
    if not val:
        return ""

    # Убираем пробелы/переносы между закодированными блоками
    val = re.sub(r'(\?=)\s+(=\?)', r'\1\2', str(val))

    parts = []
    last_end = 0
    pattern = re.compile(r'=\?([^?]+)\?([bBqQ])\?([^?]+)\?=')

    for m in pattern.finditer(val):
        # Добавляем обычный текст, который был до закодированного блока
        if m.start() > last_end:
            parts.append(('ascii', val[last_end:m.start()].encode('ascii', 'ignore')))

        charset = m.group(1).lower()
        enc = m.group(2).lower()
        payload = m.group(3)

        try:
            if enc == 'b':  # Base64
                b = base64.b64decode(payload + '===')
            elif enc == 'q':  # Quoted-Printable
                payload = payload.replace('_', ' ').encode('ascii')
                b = re.sub(b'=([0-9A-Fa-f]{2})', lambda x: bytes([int(x.group(1), 16)]), payload)
            else:
                b = m.group(0).encode('ascii', 'ignore')
        except Exception:
            b = m.group(0).encode('ascii', 'ignore')

        parts.append((charset, b))
        last_end = m.end()

    # Добавляем хвост строки, если он есть
    if last_end < len(val):
        parts.append(('ascii', val[last_end:].encode('ascii', 'ignore')))

    # Склеиваем байты с одинаковой кодировкой
    result = ""
    current_charset = None
    current_bytes = b""

    for charset, b in parts:
        if charset == current_charset:
            current_bytes += b
        else:
            if current_charset is not None:
                result += current_bytes.decode(current_charset, errors='replace')
            current_charset = charset
            current_bytes = b

    if current_charset is not None:
        result += current_bytes.decode(current_charset, errors='replace')

    return result


def parse_raw_headers(header_bytes: bytes) -> dict[str, str]:
    """
        Разбирает сырые байты заголовков от сервера и собирает их в словарь.
        Реализует механизм Header Folding (RFC 5322), склеивая строки, разбитые
        переносами '\r\n' с последующим пробелом или табуляцией, чтобы длинные
        заголовки (например, Subject) не обрезались.
    """
    text = re.sub(r'\r\n([ \t]+)', r' \1', header_bytes.decode('utf-8', 'ignore'))
    return {k.strip().lower(): v.strip() for k, v in re.findall(r'(?m)^([^:]+):(.*)$', text)}


def parse_imap_bodystructure(s: str) -> list:
    """
        Строит абстрактное синтаксическое дерево (AST) из LISP-подобного ответа BODYSTRUCTURE.
        Использует регулярное выражение для токенизации строки (разбиения на скобки, слова
        и строки в кавычках) и рекурсивно собирает их во вложенные списки для удобной навигации.
    """

    # Разбиваем строку на 3 типа токенов: Строки в кавычках | Скобки | Слова без пробелов
    tokens = re.findall(r'"(?:\\.|[^"\\])*"|[()]|[^\s()]+', s)

    def build(it) -> list:
        res = []
        for t in it:
            if t == '(':
                res.append(build(it))
            elif t == ')':
                return res
            elif t.upper() == 'NIL':
                res.append(None)
            else:
                res.append(t.strip('"').replace('\\"', '"'))  # Убираем кавычки
        return res

    ast = build(iter(tokens))
    return ast[0] if ast else []


def extract_attachments(ast: list | str, prefix: str = "") -> list[dict]:
    """
        Рекурсивно обходит AST-дерево структуры письма для поиска вложений.
        Отслеживает иерархию (part_id), чтобы файл можно было скачать через FETCH BODY.PEEK[part_id].
    """

    def find_name(lst: list | str) -> str | None:
        if isinstance(lst, list):
            for i in range(len(lst) - 1):
                if str(lst[i]).lower() in ('name', 'filename') and isinstance(lst[i + 1], str):
                    return custom_decode_header(lst[i + 1])
            for item in lst:
                res = find_name(item)
                if res:
                    return res
        return None

    att: list[dict] = []
    if isinstance(ast, list) and ast:
        if isinstance(ast[0], str):  # Это конечный узел (MIME-часть)
            fname = find_name(ast)
            if fname:
                size = int(ast[6]) if len(ast) > 6 and str(ast[6]).isdigit() else 0
                # Если структура плоская, префикс может быть пустым. В IMAP корень часто запрашивается как "1"
                att.append({'name': fname, 'size': size, 'part_id': prefix or "1"})
        else:  # Это составной узел (multipart), идем глубже
            part_num = 1
            for item in ast:
                if isinstance(item, list):
                    # Формируем иерархический индекс: "1.2", "2", и т.д.
                    new_prefix = f"{prefix}.{part_num}" if prefix else str(part_num)
                    att.extend(extract_attachments(item, new_prefix))
                    part_num += 1
    return att


def find_text_part(ast: list | str, prefix: str = "") -> str | None:
    """
    Рекурсивно ищет текстовую часть (text/plain или text/html) в дереве BODYSTRUCTURE.
    Возвращает точный part_id (например, '1', '1.1', '2').
    """
    if isinstance(ast, list) and ast:
        if isinstance(ast[0], str):  # Это конечный узел (MIME-часть)
            mime_type = str(ast[0]).lower()
            if mime_type == "text":
                return prefix or "1"
        else:  # Это составной узел (multipart), идем вглубь
            part_num = 1
            for item in ast:
                if isinstance(item, list):
                    new_prefix = f"{prefix}.{part_num}" if prefix else str(part_num)
                    res = find_text_part(item, new_prefix)
                    if res:
                        return res
                    part_num += 1
    return None


class IMAPClient:
    def __init__(self, host: str, port: int, use_ssl: bool, verbose: bool = False) -> None:
        """
            Инициализирует объект IMAP-клиента.
            Задает базовые параметры подключения и создает счетчик тегов tag_counter
            для формирования уникальных идентификаторов команд (A001, A002...).
        """
        self.host: str = host
        self.port: int = port
        self.use_ssl: bool = use_ssl
        self.verbose: bool = verbose
        self.sock: socket.socket | None = None
        self.file = None
        self.tag_counter: int = 1

    def send_command(self, cmd: bytes, is_sensitive: bool = False) -> bytes:
        """
            Отправляет команду на сервер и читает многострочный ответ.
            Автоматически генерирует уникальный тег, прикрепляет его к запросу и накапливает
            ответ, корректно обрабатывая IMAP Literals ({размер}\r\n). При включенном verbose
            скрывает чувствительные данные (пароли) в логах.
        """
        tag = f"A{self.tag_counter:03d}".encode()
        self.tag_counter += 1
        full_cmd = tag + b' ' + cmd + b'\r\n'

        if self.verbose:
            print(
                f">>> {tag.decode()} LOGIN \"***\" \"***\"" if is_sensitive else f">>> "
                                                                                 f"{full_cmd.decode('utf-8', 'replace').strip()}")
        self.sock.sendall(full_cmd)

        lines: list[bytes] = []
        while True:
            line = self.file.readline()
            if not line:
                break
            if self.verbose and not line.startswith((b'* BODY', b'* FETCH')):
                print(f"<<< {line.decode('utf-8', 'replace').strip()}")

            lit_match = re.search(rb'\{(\d+)\+?\}\r\n$', line)
            if lit_match:  # Обработка IMAP Literals
                lines.extend([line, self.file.read(int(lit_match.group(1)))])
                continue

            lines.append(line)
            if line.startswith(tag):
                break
        return b''.join(lines)

    def connect(self) -> None:
        """
            Устанавливает TCP-соединение с IMAP-сервером.
            Поддерживает неявный SSL при подключении к порту 993. Для стандартных портов
            запрашивает возможности сервера (CAPABILITY) и при наличии STARTTLS переводит
            открытое соединение в защищенный TLS-контекст.
        """
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(60)
        if self.use_ssl and self.port == 993:
            self.sock = ssl.create_default_context().wrap_socket(self.sock, server_hostname=self.host)

        self.sock.connect((self.host, self.port))
        self.file = self.sock.makefile('rb')
        if self.verbose:
            print(f"<<< {self.file.readline().decode('utf-8', 'replace').strip()}")

        if self.use_ssl and self.port != 993:  # Явный STARTTLS
            if b'STARTTLS' in self.send_command(b'CAPABILITY'):
                if b'OK' in self.send_command(b'STARTTLS').split(b'\r\n')[-2]:
                    self.sock = ssl.create_default_context().wrap_socket(self.sock, server_hostname=self.host)
                    self.file = self.sock.makefile('rb')

    def fetch_info(self, start: int, end: int) -> tuple[
        dict[int, int], dict[int, dict[str, str]], dict[int, list[dict]]]:
        """
            Запрашивает у сервера информацию о диапазоне писем.
            Отправляет три последовательные команды FETCH. Использует кастомные парсеры
            для распаковки сырых байтов заголовков, их декодирования и извлечения
            данных о файлах вложениях из структуры BODYSTRUCTURE.
        """
        sz: dict[int, int] = {}
        hdrs: dict[int, dict[str, str]] = {}
        atts: dict[int, list[dict]] = {}

        # 1. Запрашиваем размеры
        for m in re.finditer(rb'\* (\d+) FETCH .*?RFC822\.SIZE (\d+)',
                             self.send_command(f'FETCH {start}:{end} RFC822.SIZE'.encode())):
            sz[int(m.group(1))] = int(m.group(2))

        # 2. Запрашиваем заголовки
        for blk in self.send_command(f'FETCH {start}:{end} BODY.PEEK[HEADER]'.encode()).split(b'* '):
            m2 = re.search(rb'(\d+)\s+FETCH.*?\{(\d+)\+?\}\r\n', blk)
            if m2:
                mid, size = int(m2.group(1)), int(m2.group(2))
                raw_hdrs = parse_raw_headers(blk[m2.end(): m2.end() + size])
                hdrs[mid] = {k: custom_decode_header(raw_hdrs.get(k.lower(), '')) for k in
                             ('To', 'From', 'Subject', 'Date')}

        # 3. Запрашиваем структуру (BODYSTRUCTURE)
        for blk in self.send_command(f'FETCH {start}:{end} BODYSTRUCTURE'.encode()).split(b'* '):
            m3 = re.search(rb'(\d+)\s+FETCH', blk)
            idx = blk.find(b'BODYSTRUCTURE')
            if m3 and idx != -1:
                ast = parse_imap_bodystructure(blk[blk.find(b'(', idx):].decode('utf-8', 'ignore'))
                atts[int(m3.group(1))] = extract_attachments(ast)

        return sz, hdrs, atts

    def create_folder(self, folder_name: str) -> None:
        """Создает новую почтовую папку"""
        resp = self.send_command(f'CREATE "{folder_name}"'.encode())
        if b'OK' not in resp:
            raise RuntimeError(f"Ошибка создания папки: {resp}")

    def delete_email(self, msg_id: int) -> None:
        """Помечает письмо на удаление и очищает ящик"""
        resp = self.send_command(f'STORE {msg_id} +FLAGS (\\Deleted)'.encode())
        if b'OK' not in resp:
            raise RuntimeError(f"Ошибка пометки письма {msg_id} на удаление: {resp}")
        self.send_command(b'EXPUNGE')

    def move_email(self, msg_id: int, folder_name: str) -> None:
        """Копирует письмо в другую папку и удаляет из текущей"""
        resp = self.send_command(f'COPY {msg_id} "{folder_name}"'.encode())
        if b'OK' in resp:
            self.delete_email(msg_id)
        else:
            raise RuntimeError(f"Ошибка перемещения письма {msg_id}: {resp}")

    def fetch_email_body(self, msg_id: int) -> str:
        """Извлекает и декодирует текстовую часть письма, очищая её от HTML-тегов"""

        # 1. Узнаем точный part_id текста из структуры письма
        struct_resp = self.send_command(f'FETCH {msg_id} BODYSTRUCTURE'.encode())
        idx = struct_resp.find(b'BODYSTRUCTURE')
        part_id = "1"

        if idx != -1:
            ast_str = struct_resp[struct_resp.find(b'(', idx):].decode('utf-8', 'ignore')
            ast = parse_imap_bodystructure(ast_str)
            found_id = find_text_part(ast)
            if found_id:
                part_id = found_id

        # 2. Запрашиваем MIME-заголовки и тело письма
        mime_resp = self.send_command(f'FETCH {msg_id} BODY.PEEK[{part_id}.MIME]'.encode())
        body_resp = self.send_command(f'FETCH {msg_id} BODY.PEEK[{part_id}]'.encode())

        # ИСПРАВЛЕНИЕ №1: проверяем только тег-строку (последняя строка ответа),
        # а не весь ответ. Иначе слова NO/BAD в теле письма дают ложное срабатывание.
        def is_imap_error(resp: bytes) -> bool:
            for line in reversed(resp.split(b'\r\n')):
                if re.match(rb'^A\d{3} ', line):
                    return bool(re.match(rb'^A\d{3} (NO|BAD)\b', line))
            return False

        if is_imap_error(body_resp):
            mime_resp = self.send_command(f'FETCH {msg_id} BODY.PEEK[HEADER]'.encode())
            body_resp = self.send_command(f'FETCH {msg_id} BODY.PEEK[TEXT]'.encode())

        # ИСПРАВЛЕНИЕ №2: фильтруем строки точно по паттерну IMAP-тега (A001, A002...),
        # а не по любой строке, начинающейся с буквы A.
        def clean_imap_response(resp: bytes) -> bytes:
            lines = resp.split(b'\r\n')
            clean_lines = []
            for line in lines[1:-2]:
                is_tag_line = bool(re.match(rb'^A\d{3}\s', line))
                is_untagged = line.startswith(b'* ')
                if not is_tag_line and not is_untagged:
                    clean_lines.append(line)
            return b'\r\n'.join(clean_lines)

        mime_headers = clean_imap_response(mime_resp).decode('utf-8', errors='ignore').lower()
        content = clean_imap_response(body_resp)

        if not mime_headers.strip():
            mime_resp = self.send_command(f'FETCH {msg_id} BODY.PEEK[HEADER]'.encode())
            mime_headers = clean_imap_response(mime_resp).decode('utf-8', errors='ignore').lower()

        # 3. Декодирование (Base64 или Quoted-Printable)
        if 'content-transfer-encoding: base64' in mime_headers:
            try:
                content = base64.b64decode(content)
            except Exception:
                pass
        elif 'content-transfer-encoding: quoted-printable' in mime_headers:
            try:
                content = quopri.decodestring(content)
            except Exception:
                pass

        # 4. Определяем кодировку и переводим в строку
        charset = 'utf-8'
        charset_match = re.search(r'charset=["\']?([\w-]+)["\']?', mime_headers)
        if charset_match:
            charset = charset_match.group(1)

        text = content.decode(charset, errors='replace')

        # 5. Очищаем от HTML-разметки
        if '<html' in text.lower() or '<body' in text.lower() or '<div' in text.lower():
            import html
            text = re.sub(r'<(style|script)[^>]*>.*?</\1>', '', text, flags=re.IGNORECASE | re.DOTALL)
            text = re.sub(r'<[^>]+>', '', text)
            text = html.unescape(text)
            text = re.sub(r'\n\s*\n', '\n\n', text.strip())

        return text

    def download_attachment(self, msg_id: int, part_id: str, save_path: str) -> None:
        """Скачивает вложение по его part_id и сохраняет на диск"""
        mime_resp = self.send_command(f'FETCH {msg_id} BODY.PEEK[{part_id}.MIME]'.encode())
        body_resp = self.send_command(f'FETCH {msg_id} BODY.PEEK[{part_id}]'.encode())

        def extract_payload(resp: bytes) -> bytes:
            m = re.search(rb'\{(\d+)\+?\}\r\n', resp)
            if m:
                return resp[m.end():m.end() + int(m.group(1))]
            m_quote = re.search(rb'\[.*?\]\s+"([^"]*)"', resp)
            if m_quote:
                return m_quote.group(1)
            return b""

        mime_headers = extract_payload(mime_resp).decode('utf-8', 'ignore').lower()
        raw_data = extract_payload(body_resp)

        if 'content-transfer-encoding: base64' in mime_headers:
            raw_data = base64.b64decode(raw_data)
        elif 'content-transfer-encoding: quoted-printable' in mime_headers:
            raw_data = quopri.decodestring(raw_data)

        with open(save_path, "wb") as f:
            f.write(raw_data)

    def list_folders(self) -> list[str]:
        """Возвращает список всех папок почтового ящика"""
        resp = self.send_command(b'LIST "" "*"')
        folders = []
        for line in resp.split(b'\r\n'):
            # Формат: * LIST (\Flags) "/" "Folder Name"
            m = re.search(rb'\* LIST \([^)]*\) "[^"]*" (.+)$', line)
            if m:
                name = m.group(1).decode('utf-8', 'replace').strip().strip('"')
                folders.append(name)
        return folders


def main() -> None:
    """
        Точка входа в программу.
        Обрабатывает аргументы командной строки, скрыто запрашивает пароль,
        устанавливает защищенную сессию с сервером и выводит красиво отформатированную
        таблицу со списком писем в консоль.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--server', required=True)
    parser.add_argument('-u', '--user', required=True)
    parser.add_argument('--ssl', action='store_true')
    parser.add_argument('-n', nargs='+', type=int)
    parser.add_argument('-v', '--verbose', action='store_true')
    args = parser.parse_args()

    host, port = (args.server.rsplit(':', 1) + [143])[:2] if ':' in args.server else (args.server, 143)
    pwd = getpass.getpass("Пароль: ").replace(" ", "").strip()

    client = IMAPClient(host, int(port), args.ssl, args.verbose)
    try:
        client.connect()
        try:
            client.sock.settimeout(120)
            if b"OK" not in client.send_command(f'LOGIN "{args.user}" "{pwd}"'.encode(), True).split(b'\r\n')[-2]:
                raise RuntimeError("Ошибка авторизации")
            client.sock.settimeout(60)
        except socket.timeout:
            raise RuntimeError("Таймаут авторизации! Google заморозил соединение.")

        m = re.search(rb'\* (\d+) EXISTS', client.send_command(b'SELECT INBOX'))
        total_msgs = int(m.group(1)) if m else 0
        if total_msgs == 0:
            print("В ящике INBOX нет писем.")
            return

        start = max(1, args.n[0] if args.n else 1)
        end = min(total_msgs, args.n[1] if args.n and len(args.n) > 1 else (start if args.n else total_msgs))
        if start > end:
            print(f"Неверный диапазон. Всего писем: {total_msgs}")
            return

        print("\nПолучение данных с сервера...\n")
        sizes, headers, attachments = client.fetch_info(start, end)

        print(f"{'ID':<4} | {'От кого':<25} | {'Кому':<25} | {'Тема':<35} | {'Дата':<20} | {'Размер':<8} | Аттачи")
        print("-" * 150)

        fmt = lambda t, l: (t[:l - 3] + '...') if len(t) > l else t
        for i in range(start, end + 1):
            if i not in headers: continue
            h, s, a = headers[i], sizes.get(i, 0), attachments.get(i, [])
            att_str = f"{len(a)} шт. [{', '.join(f'{at['name']} ({at['size']}B)' for at in a)}]" if a else "Нет"
            print(
                f"{i:<4} | {fmt(h['From'], 25):<25} | {fmt(h['To'], 25):<25} | {fmt(h['Subject'], 35):<35} | "
                f"{h['Date'][:20]:<20} | {s:<8} | {att_str}")

    except Exception as e:
        print(f"\nОшибка: {e}")


if __name__ == "__main__":
    main()
