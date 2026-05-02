import argparse
import datetime
import getpass
import os
import socket
import ssl
import uuid
from base64 import b64encode

from validators import parse_hostport


def b64_mime_wrap(data: bytes, width: int = 76) -> str:
    """Кодирует ``data`` в base64 и переносит каждые ``width`` символов (RFC 2045 §6.8)."""
    s = b64encode(data).decode("ascii")
    return "\r\n".join(s[i : i + width] for i in range(0, len(s), width))


def _sanitize_addr(addr: str) -> str:
    """Удаляет CR/LF из адреса — защита от SMTP header-injection."""
    cleaned = addr.replace("\r", "").replace("\n", "").strip().strip("<>")
    if not cleaned:
        raise ValueError("Адрес не может быть пустым")
    return cleaned


def _encode_header_value(value: str) -> str:
    """Вычищает CRLF и кодирует не-ASCII в RFC 2047 (=?utf-8?B?...?=)."""
    cleaned = value.replace("\r", " ").replace("\n", " ")
    try:
        cleaned.encode("ascii")
        return cleaned
    except UnicodeEncodeError:
        return "=?utf-8?B?" + b64encode(cleaned.encode("utf-8")).decode("ascii") + "?="


class SMTPClient:
    """Низкоуровневый SMTP-клиент с обработкой многострочных ответов"""

    def __init__(self, host: str, port: int, use_ssl: bool, verbose: bool):
        """
        Инициализирует объект SMTP-клиента.
        """
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.verbose = verbose
        self.sock = None
        self.is_tls = False
        self.capabilities: set[str] = set()
        # Во время AUTH LOGIN следующие команды — base64 учётные данные,
        # их нельзя выводить в verbose-лог.
        self._auth_in_progress = False

    def _print_verbose(self, direction: str, text: str):
        """
        Вспомогательный метод для вывода отладочной информации (протокола).
        Работает только если при инициализации был включен параметр verbose.
        """

        if not self.verbose:
            return
        for line in text.strip().split("\r\n"):
            if line:
                print(f"{direction} {line}")

    def _recv(self) -> tuple[int, str]:
        """
        Читает ответ сервера из сокета.
        Корректно накапливает данные и обрабатывает многострочные ответы SMTP,
        ожидая строку формата '<трехзначный_код><пробел><текст>'.
        """
        assert self.sock is not None, "Сокет не подключен"
        data = b""
        while True:
            chunk = self.sock.recv(4096)
            if not chunk:
                break
            data += chunk

            # Проверяем, что мы получили конец строки
            if data.endswith(b"\r\n"):
                decoded = data.decode("utf-8", errors="replace")
                # Убираем пустую строку в конце после split
                lines = decoded.strip("\r\n").split("\r\n")
                last_line = lines[-1]

                # По правилам SMTP последняя строка многострочного ответа
                # имеет формат "250 Text" (с пробелом после кода)
                if len(last_line) >= 4 and last_line[:3].isdigit() and last_line[3] == " ":
                    break

        response = data.decode("utf-8", errors="replace").strip()
        self._print_verbose("<<<", response)

        try:
            code = int(response[:3])
        except (ValueError, IndexError):
            code = 0
        return code, response

    def connect(self):
        """
        Устанавливает TCP-соединение с сервером.
        Если указан порт 465 и включен SSL, сразу оборачивает сокет в
        TLS-контекст (неявный SSL).
        Ожидает от сервера приветственный код 220.
        """

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(30)

        if self.use_ssl and self.port == 465:
            context = ssl.create_default_context()
            self.sock = context.wrap_socket(self.sock, server_hostname=self.host)
            self.is_tls = True

        self.sock.connect((self.host, self.port))
        self._print_verbose("<<<", "Connected")
        code, resp = self._recv()
        if code != 220:
            raise RuntimeError(f"Server refused connection: {resp}")

    def ehlo(self):
        """
        Отправляет команду приветствия EHLO и сохраняет поддерживаемые сервером
        ESMTP-расширения (например, AUTH, STARTTLS, SIZE) во множество
        capabilities.
        """
        self._send(f"EHLO {socket.gethostname()}")
        code, resp = self._recv()
        if code != 250:
            raise RuntimeError(f"EHLO failed: {resp}")

        for line in resp.split("\r\n"):
            line = line.lower()
            if line.startswith(("250-", "250 ")):
                line = line[4:].strip()
            if line:
                self.capabilities.add(line)
        self._print_verbose("INFO", f"ESMTP capabilities: {self.capabilities}")

    def starttls_if_possible(self):
        """
        Проверяет поддержку STARTTLS сервером и настройки клиента.
        Если возможно, отправляет команду STARTTLS, устанавливает защищенное
        соединение (оборачивает сокет) и заново вызывает ehlo().
        """
        if not self.use_ssl or self.is_tls or "starttls" not in self.capabilities:
            return False

        self._send("STARTTLS")
        code, resp = self._recv()
        if code != 220:
            self._print_verbose("WARN", "STARTTLS not supported by server")
            return False

        context = ssl.create_default_context()
        self.sock = context.wrap_socket(self.sock, server_hostname=self.host)
        self.is_tls = True
        self._print_verbose("INFO", "STARTTLS established")
        self.ehlo()
        return True

    def auth(self, username: str, password: str):
        """AUTH LOGIN с проверкой кодов 334/235.

        Прежняя версия отправляла base64-пароль даже если сервер отверг саму
        команду AUTH LOGIN — утечка учётных данных.
        """
        self._auth_in_progress = True
        try:
            self._send("AUTH LOGIN")
            code, resp = self._recv()
            if code != 334:
                raise RuntimeError(f"AUTH LOGIN отклонён: {resp}")

            self._send(b64encode(username.encode("utf-8")).decode())
            code, resp = self._recv()
            if code != 334:
                raise RuntimeError(f"Сервер отклонил имя пользователя: {resp}")

            self._send(b64encode(password.encode("utf-8")).decode())
            code, resp = self._recv()
            if code != 235:
                raise RuntimeError(f"AUTH failed: {resp}")
        finally:
            self._auth_in_progress = False
        self._print_verbose("INFO", "AUTH successful")

    def mail_from(self, sender: str, msg_size: int = 0):
        """
        Начинает транзакцию отправки письма, указывая адрес отправителя.
        Если сервер поддерживает ESMTP-расширение SIZE, передает ожидаемый
        размер письма.
        """
        sender = _sanitize_addr(sender)
        size_cmd = (
            f" SIZE={msg_size}"
            if msg_size > 0 and any(c.startswith("size") for c in self.capabilities)
            else ""
        )
        self._send(f"MAIL FROM:<{sender}>{size_cmd}")
        code, resp = self._recv()
        if code != 250:
            raise RuntimeError(f"MAIL FROM failed: {resp}")

    def rcpt_to(self, recipient: str):
        """
        Указывает адрес получателя письма.
        """
        recipient = _sanitize_addr(recipient)
        self._send(f"RCPT TO:<{recipient}>")
        code, resp = self._recv()
        if code not in (250, 251):
            raise RuntimeError(f"RCPT TO failed: {resp}")

    def data(self, message: str):
        """
        Отправляет содержимое письма.
        Выполняет dot-stuffing (экранирование строк, начинающихся с точки),
        добавляет завершающую последовательность <CRLF>.<CRLF> и отправляет
        данные.
        """
        assert self.sock is not None
        self._send("DATA")
        code, resp = self._recv()
        if code != 354:
            raise RuntimeError(f"DATA failed: {resp}")

        message = message.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "\r\n")
        # Экранируем строки, начинающиеся с точки
        lines = message.split("\r\n")
        lines = [("." + line if line.startswith(".") else line) for line in lines]
        message = "\r\n".join(lines)

        if not message.endswith("\r\n"):
            message += "\r\n"
        message += ".\r\n"

        if self.verbose:
            print(">>> [MESSAGE BODY HIDDEN AS REQUIRED]")

        self.sock.settimeout(180)
        try:
            # sendall, не send: send может отправить не все байты для большого тела.
            self.sock.sendall(message.encode("utf-8"))
        finally:
            self.sock.settimeout(30)

        code, resp = self._recv()
        if code != 250:
            raise RuntimeError(f"Message not accepted: {resp}")

    def quit(self):
        """Корректно завершает сессию: в try/finally, чтобы сокет всегда закрывался."""
        try:
            if self.sock is not None:
                self._send("QUIT")
                self._recv()
        finally:
            if self.sock is not None:
                try:
                    self.sock.close()
                except OSError:
                    pass
                self.sock = None

    def _send(self, cmd: str | bytes) -> None:
        """
        Добавляет корректный перенос строки (CRLF) к команде, кодирует её в
        байты
        и отправляет в сокет. При включенном verbose скрывает пароли в логах
        консоли.
        """
        assert self.sock is not None
        if isinstance(cmd, str):
            cmd = cmd.encode("utf-8")
        if not cmd.endswith(b"\r\n"):
            cmd += b"\r\n"
        self.sock.sendall(cmd)
        # В время AUTH LOGIN отправляются base64-строки username/password — они не
        # начинаются с "AUTH", поэтому старая проверка startswith("AUTH") их пропускала.
        if self.verbose and not self._auth_in_progress:
            visible = cmd.decode("utf-8", errors="replace").strip()
            if not visible.upper().startswith("AUTH"):
                print(f">>> {visible}")


def build_mime_message(
    from_addr: str, to_addr: str, subject: str, text_body: str, image_files: list
) -> str:
    """
    Вручную формирует структуру электронного письма в формате multipart/mixed.
    Генерирует заголовки, кодирует текстовую часть и файлы изображений в base64
    с правильным разбиением строк (по 76 символов) и расставляет
    boundary-разделители.
    """
    boundary = f"===============happy_pictures_{uuid.uuid4().hex[:16]}=="

    # Заголовки письма
    now = datetime.datetime.now(datetime.UTC)
    date_str = now.strftime("%a, %d %b %Y %H:%M:%S %z")
    message_id = f"<{uuid.uuid4()}@{socket.gethostname()}>"

    safe_from = _sanitize_addr(from_addr)
    safe_to = _sanitize_addr(to_addr)
    lines = [
        f'Content-Type: multipart/mixed; boundary="{boundary}"',
        "MIME-Version: 1.0",
        f"From: {safe_from}",
        f"To: {safe_to}",
        f"Subject: {_encode_header_value(subject)}",
        f"Date: {date_str}",
        f"Message-ID: {message_id}",
        "",
    ]

    # Текстовая часть
    wrapped_text = b64_mime_wrap(text_body.encode("utf-8"))

    lines.extend(
        [
            f"--{boundary}",
            'Content-Type: text/plain; charset="utf-8"',
            "MIME-Version: 1.0",
            "Content-Transfer-Encoding: base64",
            "",
            wrapped_text,
            "",
        ]
    )

    # Файлы-вложения
    for img_path in image_files:
        filename = os.path.basename(img_path)
        mime_type = get_image_mime_by_signature(img_path)

        if mime_type is None:
            mime_type = "application/octet-stream"

        with open(img_path, "rb") as f:
            img_data = f.read()

        wrapped = b64_mime_wrap(img_data)

        encoded_name = _encode_header_value(filename)
        lines.extend(
            [
                f"--{boundary}",
                f'Content-Type: {mime_type}; name="{encoded_name}"',
                "MIME-Version: 1.0",
                "Content-Transfer-Encoding: base64",
                f'Content-Disposition: attachment; filename="{encoded_name}"',
                "",
                wrapped,
                "",
            ]
        )

    lines.append(f"--{boundary}--")
    return "\r\n".join(lines) + "\r\n"


def get_image_mime_by_signature(filepath: str):
    """
    Определяет MIME-тип изображения по сигнатуре файла.
    Возвращает строку с MIME-типом или None, если файл не является картинкой.
    """
    try:
        with open(filepath, "rb") as f:
            header = f.read(20)
    except OSError:
        return None

    # JPEG: начинается с FF D8 FF
    if header.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"

    # PNG: начинается с 89 50 4E 47 0D 0A 1A 0A
    if header.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"

    # GIF: начинается с GIF87a или GIF89a
    if header.startswith(b"GIF87a") or header.startswith(b"GIF89a"):
        return "image/gif"

    # BMP: начинается с BM
    if header.startswith(b"BM"):
        return "image/bmp"

    # TIFF: начинается с II*NUL или MM NUL*
    if header.startswith(b"II*\x00") or header.startswith(b"MM\x00*"):
        return "image/tiff"

    # WebP: начинается с RIFF, а с 8-го байта идет WEBP
    if header.startswith(b"RIFF") and header[8:12] == b"WEBP":
        return "image/webp"

    return None


def main():
    parser = argparse.ArgumentParser(description="smtp-mime — отправка всех картинок из каталога")
    parser.add_argument(
        "-s",
        "--server",
        required=True,
        help="SMTP-сервер в формате host[:port] (по умолчанию порт 25)",
    )
    parser.add_argument("-t", "--to", required=True, help="Адрес получателя")
    parser.add_argument(
        "-f", "--from", dest="from_addr", default="<>", help="Адрес отправителя (по умолчанию <>)"
    )
    parser.add_argument(
        "--subject", default="Happy Pictures", help="Тема письма (по умолчанию “Happy Pictures”)"
    )
    parser.add_argument(
        "-d",
        "--directory",
        default=os.getcwd(),
        help="Каталог с изображениями (по умолчанию текущий)",
    )
    parser.add_argument(
        "--ssl",
        action="store_true",
        help="Разрешить SSL/STARTTLS, если сервер поддерживает (по умолчанию выкл)",
    )
    parser.add_argument(
        "--auth", action="store_true", help="Запрашивать авторизацию (пароль не отображается)"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Показывать протокол SMTP (кроме тела письма)"
    )
    parser.add_argument(
        "-m",
        "--message",
        default="Happy Pictures!\n\nВсе изображения из каталога прикреплены как вложения.",
        help="Кастомный текст сообщения (по умолчанию стандартный текст)",
    )

    args = parser.parse_args()

    host, port = parse_hostport(args.server, 25)

    # Собираем картинки, проверяя их реальное содержимое (сигнатуры)
    images = []
    for f in os.listdir(args.directory):
        filepath = os.path.join(args.directory, f)
        if os.path.isfile(filepath):
            # Если функция вернула MIME-тип, значит это картинка
            if get_image_mime_by_signature(filepath) is not None:
                images.append(filepath)

    if not images:
        print("В указанном каталоге не найдено изображений.")
        return 1

    print(f"Найдено изображений: {len(images)}")

    message_str = build_mime_message(args.from_addr, args.to, args.subject, args.message, images)
    client = SMTPClient(host, port, args.ssl, args.verbose)

    login = None
    password = None

    if args.auth:
        password = getpass.getpass("Password: ")
        login = args.from_addr.strip("<>")
        if not login:
            login = input("Login (email): ")

    try:
        client.connect()
        client.ehlo()
        client.starttls_if_possible()

        if args.auth:
            client.auth(login, password)

        client.mail_from(args.from_addr.strip("<>"), msg_size=len(message_str.encode("utf-8")))
        client.rcpt_to(args.to)
        client.data(message_str)
        client.quit()

        print("Письмо успешно отправлено!")

    except Exception as e:
        print(f"Ошибка: {e}")
        return 1

    return 0


if __name__ == "__main__":
    main()
