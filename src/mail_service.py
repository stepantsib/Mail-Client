import re

from imap_client import IMAPClient
from smtp_client import SMTPClient, build_mime_message


class MailService:
    """Бизнес-логика почтового клиента: подключение и отправка писем.

    MailCLI занимается только вводом-выводом и делегирует операции сюда.
    """

    def __init__(self, user: str, password: str) -> None:
        self.user = user
        self.password = password
        self.imap: IMAPClient | None = None
        self.smtp: SMTPClient | None = None
        self.current_folder: str = "INBOX"

    def connect_imap(self, host: str, port: int, folder: str = "INBOX") -> None:
        """Устанавливает IMAP-соединение, аутентифицирует пользователя и
        открывает папку."""
        self.current_folder = folder
        self.imap = IMAPClient(host, port, use_ssl=True, verbose=False)
        self.imap.connect()

        resp = self.imap.send_command(
            f'LOGIN "{self.user}" "{self.password}"'.encode(),
            is_sensitive=True,
        )
        tag_lines = [line for line in resp.split(b"\r\n") if re.match(rb"^A\d{3} ", line)]
        if not tag_lines or b" OK " not in tag_lines[-1] + b" ":
            raise RuntimeError("Ошибка аутентификации: неверный логин или пароль.")

        self.imap.send_command(f'SELECT "{self.current_folder}"'.encode())

    def connect_smtp(self, host: str, port: int) -> None:
        """Устанавливает SMTP-соединение и аутентифицирует пользователя."""
        self.smtp = SMTPClient(host, port, use_ssl=True, verbose=False)
        self.smtp.connect()
        self.smtp.ehlo()
        self.smtp.starttls_if_possible()
        self.smtp.auth(self.user, self.password)

    def send(self, to: str, subject: str, body: str, files: list[str]) -> None:
        """Формирует и отправляет письмо с опциональными вложениями."""
        if self.smtp is None:
            raise RuntimeError("SMTP-соединение не установлено.")

        if files:
            message = build_mime_message(self.user, to, subject, body, files)
        else:
            message = build_mime_message(self.user, to, subject, body, [])

        msg_size = len(message.encode("utf-8"))
        self.smtp.mail_from(self.user, msg_size=msg_size)
        self.smtp.rcpt_to(to)
        self.smtp.data(message)
        self.smtp.quit()
