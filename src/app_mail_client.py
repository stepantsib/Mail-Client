import getpass
import json
import os
import re

from imap_client import _sanitize_folder_name
from mail_service import MailService
from validators import parse_msg_id, parse_range

_CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".mailclient")
_CONFIG_PATH = os.path.join(_CONFIG_DIR, "servers.json")
_DEFAULT_CONFIG = {
    "imap_servers": ["imap.yandex.ru:993", "imap.mail.ru:993", "imap.gmail.com:993"],
    "smtp_servers": ["smtp.yandex.ru:465", "smtp.mail.ru:465", "smtp.gmail.com:465"],
    "last_imap": None,
    "last_smtp": None,
}


def _load_server_config() -> dict:
    if os.path.exists(_CONFIG_PATH):
        try:
            with open(_CONFIG_PATH) as f:
                return {**_DEFAULT_CONFIG, **json.load(f)}
        except (json.JSONDecodeError, OSError):
            pass
    return dict(_DEFAULT_CONFIG)


def _save_server_config(config: dict) -> None:
    os.makedirs(_CONFIG_DIR, exist_ok=True)
    with open(_CONFIG_PATH, "w") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)


class MailCLI:
    def __init__(self) -> None:
        self.service: MailService | None = None
        self.current_folder = "INBOX"
        self.imap_host: str | None = None
        self.imap_port: int | None = None

    def _choose_server(self, server_type: str) -> str:
        """Предлагает список серверов из конфига, кеширует последний выбор."""
        config = _load_server_config()
        servers_key = "imap_servers" if server_type == "IMAP" else "smtp_servers"
        last_key = "last_imap" if server_type == "IMAP" else "last_smtp"
        servers = config[servers_key]
        last = config.get(last_key)

        print(f"\n--- Выбор {server_type} сервера ---")
        for i, s in enumerate(servers, 1):
            marker = " (последний)" if s == last else ""
            print(f"{i}. {s}{marker}")
        print(f"{len(servers) + 1}. Ввести свой")
        if last:
            print(f"Enter — использовать {last}")

        while True:
            choice = input("Ваш выбор: ").strip()

            if choice == "" and last:
                selected = last
            elif choice.isdigit():
                c = int(choice)
                if 1 <= c <= len(servers):
                    selected = servers[c - 1]
                elif c == len(servers) + 1:
                    selected = input(
                        f"Введите {server_type} сервер (например, {servers[0]}): "
                    ).strip()
                else:
                    print("Неверный выбор. Пожалуйста, введите номер из списка.")
                    continue
            else:
                print("Неверный выбор. Пожалуйста, введите номер из списка.")
                continue

            config[last_key] = selected
            _save_server_config(config)
            return str(selected)

    def _do_imap_connect(self) -> None:
        assert self.service is not None
        assert self.imap_host is not None
        assert self.imap_port is not None
        self.service.connect_imap(self.imap_host, self.imap_port, self.current_folder)

    def login(self) -> None:
        host_str = self._choose_server("IMAP")
        if ":" in host_str:
            # rsplit + maxsplit=1: иначе ввод вроде "a:b:c" падает с ValueError.
            self.imap_host, port = host_str.rsplit(":", 1)
            self.imap_port = int(port)
        else:
            self.imap_host = host_str
            self.imap_port = 993

        user = input("Email: ")
        password = getpass.getpass("Пароль: ")
        self.service = MailService(user, password)

        print("\n[*] Подключение к серверу...")
        self._do_imap_connect()
        print(f"[+] Успешный вход! Текущая папка: {self.current_folder}")

    def _prompt_msg_id(self, prompt: str = "Введите ID письма: ") -> int | None:
        raw = input(prompt).strip()
        try:
            return parse_msg_id(raw)
        except ValueError as e:
            print(f"[!] {e}")
            return None

    def show_menu(self) -> None:
        assert self.service is not None
        assert self.service.imap is not None
        while True:
            print(f"\n--- Почтовый клиент (папка: {self.current_folder}) ---")
            print("1. Просмотреть список писем")
            print("2. Прочитать письмо")
            print("3. Создать папку")
            print("4. Переместить письмо")
            print("5. Удалить письмо")
            print("6. Скачать вложение")
            print("7. Отправить письмо")
            print("8. Сменить папку")
            print("0. Выход")

            choice = input("Выберите действие: ")

            if choice == "0":
                break

            try:
                if choice == "1":
                    self.list_emails()
                elif choice == "2":
                    self.read_email()
                elif choice == "3":
                    name = input("Имя новой папки: ")
                    self.service.imap.create_folder(name)
                    print(f"[+] Папка '{name}' создана.")
                elif choice == "4":
                    msg_id = self._prompt_msg_id("ID письма: ")
                    if msg_id is None:
                        continue
                    folder = input("В какую папку перенести: ")
                    self.service.imap.move_email(msg_id, folder)
                    print(f"[+] Письмо {msg_id} перемещено в {folder}.")
                elif choice == "5":
                    msg_id = self._prompt_msg_id("ID письма для удаления: ")
                    if msg_id is None:
                        continue
                    self.service.imap.delete_email(msg_id)
                    print(f"[+] Письмо {msg_id} удалено.")
                elif choice == "6":
                    self.save_attachment_cli()
                elif choice == "7":
                    self.send_email_cli()
                elif choice == "8":
                    self.switch_folder()
                else:
                    print("Неизвестная команда.")
            except (TimeoutError, ConnectionResetError, BrokenPipeError, OSError) as e:
                print(f"\n[!] Соединение с сервером потеряно ({e}).")
                print("[*] Выполняется автоматическое переподключение...")
                try:
                    self._do_imap_connect()
                    print("[+] Соединение восстановлено! Пожалуйста, повторите ваше действие.")
                except Exception as ex:
                    print(f"[-] Не удалось переподключиться: {ex}")
            except Exception as e:
                print(f"[-] Ошибка: {e}")

    def list_emails(self) -> None:
        assert self.service is not None
        assert self.service.imap is not None
        imap = self.service.imap
        resp = imap.send_command(f'SELECT "{_sanitize_folder_name(self.current_folder)}"'.encode())
        m = re.search(rb"\* (\d+) EXISTS", resp)
        total_msgs = int(m.group(1)) if m else 0

        if total_msgs == 0:
            print(f"\nВ папке {self.current_folder} нет писем.")
            return

        print(f"\nВсего писем в папке: {total_msgs}")
        ans = input(
            "Сколько последних писем показать? (введите число или диапазон '1-20', Enter для 10): "
        )

        start, end = parse_range(ans, total_msgs)

        if start > end:
            print("Некорректный диапазон.")
            return

        print(f"\nПолучение данных (с {start} по {end})...")
        sizes, headers, attachments = imap.fetch_info(start, end)

        for i in sorted(headers.keys(), reverse=True):
            h = headers[i]
            atts = attachments.get(i, [])
            total_size = sum(int(a.get("size", 0)) for a in atts)

            print(f"[{i}] От: {h.get('From')} | Тема: {h.get('Subject')}")
            print(f"    Вложений: {len(atts)} (Общий объем: {total_size} байт)")

            for a in atts:
                print(f"      - {a['name']} ({a['size']} байт, ID секции: {a['part_id']})")
            print("-" * 40)

    def read_email(self) -> None:
        assert self.service is not None
        assert self.service.imap is not None
        msg_id = self._prompt_msg_id()
        if msg_id is None:
            return
        body = self.service.imap.fetch_email_body(msg_id)
        print(f"\n--- Содержимое письма {msg_id} ---")
        print(body)
        print("----------------------------------")

    def save_attachment_cli(self) -> None:
        assert self.service is not None
        assert self.service.imap is not None
        msg_id = self._prompt_msg_id()
        if msg_id is None:
            return
        part_id = input("Введите ID секции вложения (например, 2): ")
        filename = input("Имя файла для сохранения (например, photo.jpg): ")

        default_dir = os.path.join(os.path.expanduser("~"), "Downloads")
        custom_dir = input(f"Куда сохранить? (Enter для {default_dir}): ")
        if not custom_dir.strip():
            custom_dir = default_dir

        if not os.path.exists(custom_dir):
            os.makedirs(custom_dir)

        # Защита от path traversal: os.path.basename("..") возвращает "..",
        # поэтому резолвим и сверяем, что результат — потомок custom_dir.
        from pathlib import Path

        safe_filename = Path(filename).name
        if not safe_filename or safe_filename in {".", ".."}:
            print("[!] Некорректное имя файла.")
            return
        base = Path(custom_dir).resolve()
        target = (base / safe_filename).resolve()
        if target.parent != base:
            print("[!] Целевой путь вне разрешённого каталога.")
            return
        full_path = str(target)
        print(f"[*] Скачивание вложения из письма {msg_id}...")
        self.service.imap.download_attachment(msg_id, part_id, full_path)
        print(f"[+] Файл сохранен: {full_path}")

    def switch_folder(self) -> None:
        assert self.service is not None
        assert self.service.imap is not None
        print("\n[*] Получение списка папок...")
        folders = self.service.imap.list_folders()

        if not folders:
            print("[-] Не удалось получить список папок.")
            return

        print("\n--- Доступные папки ---")
        for i, folder in enumerate(folders, 1):
            marker = " <-- текущая" if folder == self.current_folder else ""
            print(f"{i}. {folder}{marker}")

        choice = input("Выберите номер папки (Enter для отмены): ").strip()
        if not choice:
            return
        if not choice.isdigit() or not (1 <= int(choice) <= len(folders)):
            print("[!] Неверный выбор.")
            return

        new_folder = folders[int(choice) - 1]
        resp = self.service.imap.send_command(
            f'SELECT "{_sanitize_folder_name(new_folder)}"'.encode()
        )

        if b"OK" in resp:
            self.current_folder = new_folder
            print(f"[+] Текущая папка: {self.current_folder}")
        else:
            print("[-] Не удалось открыть папку.")

    def send_email_cli(self) -> None:
        assert self.service is not None
        print("\n--- Отправка письма ---")
        to_addr = input("Кому: ")
        subject = input("Тема: ")

        print("Введите текст письма (для завершения введите пустую строку дважды):")
        lines = []
        empty_count = 0
        while empty_count < 2:
            line = input()
            if not line:
                empty_count += 1
            else:
                empty_count = 0
            lines.append(line)
        body = "\n".join(lines[:-2])

        attachments_input = input("Пути к файлам через запятую (или Enter, если без вложений): ")
        image_files = []
        if attachments_input.strip():
            raw_paths = [p.strip().strip('"').strip("'") for p in attachments_input.split(",")]
            for p in raw_paths:
                if os.path.isfile(p):
                    image_files.append(p)
                else:
                    print(f"[!] Файл не найден и будет пропущен: {p}")

        try:
            smtp_host_str = self._choose_server("SMTP")
            host, port = (
                smtp_host_str.rsplit(":", 1) if ":" in smtp_host_str else (smtp_host_str, 465)
            )

            print(f"\n[*] Авторизация на {host} как {self.service.user}...")
            self.service.connect_smtp(host, int(port))

            if image_files:
                print(f"[*] Прикрепляем файлы: {len(image_files)} шт...")

            self.service.send(to_addr, subject, body, image_files)
            print("[+] Письмо успешно отправлено!")
        except Exception as e:
            print(f"[-] Ошибка при отправке: {e}")


if __name__ == "__main__":
    app = MailCLI()
    app.login()
    app.show_menu()
