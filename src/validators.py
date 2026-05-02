def parse_hostport(s: str, default_port: int) -> tuple[str, int]:
    """Парсит 'host', 'host:port' или 'host:port:extra' (последнее — ошибка).

    rsplit с maxsplit=1 нужен на случай нестандартных входов; если порт не число —
    бросается ValueError с понятным сообщением. Это единая точка для будущего
    расширения (например, поддержки IPv6 [::1]:993).
    """
    s = s.strip()
    if ":" not in s:
        return s, default_port
    host, _, port_s = s.rpartition(":")
    try:
        return host, int(port_s)
    except ValueError as e:
        raise ValueError(f"Неверный порт в адресе {s!r}") from e


def parse_msg_id(s: str) -> int:
    """Парсит и проверяет строку с ID письма.

    Возвращает положительное целое число или бросает ValueError.
    """
    s = s.strip()
    if not s.isdecimal():
        raise ValueError(f"ID письма должен быть положительным целым числом, получено: {s!r}")
    value = int(s)
    if value < 1:
        raise ValueError(f"ID письма должен быть положительным целым числом, получено: {s!r}")
    return value


def parse_range(s: str, total: int) -> tuple[int, int]:
    """Парсит строку диапазона писем ('1-20', '10' или '') для ящика с total
    сообщениями.

    Возвращает (start, end), ограниченные значениями [1, total].
    """
    s = s.strip()
    if "-" in s:
        try:
            start, end = map(int, s.split("-", 1))
        except ValueError:
            start, end = max(1, total - 9), total
    elif s.isdecimal():
        count = int(s)
        start = max(1, total - count + 1)
        end = total
    else:
        start = max(1, total - 9)
        end = total

    start = max(1, start)
    end = min(total, end)
    return start, end
