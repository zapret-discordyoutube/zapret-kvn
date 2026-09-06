"""Short connection errors for the UI; full core evidence stays in the log."""

def connection_message(message: str) -> str:
    text = (message or "").strip()
    lowered = text.lower()
    if "no authenticated handshake observed" in lowered:
        return "Сервер AWG не ответил на запрос подключения. Подробности — в логах."
    if "functional https probes failed" in lowered or "_ssl.c:" in lowered:
        return "Проверка HTTPS через VPN не завершилась. Подробности — в логах."
    if "no recent network activity" in lowered:
        return "Hysteria не удалось установить соединение с сервером: превышено время ожидания."
    return text
