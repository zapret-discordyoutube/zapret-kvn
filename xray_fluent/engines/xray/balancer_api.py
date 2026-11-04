"""Управление балансировщиком работающего xray через его gRPC API.

``xray api bo`` фиксирует выбор балансировщика на конкретном outbound'е. Ядро при
этом не перезапускается, конфиг на диске не переписывается, уже установленные
соединения не рвутся — новые сразу идут через выбранный сервер. Это и есть механизм
переключения серверов при активной ротации.

Команда требует ``"RoutingService"`` в секции ``api.services`` конфига; его добавляет
:func:`xray_fluent.application.outbound_pool_service.ensure_xray_pool_control_plane`
вместе с самим балансировщиком, когда ноды загружаются в ядро пулом.
"""

from __future__ import annotations

import os
import socket
import time
from pathlib import Path

from ...constants import PROXY_HOST
from ...platform.windows.subprocess_utils import CREATE_NO_WINDOW, result_output_text, run_text, run_text_pumped


#: Таймаут самого вызова API внутри ``xray api`` (по умолчанию у ядра 3 с: на
#: загруженном ПК рукопожатие gRPC с локальным API не успевало, и запуск VLESS
#: падал с «failed to dial»).
API_CALL_TIMEOUT_SEC = 8
#: Потолок на процесс: вызов + запас на запуск exe (антивирус сканирует его при каждом старте).
COMMAND_TIMEOUT_SEC = API_CALL_TIMEOUT_SEC + 6.0
#: Отказ «не дозвонились» повторяют: сразу после старта ядро может ещё не принимать gRPC.
DIAL_ATTEMPTS = 3
DIAL_RETRY_PAUSE_SEC = 0.5
_PROXY_ENV_NAMES = (
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "GRPC_PROXY",
    "http_proxy", "https_proxy", "all_proxy", "no_proxy",
)


def build_balancer_override_command(
    xray_path: str | Path,
    api_port: int,
    balancer_tag: str,
    outbound_tag: str = "",
    *,
    remove: bool = False,
    timeout: float | None = None,
) -> list[str]:
    """Собрать argv для ``xray api bo``. Без ``outbound_tag`` требуется ``remove=True``.

    ``timeout`` (с) — флаг ``--timeout`` самого вызова; без него у ядра 3 с.
    """

    if not str(xray_path or "").strip():
        raise ValueError("Путь к xray не задан")
    if int(api_port) <= 0:
        raise ValueError("Порт API xray не задан")
    if not str(balancer_tag or "").strip():
        raise ValueError("Тег балансировщика не задан")

    command = [
        str(xray_path),
        "api",
        "bo",
        f"--server={PROXY_HOST}:{int(api_port)}",
        "-b",
        str(balancer_tag),
    ]
    if timeout is not None:
        command.insert(4, f"--timeout={int(timeout)}")
    if remove:
        command.append("-r")
        return command
    if not str(outbound_tag or "").strip():
        raise ValueError("Тег outbound не задан")
    command.append(str(outbound_tag))
    return command


def apply_balancer_override(
    xray_path: str | Path,
    api_port: int,
    balancer_tag: str,
    outbound_tag: str = "",
    *,
    remove: bool = False,
    pump: bool = True,
) -> tuple[bool, str]:
    """Применить (или снять) фиксацию выбора. Возвращает ``(успех, текст вывода)``.

    ``pump=True`` прокачивает события Qt на время ожидания: вызов идёт из главного
    потока, и без этого зависший процесс подморозил бы интерфейс.
    """

    try:
        command = build_balancer_override_command(
            xray_path, api_port, balancer_tag, outbound_tag, remove=remove, timeout=API_CALL_TIMEOUT_SEC
        )
    except ValueError as exc:
        return False, str(exc)

    runner = run_text_pumped if pump else run_text
    # Повторы только в рабочем потоке: из главного ждать между ними нельзя.
    attempts = 1 if pump else DIAL_ATTEMPTS
    output = ""
    for attempt in range(attempts):
        try:
            result = runner(command, timeout=COMMAND_TIMEOUT_SEC, creationflags=CREATE_NO_WINDOW)
        except Exception as exc:
            return False, f"{type(exc).__name__}: {exc}"
        output = result_output_text(result).strip()
        if result.returncode == 0:
            return True, output
        if "failed to dial" not in output or attempt + 1 >= attempts:
            break
        time.sleep(DIAL_RETRY_PAUSE_SEC)
    if "failed to dial" in output:
        output = f"{output} [{describe_api_reachability(api_port)}]"
    return False, output


def describe_api_reachability(api_port: int) -> str:
    """Что видно с этого ПК про порт API: для журнала, когда «xray api» не дозвонился.

    Различает «порт не слушает / закрыт» и «TCP есть, а gRPC не отвечает», а
    заодно называет (без значений) переменные окружения прокси — частая
    причина странных отказов локальных клиентов.
    """

    started = time.monotonic()
    try:
        with socket.create_connection((PROXY_HOST, int(api_port)), timeout=2.0):
            tcp = f"TCP до порта API {api_port} есть ({int((time.monotonic() - started) * 1000)} мс), gRPC не ответил"
    except OSError as exc:
        tcp = f"TCP до порта API {api_port} не открылся: {type(exc).__name__}"
    names = [name for name in _PROXY_ENV_NAMES if os.environ.get(name)]
    env = "прокси в окружении: " + (", ".join(names) if names else "нет")
    return f"{tcp}; {env}"
