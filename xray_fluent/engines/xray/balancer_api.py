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

from pathlib import Path

from ...constants import PROXY_HOST
from ...platform.windows.subprocess_utils import CREATE_NO_WINDOW, result_output_text, run_text, run_text_pumped


#: Команда короткая и локальная; ждать дольше смысла нет.
COMMAND_TIMEOUT_SEC = 5.0


def build_balancer_override_command(
    xray_path: str | Path,
    api_port: int,
    balancer_tag: str,
    outbound_tag: str = "",
    *,
    remove: bool = False,
) -> list[str]:
    """Собрать argv для ``xray api bo``. Без ``outbound_tag`` требуется ``remove=True``."""

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
            xray_path, api_port, balancer_tag, outbound_tag, remove=remove
        )
    except ValueError as exc:
        return False, str(exc)

    runner = run_text_pumped if pump else run_text
    try:
        result = runner(command, timeout=COMMAND_TIMEOUT_SEC, creationflags=CREATE_NO_WINDOW)
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"
    return result.returncode == 0, result_output_text(result).strip()
