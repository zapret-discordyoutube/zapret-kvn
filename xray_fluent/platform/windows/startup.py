"""Запуск приложения при входе в Windows.

Приложение собрано с манифестом «требуются права администратора», а записи
из ключа реестра ``Run`` с таким требованием Windows при входе в систему
молча пропускает: запрос UAC на этом этапе не показывается. Поэтому
автозапуск — это задание Планировщика «при входе пользователя» с наивысшими
правами: оно стартует без запроса, а создать его может только уже повышенный
процесс, каким приложение и является.
"""

from __future__ import annotations

import logging
import os
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from xml.sax.saxutils import escape

from .subprocess_utils import CREATE_NO_WINDOW, result_output_text, run_text

if sys.platform == "win32":
    import winreg

_log = logging.getLogger(__name__)

TASK_NAME = "ZapretKVN Autostart"
# Прежний, нерабочий способ: значение в HKCU\...\Run. Убирается при любой
# настройке автозапуска, чтобы в «Автозагрузке» не висела мёртвая запись.
LEGACY_RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
LEGACY_RUN_VALUES = ("zapret kvn", "ZapretKVN", "Zapret KVN")
_SCHTASKS_TIMEOUT_S = 20.0


class StartupError(RuntimeError):
    """Планировщик заданий отказал; текст — его собственный ответ."""


@dataclass(frozen=True, slots=True)
class StartupTarget:
    executable: Path
    arguments: str
    working_dir: Path


def startup_target() -> StartupTarget:
    """Что запускать при входе: приложение, свёрнутое в трей."""

    if getattr(sys, "frozen", False):
        exe = Path(sys.executable).resolve()
        return StartupTarget(exe, "--tray", exe.parent)

    base_dir = Path(__file__).resolve().parents[3]
    venv_pythonw = base_dir / ".venv" / "Scripts" / "pythonw.exe"
    python_exe = venv_pythonw if venv_pythonw.exists() else Path(sys.executable).resolve()
    return StartupTarget(python_exe, f'"{base_dir / "main.py"}" --tray', base_dir)


def _current_user() -> str:
    if sys.platform == "win32":
        try:
            import ctypes

            size = ctypes.c_ulong(512)
            buffer = ctypes.create_unicode_buffer(size.value)
            # 2 = NameSamCompatible: «ДОМЕН\пользователь».
            if ctypes.windll.secur32.GetUserNameExW(2, buffer, ctypes.byref(size)):
                return buffer.value
        except Exception:
            pass
    domain = os.environ.get("USERDOMAIN", "")
    name = os.environ.get("USERNAME", "") or os.environ.get("USER", "")
    return f"{domain}\\{name}" if domain else name


def build_task_xml(target: StartupTarget, user: str) -> str:
    """Описание задания: при входе этого пользователя, с наивысшими правами."""

    return f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Запуск Zapret KVN при входе в Windows</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>{escape(user)}</UserId>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{escape(user)}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>false</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>5</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{escape(str(target.executable))}</Command>
      <Arguments>{escape(target.arguments)}</Arguments>
      <WorkingDirectory>{escape(str(target.working_dir))}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"""


def _schtasks(*arguments: str):
    return run_text(
        ["schtasks", *arguments], timeout=_SCHTASKS_TIMEOUT_S, creationflags=CREATE_NO_WINDOW
    )


def is_registered() -> bool:
    if sys.platform != "win32":
        return False
    return _schtasks("/Query", "/TN", TASK_NAME).returncode == 0


def enable(target: StartupTarget | None = None) -> None:
    if sys.platform != "win32":
        return
    xml = build_task_xml(target or startup_target(), _current_user())
    handle, name = tempfile.mkstemp(prefix="zapretkvn_autostart_", suffix=".xml")
    try:
        with os.fdopen(handle, "wb") as file:
            # schtasks читает описание задания только в UTF-16 с BOM.
            file.write(xml.encode("utf-16"))
        result = _schtasks("/Create", "/TN", TASK_NAME, "/XML", name, "/F")
    finally:
        try:
            os.unlink(name)
        except OSError:
            pass
    if result.returncode != 0:
        raise StartupError(result_output_text(result).strip() or f"schtasks: код {result.returncode}")
    _remove_legacy_run_entries()


def disable() -> None:
    if sys.platform != "win32":
        return
    _remove_legacy_run_entries()
    if not is_registered():
        return
    result = _schtasks("/Delete", "/TN", TASK_NAME, "/F")
    if result.returncode != 0:
        raise StartupError(result_output_text(result).strip() or f"schtasks: код {result.returncode}")


def apply(enabled: bool) -> None:
    """Привести автозапуск в соответствие с настройкой; при отказе — StartupError."""

    if enabled:
        enable()
    else:
        disable()


def repair(enabled: bool) -> None:
    """Сверка при старте приложения. Вызывать не из GUI-потока; не бросает.

    Портативную папку можно перенести — тогда задание указывает на прежний
    путь. Заодно это чинит автозапуск тем, у кого настройка была включена
    ещё при способе через реестр.
    """

    if sys.platform != "win32" or not getattr(sys, "frozen", False):
        return
    try:
        apply(enabled)
    except Exception as error:
        _log.warning("Не удалось сверить автозапуск: %s", error)


def _remove_legacy_run_entries() -> None:
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, LEGACY_RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
            for value in LEGACY_RUN_VALUES:
                try:
                    winreg.DeleteValue(key, value)
                except FileNotFoundError:
                    pass
    except OSError:
        _log.debug("Не удалось очистить прежнюю запись автозапуска", exc_info=True)
