from __future__ import annotations

import ctypes
import json
import logging
import sys
from dataclasses import dataclass

try:
    import winreg
except ImportError:  # pragma: no cover - non-Windows dev runs
    winreg = None  # type: ignore[assignment]

from .constants import PROXY_HOST, RUNTIME_DIR


logger = logging.getLogger(__name__)

INTERNET_OPTION_REFRESH = 37
INTERNET_OPTION_SETTINGS_CHANGED = 39
INTERNET_OPTION_PER_CONNECTION_OPTION = 75
INTERNET_PER_CONN_FLAGS = 1
INTERNET_PER_CONN_PROXY_SERVER = 2
INTERNET_PER_CONN_PROXY_BYPASS = 3
PROXY_TYPE_DIRECT = 0x1
PROXY_TYPE_PROXY = 0x2
RAS_MAX_ENTRY_NAME = 256
RAS_MAX_PATH = 260

INTERNET_SETTINGS_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
INTERNET_POLICY_KEY = r"SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"


class _PerConnValue(ctypes.Union):
    _fields_ = [
        ("dwValue", ctypes.c_uint32),
        ("pszValue", ctypes.c_wchar_p),
        ("ftValue", ctypes.c_uint64),
    ]


class INTERNET_PER_CONN_OPTIONW(ctypes.Structure):
    _fields_ = [
        ("dwOption", ctypes.c_uint32),
        ("Value", _PerConnValue),
    ]


class INTERNET_PER_CONN_OPTION_LISTW(ctypes.Structure):
    _fields_ = [
        ("dwSize", ctypes.c_uint32),
        ("pszConnection", ctypes.c_wchar_p),
        ("dwOptionCount", ctypes.c_uint32),
        ("dwOptionError", ctypes.c_uint32),
        ("pOptions", ctypes.POINTER(INTERNET_PER_CONN_OPTIONW)),
    ]


class RASENTRYNAMEW(ctypes.Structure):
    _fields_ = [
        ("dwSize", ctypes.c_uint32),
        ("szEntryName", ctypes.c_wchar * (RAS_MAX_ENTRY_NAME + 1)),
        ("dwFlags", ctypes.c_uint32),
        ("szPhonebookPath", ctypes.c_wchar * (RAS_MAX_PATH + 1)),
    ]


@dataclass(frozen=True)
class SystemProxyState:
    """Реальное (эффективное) состояние системного прокси Windows.

    ``source`` — откуда читались значения: ``"hkcu"`` (обычный per-user режим)
    или ``"hklm-policy"`` (политика ``ProxySettingsPerUser=0`` перенаправляет
    настройки на машинный улей).
    """

    supported: bool = False
    enabled: bool = False
    server: str = ""
    override: str = ""
    autoconfig_url: str = ""
    source: str = "hkcu"
    is_ours: bool = False


class ProxyManager:
    def __init__(self) -> None:
        self._backup: dict[str, str | int] | None = None
        self._backup_file = RUNTIME_DIR / "system_proxy_backup.json"

    @property
    def is_supported(self) -> bool:
        return winreg is not None

    @staticmethod
    def is_our_proxy_server(proxy_server: str) -> bool:
        """Проверяет, что строка ProxyServer указывает на наш локальный прокси.

        Единственный источник истины для «наш ли прокси»: записи
        http=/https=/socks= должны указывать на PROXY_HOST (порт любой) —
        именно такую строку пишет :meth:`enable`.
        """
        value = str(proxy_server or "").lower().replace(" ", "")
        if not value:
            return False
        host = PROXY_HOST.lower()
        return (
            f"http={host}:" in value
            and f"https={host}:" in value
            and f"socks={host}:" in value
        )

    def _read_settings(self) -> dict[str, str | int]:
        if not self.is_supported:
            return {}
        values: dict[str, str | int] = {}
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS_KEY, 0, winreg.KEY_READ) as key:
            for name, default in (("ProxyEnable", 0), ("ProxyServer", ""), ("ProxyOverride", "")):
                try:
                    values[name], _ = winreg.QueryValueEx(key, name)
                except FileNotFoundError:
                    values[name] = default
        return values

    def _write_settings(self, values: dict[str, str | int]) -> None:
        if not self.is_supported:
            return
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS_KEY, 0, winreg.KEY_SET_VALUE) as key:
            if "ProxyEnable" in values:
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, int(values["ProxyEnable"]))
            if "ProxyServer" in values:
                winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, str(values["ProxyServer"]))
            if "ProxyOverride" in values:
                winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, str(values["ProxyOverride"]))

    def query_state(self) -> SystemProxyState:
        """Полный снимок эффективного состояния прокси (только чтение реестра).

        Учитывает политику ``ProxySettingsPerUser=0`` (машинные настройки в
        HKLM вместо HKCU) и PAC (``AutoConfigURL``). Без вызовов WinINet/RAS —
        безопасно вызывать с UI-потока.
        """
        if not self.is_supported:
            return SystemProxyState(supported=False)

        hive = winreg.HKEY_CURRENT_USER
        source = "hkcu"
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, INTERNET_POLICY_KEY, 0, winreg.KEY_READ) as key:
                per_user, _ = winreg.QueryValueEx(key, "ProxySettingsPerUser")
                if int(per_user) == 0:
                    hive = winreg.HKEY_LOCAL_MACHINE
                    source = "hklm-policy"
        except (FileNotFoundError, OSError, ValueError, TypeError):
            pass

        enabled = False
        server = ""
        override = ""
        autoconfig_url = ""
        try:
            with winreg.OpenKey(hive, INTERNET_SETTINGS_KEY, 0, winreg.KEY_READ) as key:
                for name, default in (
                    ("ProxyEnable", 0),
                    ("ProxyServer", ""),
                    ("ProxyOverride", ""),
                    ("AutoConfigURL", ""),
                ):
                    try:
                        value, _ = winreg.QueryValueEx(key, name)
                    except FileNotFoundError:
                        value = default
                    if name == "ProxyEnable":
                        try:
                            enabled = int(value or 0) == 1
                        except (ValueError, TypeError):
                            enabled = False
                    elif name == "ProxyServer":
                        server = str(value or "")
                    elif name == "ProxyOverride":
                        override = str(value or "")
                    else:
                        autoconfig_url = str(value or "")
        except OSError:
            logger.debug("Failed to read effective proxy state", exc_info=True)

        return SystemProxyState(
            supported=True,
            enabled=enabled,
            server=server,
            override=override,
            autoconfig_url=autoconfig_url,
            source=source,
            is_ours=enabled and self.is_our_proxy_server(server),
        )

    def has_backup(self) -> bool:
        return self._backup is not None or self._load_persisted_backup() is not None

    def should_auto_disable(self) -> bool:
        """Можно ли автоматически выключать системный прокси.

        True, только когда активный прокси установлен нами (``is_ours``) либо
        существует резервная копия для восстановления. Чужой/корпоративный
        прокси без нашей резервной копии никогда не трогаем.
        """
        if not self.is_supported:
            return False
        state = self.query_state()
        if state.enabled and state.is_ours:
            return True
        return self.has_backup()

    def release_if_owned(self, restore_previous: bool = True) -> bool:
        """Выключает системный прокси только если он наш или есть бэкап."""
        if not self.should_auto_disable():
            return False
        self.disable(restore_previous=restore_previous)
        return True

    def _load_persisted_backup(self) -> dict[str, str | int] | None:
        if not self._backup_file.exists():
            return None
        try:
            payload = json.loads(self._backup_file.read_text(encoding="utf-8"))
        except Exception:
            return None
        if not isinstance(payload, dict):
            return None
        result: dict[str, str | int] = {}
        for key in ("ProxyEnable", "ProxyServer", "ProxyOverride"):
            if key in payload:
                result[key] = payload[key]
        return result or None

    def _persist_backup(self, values: dict[str, str | int] | None) -> None:
        try:
            if values:
                self._backup_file.parent.mkdir(parents=True, exist_ok=True)
                self._backup_file.write_text(json.dumps(values, ensure_ascii=True, indent=2), encoding="utf-8")
            elif self._backup_file.exists():
                self._backup_file.unlink()
        except Exception:
            pass

    def _ras_entry_names(self) -> list[str]:
        """Имена RAS/VPN-подключений (RasEnumEntriesW); отсутствие — норма."""
        if sys.platform != "win32":
            return []
        try:
            rasapi = ctypes.windll.rasapi32
            entries = (RASENTRYNAMEW * 64)()
            entries[0].dwSize = ctypes.sizeof(RASENTRYNAMEW)
            cb = ctypes.c_uint32(ctypes.sizeof(entries))
            count = ctypes.c_uint32(0)
            ret = rasapi.RasEnumEntriesW(None, None, entries, ctypes.byref(cb), ctypes.byref(count))
            if ret != 0:
                return []
            return [entries[i].szEntryName for i in range(count.value) if entries[i].szEntryName]
        except Exception:
            logger.debug("RAS entry enumeration unavailable", exc_info=True)
            return []

    def _apply_per_connection(self, proxy_server: str, override: str, enable: bool) -> None:
        """Применяет настройки через WinINet для DefaultConnectionSettings.

        Пишет per-connection параметры (option 75) для подключения по
        умолчанию (NULL) и всех RAS-подключений, чтобы страница «Прокси» в
        Параметрах Windows видела актуальное состояние. Любой сбой деградирует
        до текущего поведения (только реестр) без исключений.
        """
        if sys.platform != "win32":
            return
        try:
            wininet = ctypes.windll.Wininet
        except Exception:
            logger.debug("WinINet unavailable for per-connection apply", exc_info=True)
            return
        connections: list[str | None] = [None]
        connections.extend(self._ras_entry_names())
        for connection in connections:
            try:
                options = (INTERNET_PER_CONN_OPTIONW * 3)()
                options[0].dwOption = INTERNET_PER_CONN_FLAGS
                options[0].Value.dwValue = (
                    PROXY_TYPE_DIRECT | PROXY_TYPE_PROXY if enable else PROXY_TYPE_DIRECT
                )
                options[1].dwOption = INTERNET_PER_CONN_PROXY_SERVER
                options[1].Value.pszValue = str(proxy_server or "")
                options[2].dwOption = INTERNET_PER_CONN_PROXY_BYPASS
                options[2].Value.pszValue = str(override or "")

                option_list = INTERNET_PER_CONN_OPTION_LISTW()
                option_list.dwSize = ctypes.sizeof(INTERNET_PER_CONN_OPTION_LISTW)
                option_list.pszConnection = connection
                option_list.dwOptionCount = len(options)
                option_list.dwOptionError = 0
                option_list.pOptions = options
                wininet.InternetSetOptionW(
                    0,
                    INTERNET_OPTION_PER_CONNECTION_OPTION,
                    ctypes.byref(option_list),
                    option_list.dwSize,
                )
            except Exception:
                logger.debug(
                    "Per-connection proxy apply failed for %r", connection, exc_info=True
                )

    def _refresh_system_proxy(self) -> None:
        if sys.platform != "win32":
            return
        try:
            wininet = ctypes.windll.Wininet
            wininet.InternetSetOptionW(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
            wininet.InternetSetOptionW(0, INTERNET_OPTION_REFRESH, 0, 0)
        except Exception:
            logger.debug("WinINet refresh failed", exc_info=True)

    def enable(self, http_port: int, socks_port: int, bypass_lan: bool = True) -> None:
        if not self.is_supported:
            return
        if self._backup is None:
            self._backup = self._read_settings()
            self._persist_backup(self._backup)

        proxy_server = (
            f"http={PROXY_HOST}:{http_port};"
            f"https={PROXY_HOST}:{http_port};"
            f"socks={PROXY_HOST}:{socks_port}"
        )

        override = "<local>;localhost;127.*"
        if bypass_lan:
            override = (
                "<local>;localhost;127.*;10.*;172.*;192.168.*;"
                "*.local;::1"
            )

        self._write_settings(
            {
                "ProxyEnable": 1,
                "ProxyServer": proxy_server,
                "ProxyOverride": override,
            }
        )
        self._apply_per_connection(proxy_server, override, enable=True)
        self._refresh_system_proxy()

    def disable(self, restore_previous: bool = True) -> None:
        if not self.is_supported:
            return
        backup = self._backup or self._load_persisted_backup()
        if restore_previous and backup:
            self._write_settings(dict(backup))
            try:
                restored_enabled = int(backup.get("ProxyEnable", 0) or 0) == 1
            except (ValueError, TypeError):
                restored_enabled = False
            self._apply_per_connection(
                str(backup.get("ProxyServer", "") or ""),
                str(backup.get("ProxyOverride", "") or ""),
                enable=restored_enabled,
            )
        else:
            self._write_settings({"ProxyEnable": 0, "ProxyServer": ""})
            self._apply_per_connection("", "", enable=False)
        self._backup = None
        self._persist_backup(None)
        self._refresh_system_proxy()

    def is_enabled(self) -> bool:
        return self.query_state().enabled
