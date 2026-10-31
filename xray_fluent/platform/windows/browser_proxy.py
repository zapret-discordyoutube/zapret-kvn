"""Браузеры, которые не берут системный прокси Windows и поэтому идут мимо VPN.

В режиме прокси приложение (как и v2rayN) включает системный прокси Windows.
Chromium-браузеры берут его, только пока их собственная настройка прокси —
«системная». Её перебивают:

* политика в реестре (``HKLM``/``HKCU\\SOFTWARE\\Policies\\<браузер>``:
  ``ProxyMode``, ``ProxyServerMode``, ``ProxySettings``) — так бывает на
  рабочих машинах и после «оптимизаторов»;
* расширение, которое управляет прокси (ZeroOmega/SwitchyOmega в режиме
  «Direct», Browsec, Hola и т. п.) — его настройка лежит в файле профиля
  ``Preferences`` / ``Secure Preferences`` под ``extensions.settings.<id>``.

Тогда браузер идёт мимо VPN, хотя остальные программы работают. Модуль только
читает реестр и файлы профилей, ничего не меняет; в режиме TUN это не важно —
туда попадает весь трафик.
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

#: Режим, при котором браузер берёт системный прокси.
_SYSTEM = "system"
#: ``ProxyServerMode`` политики: 0 — напрямую, 1 — автоопределение, 2 — вручную, 3 — системный.
_SERVER_MODE = {0: "direct", 1: "auto_detect", 2: "fixed_servers", 3: _SYSTEM}
_LOCAL_HOSTS = ("127.0.0.1", "localhost", "[::1]", "::1")


@dataclass(frozen=True)
class Browser:
    name: str
    #: Ключи политик относительно ``SOFTWARE\\Policies``.
    policy_keys: tuple[str, ...]
    #: Каталог «User Data» относительно %LOCALAPPDATA% или %APPDATA%.
    user_data: str
    roaming: bool = False


BROWSERS: tuple[Browser, ...] = (
    Browser("Google Chrome", (r"Google\Chrome",), r"Google\Chrome\User Data"),
    Browser("Microsoft Edge", (r"Microsoft\Edge",), r"Microsoft\Edge\User Data"),
    Browser("Brave", (r"BraveSoftware\Brave",), r"BraveSoftware\Brave-Browser\User Data"),
    Browser("Яндекс Браузер", (r"YandexBrowser",), r"Yandex\YandexBrowser\User Data"),
    Browser("Opera", (), r"Opera Software\Opera Stable", roaming=True),
)


@dataclass(frozen=True)
class ProxyBypass:
    """Браузер не возьмёт системный прокси."""

    browser: str
    source: str  # "policy" | "extension"
    mode: str  # direct | fixed_servers | pac_script | auto_detect
    detail: str = ""  # имя расширения или сервер политики


# ── разбор (чистые функции, проверяются без Windows) ─────────────────────


def _points_to_us(server: str, ports: Iterable[int]) -> bool:
    """Свой прокси браузера указывает на наш локальный порт — тогда всё равно через VPN."""

    text = str(server or "").lower()
    if not any(host in text for host in _LOCAL_HOSTS):
        return False
    found = {int(port) for port in re.findall(r":(\d{2,5})\b", text)}
    return bool(found) and found <= {int(p) for p in ports}


def policy_mode(values: Mapping[str, Any]) -> tuple[str, str] | None:
    """``(mode, server)`` из значений ключа политик или ``None``, если прокси не задан.

    ``ProxySettings`` (JSON) главнее отдельных ``ProxyMode``/``ProxyServerMode``.
    """

    settings = values.get("ProxySettings")
    if isinstance(settings, str) and settings.strip():
        try:
            parsed = json.loads(settings)
        except ValueError:
            parsed = None
        if isinstance(parsed, dict) and parsed.get("ProxyMode"):
            return str(parsed["ProxyMode"]).lower(), str(parsed.get("ProxyServer") or "")
    server = str(values.get("ProxyServer") or "")
    if values.get("ProxyMode"):
        return str(values["ProxyMode"]).lower(), server
    server_mode = values.get("ProxyServerMode")
    if isinstance(server_mode, int) and server_mode in _SERVER_MODE:
        return _SERVER_MODE[server_mode], server
    return None


def policy_bypass(browser: str, values: Mapping[str, Any], ports: Iterable[int]) -> ProxyBypass | None:
    found = policy_mode(values)
    if found is None:
        return None
    mode, server = found
    if mode == _SYSTEM or (mode == "fixed_servers" and _points_to_us(server, ports)):
        return None
    return ProxyBypass(browser, "policy", mode, server)


def _extension_enabled(entry: Mapping[str, Any]) -> bool:
    if entry.get("state", 1) == 0:
        return False
    reasons = entry.get("disable_reasons")
    return not reasons


def _extension_name(ext_id: str, entry: Mapping[str, Any]) -> str:
    manifest = entry.get("manifest")
    name = manifest.get("name") if isinstance(manifest, dict) else ""
    if not isinstance(name, str) or not name or name.startswith("__MSG_"):
        return ext_id  # локализованное имя в файле не лежит
    return name


def extension_bypasses(browser: str, prefs: Mapping[str, Any], ports: Iterable[int]) -> list[ProxyBypass]:
    """Включённые расширения профиля, которые перебили прокси браузера."""

    extensions = prefs.get("extensions")
    settings = extensions.get("settings") if isinstance(extensions, dict) else None
    if not isinstance(settings, dict):
        return []
    found: list[ProxyBypass] = []
    for ext_id, entry in settings.items():
        if not isinstance(entry, dict) or not _extension_enabled(entry):
            continue
        for scope in ("preferences", "regular_only_preferences"):
            controlled = entry.get(scope)
            proxy = controlled.get("proxy") if isinstance(controlled, dict) else None
            if not isinstance(proxy, dict):
                continue
            mode = str(proxy.get("mode") or "").lower()
            server = str(proxy.get("server") or "")
            if not mode or mode == _SYSTEM or (mode == "fixed_servers" and _points_to_us(server, ports)):
                continue
            found.append(ProxyBypass(browser, "extension", mode, _extension_name(str(ext_id), entry)))
            break
    return found


def describe(bypass: ProxyBypass) -> str:
    """Одна фраза для пользователя: что не так и что сделать."""

    if bypass.source == "extension":
        what = f"расширение «{bypass.detail}» управляет его прокси"
        fix = "переключите расширение на «Системный прокси» (System proxy) или отключите его"
    else:
        what = "его прокси задан политикой в реестре Windows"
        fix = "уберите политику ProxyMode / ProxySettings или включите режим TUN"
    return f"{bypass.browser} идёт мимо VPN: {what}. Чтобы он шёл через VPN, {fix}."


def message(bypasses: list[ProxyBypass]) -> str:
    """Текст уведомления; режим TUN исправляет все случаи разом."""

    lines = [describe(item) for item in bypasses]
    lines.append("Или включите режим TUN: в нём через VPN идёт весь трафик, что бы ни было в браузере.")
    return " ".join(lines)


# ── чтение (только Windows; зовётся из фонового потока) ───────────────────


def _read_policy_values(key_path: str) -> list[dict[str, Any]]:
    import winreg  # noqa: PLC0415 — только Windows

    result: list[dict[str, Any]] = []
    for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
        try:
            with winreg.OpenKey(hive, rf"SOFTWARE\Policies\{key_path}") as key:
                values: dict[str, Any] = {}
                for name in ("ProxyMode", "ProxyServerMode", "ProxyServer", "ProxySettings"):
                    try:
                        values[name] = winreg.QueryValueEx(key, name)[0]
                    except OSError:
                        pass
                if values:
                    result.append(values)
        except OSError:
            continue
    return result


def _profile_dirs(user_data: Path, roaming: bool) -> list[Path]:
    if roaming:  # Opera: один профиль прямо в каталоге
        return [user_data] if user_data.is_dir() else []
    if not user_data.is_dir():
        return []
    return [
        path for path in user_data.iterdir()
        if path.is_dir() and (path.name == "Default" or path.name.startswith("Profile "))
    ]


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        # Файлы профиля бывают по десятку МБ; браузер их не блокирует на чтение.
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def find_bypasses(ports: Iterable[int], *, env: Mapping[str, str] | None = None) -> list[ProxyBypass]:
    """Все браузеры, которые сейчас не возьмут системный прокси. Вне Windows — пусто."""

    if sys.platform != "win32":
        return []
    ports = tuple(ports)
    env = os.environ if env is None else env
    found: list[ProxyBypass] = []
    for browser in BROWSERS:
        for key_path in browser.policy_keys:
            for values in _read_policy_values(key_path):
                hit = policy_bypass(browser.name, values, ports)
                if hit is not None:
                    found.append(hit)
        base = env.get("APPDATA" if browser.roaming else "LOCALAPPDATA", "")
        if not base:
            continue
        seen: set[tuple[str, str]] = set()
        for profile in _profile_dirs(Path(base) / browser.user_data, browser.roaming):
            for name in ("Secure Preferences", "Preferences"):
                prefs = _read_json(profile / name)
                if prefs is None:
                    continue
                for hit in extension_bypasses(browser.name, prefs, ports):
                    if (hit.browser, hit.detail) not in seen:
                        seen.add((hit.browser, hit.detail))
                        found.append(hit)
    return found
