"""Совместимость сохранённых outbound'ов с текущим ядром Xray.

Xray 26.x отвергает целиком любой конфиг, где в ``kcpSettings`` есть ключ
``header`` или ``seed`` (даже ``{"type": "none"}``): «The feature mkcp header &
seed has been removed». Узлы же хранятся в том виде, в каком их когда-то
импортировали, а весь пул из сотен узлов идёт в одном конфиге — одна такая
запись останавливала запуск ядра для всех.

Здесь только чистые функции без Qt и без доступа к состоянию приложения:

* :func:`normalize_xray_outbound` — без потерь убирает то, что ядро больше не
  принимает, но ничего не значит (``header: none``);
* :func:`xray_outbound_incompatibility` — причина, по которой узел ядро не соберёт
  и пересобрать без потери смысла нельзя (маскировка ``srtp``/``utp``/… и
  ``seed`` в новом ядре переносятся в ``finalmask`` не один в один).
"""

from __future__ import annotations

import re
from typing import Any


#: ``xray run`` называет несобираемый outbound по его тегу из конфига.
_FAILED_OUTBOUND_RE = re.compile(
    r"failed to build outbound config with tag\s+(?P<tag>\S+)", re.IGNORECASE
)

_KCP_NETWORKS = {"kcp", "mkcp"}
_NO_HEADER_TYPES = {"", "none"}


def _kcp_settings(outbound: dict[str, Any]) -> dict[str, Any] | None:
    stream = outbound.get("streamSettings")
    if not isinstance(stream, dict):
        return None
    if str(stream.get("network") or "").strip().lower() not in _KCP_NETWORKS:
        return None
    settings = stream.get("kcpSettings")
    return settings if isinstance(settings, dict) else None


def _kcp_header_type(settings: dict[str, Any]) -> str:
    header = settings.get("header")
    if isinstance(header, dict):
        return str(header.get("type") or "").strip().lower()
    return ""


def xray_outbound_incompatibility(outbound: object) -> str:
    """Пустая строка — узел собирается; иначе короткая причина для журнала и UI."""

    if not isinstance(outbound, dict):
        return ""
    settings = _kcp_settings(outbound)
    if settings is None:
        return ""
    if str(settings.get("seed") or "").strip():
        return "mKCP seed удалён в Xray 26.x (нужен finalmask)"
    header_type = _kcp_header_type(settings)
    if header_type not in _NO_HEADER_TYPES:
        return f"mKCP header «{header_type}» удалён в Xray 26.x (нужен finalmask)"
    return ""


def normalize_xray_outbound(outbound: dict[str, Any]) -> dict[str, Any]:
    """Убрать из kcp-настроек пустые ``header``/``seed``. Меняет словарь на месте.

    Вызывается на копии: сохранённый ``node.outbound`` остаётся как был.
    """

    settings = _kcp_settings(outbound)
    if settings is None:
        return outbound
    if "header" in settings and _kcp_header_type(settings) in _NO_HEADER_TYPES:
        del settings["header"]
    if "seed" in settings and not str(settings.get("seed") or "").strip():
        del settings["seed"]
    return outbound


def failed_outbound_tag(lines: object, *, prefix: str = "") -> str:
    """Тег outbound'а, на котором ядро остановило разбор конфига, из его вывода.

    Берётся последнее совпадение: предупреждения идут раньше самой ошибки.
    """

    found = ""
    for line in lines or ():
        match = _FAILED_OUTBOUND_RE.search(str(line))
        if match and match.group("tag").startswith(prefix):
            found = match.group("tag")
    return found
