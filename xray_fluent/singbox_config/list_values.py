"""Ввод списков в формах правил: разделители и приведение значений к виду ядра.

Пользователь пишет «2ip.ru, 2ip.io» в одну строку — это два домена, а не один
домен с запятой (ядро не нашло бы ни того, ни другого). Для полей, в которых
запятая и пробел не бывают частью значения, они разделяют значения; для
регулярных выражений, путей и имён программ разделитель — только строка
(«{2,3}», «Яндекс Музыка.exe»).

Домены приводятся к тому, что видит ядро (SNI/Host): без схемы, пути и порта,
в нижнем регистре, IDN — в punycode. Ведущая точка в ``domain_suffix``
сохраняется: «.example.com» значит «только поддомены».
"""

from __future__ import annotations

import ipaddress
import re

DOMAIN_FIELDS = frozenset({"domain", "domain_suffix"})
KEYWORD_FIELDS = frozenset({"domain_keyword"})
IP_FIELDS = frozenset({"ip_cidr", "source_ip_cidr"})
PORT_FIELDS = frozenset({"port", "source_port", "port_range", "source_port_range"})
#: Поля, где запятая, точка с запятой и пробелы разделяют значения.
TOKEN_FIELDS = DOMAIN_FIELDS | KEYWORD_FIELDS | IP_FIELDS | PORT_FIELDS

_TOKEN_SPLIT = re.compile(r"[\s,;]+")
_LABEL = r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?"
_DOMAIN_RE = re.compile(rf"^(?=.{{1,253}}$){_LABEL}(?:\.{_LABEL})*$")
_PORT_RANGE_RE = re.compile(r"^\d{0,5}:\d{0,5}$")


def split_values(field: str, text: str) -> list[str]:
    """Значения из текста редактора: строки, а для «токенных» полей — и запятые/пробелы."""
    values: list[str] = []
    for line in text.splitlines():
        parts = _TOKEN_SPLIT.split(line) if field in TOKEN_FIELDS else [line]
        values.extend(part.strip() for part in parts if part.strip())
    return values


def normalize_domain(value: str, *, keep_leading_dot: bool = False) -> str:
    """``https://Пример.рф:443/x`` → ``xn--e1afmkfd.xn--p1ai`` (ведущую точку — по флагу)."""
    text = value.strip().lower()
    text = re.sub(r"^[a-z][a-z0-9+.-]*://", "", text)
    text = re.split(r"[/?#]", text, maxsplit=1)[0]
    text = text.rsplit("@", 1)[-1]
    if text.count(":") == 1:
        text = text.split(":", 1)[0]
    if text.startswith("*."):
        text = text[1:] if keep_leading_dot else text[2:]
    leading = keep_leading_dot and text.startswith(".")
    text = text.strip(".")
    try:
        text = text.encode("idna").decode("ascii")
    except UnicodeError:
        pass
    return ("." if leading else "") + text


def normalize_value(field: str, value: str) -> tuple[str, str]:
    """(значение для конфига, проблема или пустая строка)."""
    if field in DOMAIN_FIELDS:
        domain = normalize_domain(value, keep_leading_dot=field == "domain_suffix")
        if not _DOMAIN_RE.match(domain.lstrip(".")):
            return value, f"Не похоже на домен: {value}"
        return domain, ""
    if field in KEYWORD_FIELDS:
        return value.lower(), ""
    if field in IP_FIELDS:
        try:
            ipaddress.ip_network(value, strict=False)
        except ValueError:
            return value, f"Не похоже на IP-адрес или подсеть: {value}"
        return value, ""
    if field in ("port_range", "source_port_range") and not _PORT_RANGE_RE.match(value):
        return value, f"Диапазон портов пишется как 1000:2000: {value}"
    return value, ""


def parse_list(field: str, text: str) -> tuple[list[str], list[str]]:
    """Все значения поля и список проблем (пустой — можно сохранять)."""
    values, problems = [], []
    for raw in split_values(field, text):
        value, problem = normalize_value(field, raw)
        if problem:
            problems.append(problem)
        elif value not in values:
            values.append(value)
    return values, problems


def value_problems(field: str, values: list) -> list[str]:
    """Проблемы уже сохранённых значений (например, «2ip.ru, 2ip.io» одной строкой)."""
    problems = []
    for value in values:
        if not isinstance(value, str) or field not in TOKEN_FIELDS:
            continue
        if len(split_values(field, value)) > 1:
            problems.append(f"«{value}» — это несколько значений в одном: разделите их по строкам")
            continue
        _normalized, problem = normalize_value(field, value)
        if problem:
            problems.append(problem)
    return problems
