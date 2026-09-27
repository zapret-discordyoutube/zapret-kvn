"""«Простое правило»: сайты, IP-адреса и программы строками — в native-правило sing-box.

Форма для тех, кто пришёл из v2rayN: по одному значению в строке, синтаксис
v2rayN понимается как есть. Результат — обычное правило ``route.rules``,
никакого своего формата поверх JSON ядра.

* сайт ``2ip.ru``, ``domain:2ip.ru``, ``*.2ip.ru``, ``https://2ip.ru/path`` —
  ``domain_suffix`` (сайт и все поддомены, как в v2rayN); ``www.`` отбрасывается;
* ``full:`` — ``domain``, ``keyword:`` — ``domain_keyword``, ``regexp:`` — ``domain_regex``;
* ``geosite:X`` / ``geoip:X`` — существующий набор ``geosite-X`` / ``geoip-X``;
  ``geoip:private`` — ``ip_is_private``;
* слово без точки (``youtube``) — ``domain_keyword``, как простая строка в Xray;
* IP и подсети — ``ip_cidr``;
* программа — ``process_path_regex`` без учёта регистра: ядро сравнивает
  ``process_name`` точно, а в Windows файл может называться ``Telegram.exe``;
  без расширения дописывается ``.exe``.

В ядре условия разных видов складываются через И (сайт И программа). В форме
пользователь ждёт «что-нибудь из списка», поэтому сайты/IP и программы
собираются в логическое правило ИЛИ.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
import re

from . import list_values

#: Куда отправить: выход ``route`` или блокировка (``reject`` не зависит от outbound block).
BLOCK = "__block__"
#: Служебные правила, которые должны идти до пользовательских (sniff даёт домен).
_SERVICE_ACTIONS = ("sniff", "hijack-dns")
#: Метасимволы регулярных выражений Go (RE2); остальное — буквально.
_REGEX_META = set("\\.+*?()|[]{}^$")
_NAME_PATTERN = re.compile(r"^\(\?i\)\(\^\|\[\\\\/\]\)(.+)\$$")
_PATH_PATTERN = re.compile(r"^\(\?i\)\^(.+)\$$")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)*$")


@dataclass
class ParsedRule:
    rule: dict | None
    errors: list[str] = field(default_factory=list)
    summary: str = ""


def _lines(text: str) -> list[str]:
    """Программы: по строке или через запятую (пробел бывает в имени файла)."""
    values = []
    for raw in text.replace(",", "\n").splitlines():
        value = raw.strip()
        if value and not value.startswith("#"):
            values.append(value)
    return values


def _tokens(text: str) -> list[str]:
    """Сайты и IP: строки, запятые, «;» и пробелы; «regexp:» — целой строкой."""
    values = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.lower().startswith(("regexp:", "regex:")):
            values.append(line)
        else:
            values.extend(part for part in re.split(r"[\s,;]+", line) if part)
    return values


def _add(fields: dict, key: str, value) -> None:
    bucket = fields.setdefault(key, [])
    if value not in bucket:
        bucket.append(value)


def normalize_domain(value: str) -> str:
    """``https://www.Пример.рф:443/x`` → ``xn--e1afmkfd.xn--p1ai`` (для сравнения со SNI).

    Как в полной форме (:mod:`list_values`), плюс удобство v2rayN: «www.»
    отбрасывается — правило и так покрывает все поддомены.
    """
    text = list_values.normalize_domain(value)
    if text.startswith("www.") and text.count(".") >= 2:
        text = text[4:]
    return text


def _rule_set_tag(prefix: str, name: str, rule_sets: set[str]) -> str | None:
    tag = f"{prefix}-{name.strip().lower()}"
    return tag if tag in rule_sets else None


def parse_sites(text: str, rule_sets: set[str], fields: dict, errors: list[str]) -> None:
    for value in _tokens(text):
        head, sep, rest = value.partition(":")
        kind = head.strip().lower() if sep else ""
        if kind == "geosite":
            tag = _rule_set_tag("geosite", rest, rule_sets)
            if tag is None:
                errors.append(f"Нет набора «geosite-{rest.strip().lower()}» — добавьте его в «Наборах правил».")
            else:
                _add(fields, "rule_set", tag)
        elif kind == "full":
            domain = normalize_domain(rest)
            if _DOMAIN_RE.match(domain):
                _add(fields, "domain", domain)
            else:
                errors.append(f"Не похоже на адрес сайта: {value}")
        elif kind == "keyword":
            word = rest.strip().lower()
            if word:
                _add(fields, "domain_keyword", word)
            else:
                errors.append(f"Пустое слово: {value}")
        elif kind in ("regexp", "regex"):
            try:
                re.compile(rest.strip())
            except re.error:
                errors.append(f"Ошибка в регулярном выражении: {value}")
            else:
                _add(fields, "domain_regex", rest.strip())
        else:
            domain = normalize_domain(rest if kind == "domain" else value)
            if kind != "domain" and "." not in domain and domain.isascii() and domain.replace("-", "").isalnum():
                _add(fields, "domain_keyword", domain)
            elif _DOMAIN_RE.match(domain):
                _add(fields, "domain_suffix", domain)
            else:
                errors.append(f"Не похоже на адрес сайта: {value}")


def parse_ips(text: str, rule_sets: set[str], fields: dict, errors: list[str]) -> None:
    for value in _tokens(text):
        head, sep, rest = value.partition(":")
        if sep and head.strip().lower() == "geoip":
            name = rest.strip().lower()
            if name == "private":
                fields["ip_is_private"] = True
                continue
            tag = _rule_set_tag("geoip", name, rule_sets)
            if tag is None:
                errors.append(f"Нет набора «geoip-{name}» — добавьте его в «Наборах правил».")
            else:
                _add(fields, "rule_set", tag)
            continue
        try:
            network = ipaddress.ip_network(value.strip(), strict=False)
        except ValueError:
            errors.append(f"Не похоже на IP-адрес или подсеть: {value}")
        else:
            _add(fields, "ip_cidr", str(network))


def _regex_escape(text: str) -> str:
    return "".join("\\" + char if char in _REGEX_META else char for char in text)


def _unescape(pattern: str) -> str:
    return re.sub(r"\\(.)", r"\1", pattern)


def process_pattern(value: str) -> str:
    """Имя или путь программы — регулярное выражение без учёта регистра."""
    name = value.strip().strip('"')
    if "\\" in name or "/" in name:
        return f"(?i)^{_regex_escape(name)}$"
    if "." not in name:
        name += ".exe"
    return f"(?i)(^|[\\\\/]){_regex_escape(name)}$"


def process_display(pattern: str) -> str | None:
    """Обратно в имя или путь для подписи; ``None`` — это не наш шаблон."""
    for shape in (_NAME_PATTERN, _PATH_PATTERN):
        match = shape.match(pattern)
        if match:
            return _unescape(match.group(1))
    return None


def parse_programs(text: str, fields: dict) -> None:
    for value in _lines(text):
        _add(fields, "process_path_regex", process_pattern(value))


def _action(target: str) -> dict:
    return {"action": "reject"} if target == BLOCK else {"action": "route", "outbound": target}


def build_rule(target: str, sites: str, ips: str, programs: str, rule_sets: set[str]) -> ParsedRule:
    """Правило из трёх текстовых полей; ``rule`` — None, если ничего не задано или есть ошибки."""
    errors: list[str] = []
    address: dict = {}
    parse_sites(sites, rule_sets, address, errors)
    parse_ips(ips, rule_sets, address, errors)
    process: dict = {}
    parse_programs(programs, process)
    if not address and not process:
        errors.append("Укажите хотя бы один сайт, IP-адрес или программу.")
    if errors:
        return ParsedRule(None, errors)
    if address and process:
        rule = {"type": "logical", "mode": "or", "rules": [address, process], **_action(target)}
    else:
        rule = {**(address or process), **_action(target)}
    return ParsedRule(rule, [], _summary(address, process))


def display_domain(domain: str) -> str:
    """Punycode обратно в буквы для подписи: ``xn--p1ai`` → ``рф``."""
    try:
        return domain.encode("ascii").decode("idna")
    except UnicodeError:
        return domain


def _summary(address: dict, process: dict) -> str:
    parts = []
    suffixes = [display_domain(value) for value in address.get("domain_suffix", [])]
    if suffixes:
        parts.append(", ".join(suffixes[:3]) + (f" +{len(suffixes) - 3}" if len(suffixes) > 3 else "") + " и поддомены")
    for key in ("domain", "domain_keyword", "domain_regex", "rule_set", "ip_cidr", "process_path_regex"):
        values = address.get(key) or process.get(key) or []
        if key == "domain":
            values = [display_domain(value) for value in values]
        elif key == "process_path_regex":
            values = [process_display(value) or value for value in values]
        if values:
            parts.append(", ".join(values[:3]) + (f" +{len(values) - 3}" if len(values) > 3 else ""))
    if address.get("ip_is_private"):
        parts.append("локальные адреса")
    return " или ".join(parts)


def _leading(rule) -> bool:
    """Служебное или защитное правило из начала списка: новое встаёт после него."""
    if not isinstance(rule, dict):
        return False
    action = rule.get("action")
    return action in _SERVICE_ACTIONS or action == "reject" or rule.get("outbound") == "block"


def insert_index(rules: list) -> int:
    """Куда встаёт новое правило: после служебных и защитных правил в начале.

    Правила проверяются сверху вниз до первого совпадения, поэтому правило
    пользователя должно стоять выше стоковых — иначе его перехватит набор.
    Но не выше sniff (без него ядро не знает домен) и не выше блоков вроде
    DoT на 853 и сервисов проверки IP: они защищают, а не маршрутизируют.
    """
    index = 0
    for rule in rules:
        if not _leading(rule):
            break
        index += 1
    return index
