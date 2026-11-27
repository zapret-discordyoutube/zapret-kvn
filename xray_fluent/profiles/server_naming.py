"""Reading a server's own name: which server it is, which variant of it, through which route.

Owner decision 2026-11-27: "server" in the grouped list means the provider's own naming. The shapes seen in real
subscriptions (the owner's state of 2121 servers, kept as a fixture in ``tests/fixtures/real_server_names.json``):

* ``🇸🇪 4stok · VLESS gRPC · TLS · V2`` and ``🇫🇮 Hosfinano · VLESS gRPC · TLS · V8 через Россию``: the server, the
  variant, an optional route marker;
* ``🇩🇪 Hiphopgen через Россию``: the same server over another route;
* ``🇳🇱 Нидерланды 3``: a country name with a counter (server ``Нидерланды``, variant ``3``);
* ``plc31-tcp``, ``plc31-xhttp``: a technical id with a transport suffix;
* ``awg-82.26.193.106:44313``: a WireGuard config named by its address;
* ``proxy``: nothing to read (the whole name is the server).

The protocol is NOT read from the name: the node's own protocol (``node_type_text``) is exact, a name is free text.
Pure functions, no state, so both grouping and tests use them as they are.
"""

from __future__ import annotations

from dataclasses import dataclass
import re

_FLAG = re.compile(
    "^(?:[\U0001F1E6-\U0001F1FF]{2}"          # a regional-indicator pair: 🇩🇪
    "|[\U0001F3F3\U0001F3F4]️?(?:‍[^\\s]{1,3})?)"  # 🏴 🏳️ 🏳️‍🌈
)
_LEADING_NOISE = re.compile(r"^[\s‍️❓❗•·|:-]+")
_VIA = re.compile(r"\s+через\s+\S+(?:\s+\S+)?$", re.IGNORECASE)
_SEPARATOR = re.compile(r"\s+[·•]\s+|\s+[—–]\s+|\s+-\s+")
_COUNTER = re.compile(r"^(?P<server>.*?\S)\s+(?P<variant>\(?\d{1,3}\)?)$")
_TECHNICAL = re.compile(
    r"^(?P<server>[A-Za-z0-9_.]+?)-(?P<variant>tcp|udp|xhttp|grpc|ws|wss|reality|h2|hy2|quic)$", re.IGNORECASE,
)
_ADDRESS = re.compile(r"^(?:awg|wg)-(?P<server>[0-9A-Za-z.:\-]+?)(?::(?P<port>\d{2,5}))?$", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class ServerName:
    flag: str
    server: str
    variant: str
    via: str

    @property
    def server_key(self) -> str:
        """Identity of the server for grouping: the case does not make two servers."""
        return self.server.casefold()


def parse_server_name(name: str) -> ServerName:
    text = str(name or "").strip()
    flag = ""
    match = _FLAG.match(text)
    if match:
        flag = match.group(0)
        text = text[match.end():]
    text = _LEADING_NOISE.sub("", text).strip()
    via = ""
    via_match = _VIA.search(text)
    if via_match:
        via = via_match.group(0).strip()
        text = text[: via_match.start()].rstrip()
    if not text:
        return ServerName(flag, str(name or "").strip(), "", via)

    address = _ADDRESS.match(text)
    if address:
        return ServerName(flag, address.group("server"), address.group("port") or "", via)

    parts = _SEPARATOR.split(text)
    if len(parts) > 1:
        server = parts[0].strip()
        variant = " · ".join(part.strip() for part in parts[1:] if part.strip())
        if server:
            return ServerName(flag, server, variant, via)

    technical = _TECHNICAL.match(text)
    if technical:
        return ServerName(flag, technical.group("server"), technical.group("variant").lower(), via)
    counter = _COUNTER.match(text)
    if counter:
        return ServerName(flag, counter.group("server"), counter.group("variant").strip("()"), via)
    return ServerName(flag, text, "", via)
