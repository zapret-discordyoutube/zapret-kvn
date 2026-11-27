"""The NaiveProxy key line the VPN bot sells, and the config of the stock naive client built from it.

Grammar (owned by the bot, ``vpnbot_contracts/naive_link.py``, confirmed by its session 2026-11-27)::

    naive+https://<client_id>:<secret>@<host>:<port>[?insecure-concurrency=<n>]#<name>

* the scheme is exactly ``naive+https``; whitespace anywhere is an error;
* ``client_id`` is ``[A-Za-z0-9._-]{1,128}`` and ``secret`` is ``[A-Za-z0-9_-]{22,128}``, neither percent-encoded;
* ``host`` is a lowercase DNS name (never an IP address); the server answers TLS for its own name only;
* the port defaults to 443; the path must be empty or ``/``;
* the only query key is ``insecure-concurrency`` (the bot issues 1..4, the app accepts 1..99 and warns above 4 so that
  a key is honoured as issued, owner decision 2026-11-27); the name after ``#`` is percent-encoded UTF-8.

The stock client takes a JSON file ``{"listen": ..., "proxy": ..., "insecure-concurrency": n}``. The key's concurrency
is passed on unchanged: the app never caps or rewrites what the operator issued.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from urllib.parse import unquote, urlsplit

SCHEME = "naive+https"
CONCURRENCY_MAX = 99
#: Upstream: "strongly recommend against using more than 4 connections".
CONCURRENCY_WARN_ABOVE = 4

_CLIENT_ID = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_SECRET = re.compile(r"^[A-Za-z0-9_-]{22,128}$")
# At least two labels, the last one starts with a letter (so an IP address never matches).
_HOST = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class NaiveKeyError(ValueError):
    """The line is not a valid NaiveProxy key. The message never contains the secret."""


@dataclass(frozen=True, slots=True)
class NaiveKey:
    client_id: str
    secret: str
    host: str
    port: int
    concurrency: int
    name: str

    @property
    def proxy_url(self) -> str:
        """The URL the stock client dials: ``https://<client_id>:<secret>@<host>:<port>`` (no query, no name)."""
        return f"https://{self.client_id}:{self.secret}@{self.host}:{self.port}"

    def secrets(self) -> tuple[str, ...]:
        """Values that must never reach a log."""
        return (self.secret, self.client_id)

    @property
    def concurrency_warning(self) -> str:
        if self.concurrency > CONCURRENCY_WARN_ABOVE:
            return (
                f"В ключе NaiveProxy указано соединений: {self.concurrency}. Разработчики naive не советуют больше "
                f"{CONCURRENCY_WARN_ABOVE}: так трафик легче заметить."
            )
        return ""


def parse_naive_key(line: str) -> NaiveKey:
    text = str(line or "")
    if any(ch.isspace() for ch in text):
        raise NaiveKeyError("В ключе NaiveProxy не должно быть пробелов и переводов строки.")
    if not text.startswith(SCHEME + "://"):
        raise NaiveKeyError("Ключ NaiveProxy начинается с naive+https://.")
    try:
        parts = urlsplit(text)
        port = parts.port
    except ValueError:
        raise NaiveKeyError("В ключе NaiveProxy неверный порт.") from None
    if parts.path not in ("", "/"):
        raise NaiveKeyError("В ключе NaiveProxy не должно быть пути.")
    # urlsplit lowercases the host and hides what a strict check needs, so read userinfo and host from the raw netloc.
    netloc = parts.netloc
    if "@" not in netloc:
        raise NaiveKeyError("В ключе NaiveProxy нет client_id и secret.")
    userinfo, _, hostport = netloc.rpartition("@")
    client_id, colon, secret = userinfo.partition(":")
    if not colon or not _CLIENT_ID.match(client_id):
        raise NaiveKeyError("В ключе NaiveProxy неверный client_id.")
    if not _SECRET.match(secret):
        raise NaiveKeyError("В ключе NaiveProxy неверный secret.")
    host = hostport.rsplit(":", 1)[0] if ":" in hostport else hostport
    if not host or host != host.lower() or len(host) > 253 or not _HOST.match(host):
        raise NaiveKeyError("В ключе NaiveProxy адрес сервера должен быть доменным именем в нижнем регистре.")
    if port is None:
        port = 443
    if not 1 <= port <= 65535:
        raise NaiveKeyError("В ключе NaiveProxy порт вне диапазона 1-65535.")
    concurrency = 1
    if parts.query:
        pairs = [item.partition("=") for item in parts.query.split("&")]
        if len(pairs) != 1 or pairs[0][0] != "insecure-concurrency":
            raise NaiveKeyError("В ключе NaiveProxy допустим только параметр insecure-concurrency.")
        value = pairs[0][2]
        if not value.isascii() or not value.isdigit() or not 1 <= int(value) <= CONCURRENCY_MAX:
            raise NaiveKeyError(f"insecure-concurrency в ключе NaiveProxy должен быть от 1 до {CONCURRENCY_MAX}.")
        concurrency = int(value)
    name = unquote(parts.fragment) if parts.fragment else ""
    if not name.strip() or len(name) > 200 or any(ord(ch) < 32 or ord(ch) == 127 for ch in name):
        raise NaiveKeyError("В ключе NaiveProxy нет имени после #.")
    return NaiveKey(client_id, secret, host, port, concurrency, name)


def helper_config(key: NaiveKey, *, relay_port: int, relay_username: str, relay_password: str,
                  relay_host: str = "127.0.0.1") -> dict:
    """The stock client's ``config.json``: a loopback SOCKS5 listener with credentials and the key's own proxy."""
    config: dict = {
        "listen": f"socks://{relay_username}:{relay_password}@{relay_host}:{relay_port}",
        "proxy": key.proxy_url,
    }
    if key.concurrency > 1:
        config["insecure-concurrency"] = key.concurrency
    return config
