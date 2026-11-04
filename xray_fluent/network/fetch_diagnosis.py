"""Где оборвалась загрузка подписки и кто виноват.

Клиент не может знать виновника точно, он выводит его из улик. Когда ни один
маршрут не получил ответа сервера, приложение один раз проверяет по стадиям
(DNS → TCP → TLS) и сам сервер подписки, и нейтральный контрольный узел — по
каждому маршруту, прямому и через VPN. Контроль отвечает, а сервер нет — виноват
не интернет: сравнение маршрутов и стадия отказа различают блокировку пути,
сломанный VPN и молчащий сервер (бот). Ответ сервера с кодом (403, 404, 5xx)
разбирается без проб: ``blame_for_http``.

Адрес в журнал и в сообщения попадает только маской: ``mask_host`` оставляет
узнаваемый облик, ``host_tag`` добавляет короткий отпечаток, по которому
владелец, зная адрес, найдёт свой сервер. Путь и токен ссылки не пишутся никогда.
"""

from __future__ import annotations

import hashlib
import ipaddress
import socket
import ssl
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from ..constants import PROXY_HOST

# Та же цель, которой приложение проверяет задержку и которой Chrome проверяет сеть.
CONTROL_HOST = "www.gstatic.com"
PROBE_TIMEOUT = 4.0

CULPRIT_SERVER = "server"      # бот или сервер подписки
CULPRIT_REFUSED = "refused"    # сервер ответил отказом клиенту (бан приложения)
CULPRIT_BLOCK = "block"        # сеть или провайдер режет путь до сервера
CULPRIT_VPN = "vpn"            # VPN подключён, но не пропускает трафик
CULPRIT_NETWORK = "network"    # у компьютера нет интернета
CULPRIT_UNKNOWN = "unknown"

_HEADLINES = {
    CULPRIT_SERVER: "сервер подписки (бот)",
    CULPRIT_REFUSED: "сервер подписки отказал приложению (бан клиента)",
    CULPRIT_BLOCK: "блокировка сети или провайдера",
    CULPRIT_VPN: "VPN",
    CULPRIT_NETWORK: "интернет-подключение компьютера",
    CULPRIT_UNKNOWN: "не удалось определить",
}


# --- маска адреса ----------------------------------------------------------


def mask_host(host: str) -> str:
    """``url.gl***.com`` — виден облик адреса, но не весь адрес."""

    text = str(host or "").strip().strip("[]").lower()
    if not text:
        return ""
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        pass
    else:
        if ip.version == 4:
            first = text.split(".")
            return f"{first[0]}.{first[1]}.*.*"
        return text.split(":")[0] + ":****"
    labels = text.split(".")
    if len(labels) == 1:
        return labels[0][:2] + "***"
    masked = [label if len(label) <= 3 else label[:2] + "***" for label in labels[:-1]]
    return ".".join([*masked, labels[-1]])


def host_fingerprint(host: str) -> str:
    return hashlib.sha256(str(host or "").strip().lower().encode("utf-8")).hexdigest()[:6]


def host_tag(host: str, port: int = 443) -> str:
    """Метка сервера для журнала: маска, порт и отпечаток (``url.gl***.com:443#3fa9c2``)."""

    return f"{mask_host(host)}:{port}#{host_fingerprint(host)}"


def redact_host(text: str, host: str) -> str:
    """Заменить адрес сервера в чужом тексте ошибки его меткой."""

    if not host:
        return text
    return text.replace(host, f"{mask_host(host)}#{host_fingerprint(host)}")


# --- пробы ----------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class HostProbe:
    ok: bool
    failed: str = ""   # "dns" | "tcp" | "tls" | "proxy" | "proxy_local"; пусто, если всё прошло
    how: str = ""      # "timeout" | "reset" | "refused" | "dns" | "cert" | "tls_error" | "error" | "status"
    ms: tuple[tuple[str, int], ...] = ()
    detail: str = ""   # технический текст для журнала, без адреса

    def timings(self) -> str:
        return " · ".join(f"{name} {value} мс" for name, value in self.ms) or "нет замеров"


def _how(exc: BaseException) -> str:
    if isinstance(exc, socket.gaierror):
        return "dns"
    if isinstance(exc, ssl.SSLCertVerificationError):
        return "cert"
    if isinstance(exc, TimeoutError):  # socket.timeout — тот же класс с Python 3.10
        return "timeout"
    if isinstance(exc, ConnectionRefusedError):
        return "refused"
    if isinstance(exc, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, ssl.SSLEOFError)):
        return "reset"
    if isinstance(exc, ssl.SSLError):
        return "tls_error"
    return "error"


def _tls(sock: socket.socket, host: str, deadline: float) -> None:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("общий срок пробы вышел")
    sock.settimeout(remaining)
    context = ssl.create_default_context()
    context.wrap_socket(sock, server_hostname=host).close()


def _ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)


def probe_direct(host: str, port: int = 443, timeout: float = PROBE_TIMEOUT) -> HostProbe:
    """DNS → TCP → TLS напрямую, как ходит приложение без VPN."""

    deadline = time.monotonic() + timeout
    timings: list[tuple[str, int]] = []
    started = time.monotonic()
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        return HostProbe(False, "dns", _how(exc), tuple(timings), type(exc).__name__)
    timings.append(("dns", _ms(started)))

    started = time.monotonic()
    sock: socket.socket | None = None
    last: BaseException = OSError("нет адресов")
    for family, kind, proto, _name, address in infos[:3]:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            last = TimeoutError("общий срок пробы вышел")
            break
        candidate = socket.socket(family, kind, proto)
        candidate.settimeout(min(remaining, timeout))
        try:
            candidate.connect(address)
        except OSError as exc:
            candidate.close()
            last = exc
            continue
        sock = candidate
        break
    if sock is None:
        return HostProbe(False, "tcp", _how(last), tuple(timings), type(last).__name__)
    timings.append(("tcp", _ms(started)))

    started = time.monotonic()
    try:
        _tls(sock, host, deadline)
    except (OSError, ssl.SSLError) as exc:
        sock.close()
        return HostProbe(False, "tls", _how(exc), tuple(timings), type(exc).__name__)
    timings.append(("tls", _ms(started)))
    return HostProbe(True, "", "", tuple(timings))


def probe_via_proxy(
    proxy_port: int, host: str, port: int = 443, timeout: float = PROBE_TIMEOUT
) -> HostProbe:
    """CONNECT через локальный прокси VPN, затем TLS поверх туннеля."""

    deadline = time.monotonic() + timeout
    timings: list[tuple[str, int]] = []
    started = time.monotonic()
    try:
        sock = socket.create_connection((PROXY_HOST, int(proxy_port)), timeout=min(timeout, 2.0))
    except OSError as exc:
        return HostProbe(False, "proxy_local", _how(exc), tuple(timings), type(exc).__name__)
    try:
        sock.settimeout(max(0.1, deadline - time.monotonic()))
        sock.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode("ascii", "ignore"))
        reply = b""
        while b"\r\n\r\n" not in reply and len(reply) < 4096:
            chunk = sock.recv(1024)
            if not chunk:
                break
            reply += chunk
        status_line = reply.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        parts = status_line.split()
        code = parts[1] if len(parts) > 1 else ""
        if code != "200":
            sock.close()
            return HostProbe(False, "proxy", "status", tuple(timings), f"ответ прокси {code or 'пустой'}")
    except OSError as exc:
        sock.close()
        return HostProbe(False, "proxy", _how(exc), tuple(timings), type(exc).__name__)
    timings.append(("connect", _ms(started)))

    started = time.monotonic()
    try:
        _tls(sock, host, deadline)
    except (OSError, ssl.SSLError) as exc:
        sock.close()
        return HostProbe(False, "tls", _how(exc), tuple(timings), type(exc).__name__)
    timings.append(("tls", _ms(started)))
    return HostProbe(True, "", "", tuple(timings))


# --- улики и вердикт ---------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Evidence:
    host: str
    port: int
    direct: tuple[HostProbe, HostProbe] | None = None  # (сервер, контроль)
    vpn: tuple[HostProbe, HostProbe] | None = None     # None — VPN не подключён


@dataclass(frozen=True, slots=True)
class Diagnosis:
    culprit: str
    certain: bool
    where: str
    advice: str = ""
    log_lines: tuple[str, ...] = field(default_factory=tuple)

    @property
    def headline(self) -> str:
        return _HEADLINES[self.culprit]

    def message(self) -> str:
        who = self.headline if self.certain else f"{self.headline} (вероятно)"
        text = f"Не удалось загрузить подписку. Виноват: {who}. Где оборвалось: {self.where}."
        if self.advice:
            text += f" {self.advice}"
        return text


def collect_evidence(
    host: str,
    port: int,
    *,
    tunnel_port: int | None,
    direct_probe: Callable[[str, int], HostProbe] = probe_direct,
    proxy_probe: Callable[[int, str, int], HostProbe] = probe_via_proxy,
    control_host: str = CONTROL_HOST,
) -> Evidence:
    """Проверить сервер и контроль по каждому маршруту параллельно."""

    jobs: dict[str, Callable[[], HostProbe]] = {
        "direct_target": lambda: direct_probe(host, port),
        "direct_control": lambda: direct_probe(control_host, 443),
    }
    if tunnel_port:
        jobs["vpn_target"] = lambda: proxy_probe(int(tunnel_port), host, port)
        jobs["vpn_control"] = lambda: proxy_probe(int(tunnel_port), control_host, 443)
    with ThreadPoolExecutor(max_workers=len(jobs)) as pool:
        futures = {name: pool.submit(job) for name, job in jobs.items()}
        results = {name: future.result() for name, future in futures.items()}
    vpn = (results["vpn_target"], results["vpn_control"]) if tunnel_port else None
    return Evidence(host, port, (results["direct_target"], results["direct_control"]), vpn)


def describe_failure(probe: HostProbe, route: str) -> str:
    """Стадия отказа простыми словами; ``route`` — «напрямую» или «через VPN»."""

    stage, how = probe.failed, probe.how
    if not stage:
        return f"{route} соединение и TLS проходят, но ответа на запрос нет"
    if stage == "dns":
        return f"{route} не нашёлся адрес сервера (DNS)"
    if stage == "tcp":
        if how == "refused":
            return f"{route} сервер отклонил TCP-соединение"
        if how == "reset":
            return f"{route} TCP-соединение оборвали сразу"
        return f"{route} TCP-соединение не устанавливается: сервер молчит"
    if stage == "tls":
        if how == "cert":
            return f"{route} сертификат сервера не прошёл проверку (подмена или просрочен)"
        if how == "reset":
            return f"{route} TCP есть, но рукопожатие TLS оборвали сразу — типичная блокировка по имени сервера (SNI)"
        if how == "timeout":
            return f"{route} TCP есть, но рукопожатие TLS повисло — типичная блокировка по имени сервера (SNI)"
        return f"{route} TCP есть, но защищённое соединение (TLS) не установилось"
    if stage == "proxy_local":
        return f"{route} приложение не достучалось до локального прокси VPN"
    if stage == "proxy":
        if how == "status":
            return f"{route} VPN не смог открыть соединение с сервером ({probe.detail})"
        return f"{route} VPN не ответил на запрос соединения с сервером"
    return f"{route} соединение с сервером не удалось ({stage})"


def _log_lines(ev: Evidence, verdict: str, certain: bool) -> tuple[str, ...]:
    tag = host_tag(ev.host, ev.port)
    lines: list[str] = []
    for label, pair in (("напрямую", ev.direct), ("через VPN", ev.vpn)):
        if pair is None:
            lines.append(f"diagnosis {tag}: {label}: не пробовали (VPN не подключён)")
            continue
        target, control = pair
        for name, probe in (("сервер", target), ("контроль", control)):
            state = "ok" if probe.ok else f"сбой на {probe.failed} ({probe.how}{', ' + probe.detail if probe.detail else ''})"
            lines.append(f"diagnosis {tag}: {label}, {name}: {state}; {probe.timings()}")
    lines.append(f"diagnosis {tag}: вердикт {verdict}{'' if certain else ' (вероятно)'}")
    return tuple(lines)


def judge(ev: Evidence) -> Diagnosis:
    """Вывести виновника из проб. Чистая функция: проба сети здесь не делается."""

    assert ev.direct is not None
    d_target, d_control = ev.direct
    v_target, v_control = ev.vpn if ev.vpn else (None, None)
    vpn_note = "" if ev.vpn else " Через VPN не пробовали: он не подключён."

    def done(culprit: str, certain: bool, where: str, advice: str = "") -> Diagnosis:
        return Diagnosis(culprit, certain, where, advice, _log_lines(ev, culprit, certain))

    # VPN подключён, но контрольный узел через него не открывается.
    if v_control is not None and not v_control.ok:
        if not d_control.ok:
            return done(
                CULPRIT_NETWORK, True,
                describe_failure(d_control, "напрямую") + f"; через VPN то же: {describe_failure(v_control, 'через VPN')}",
                "Проверьте интернет на компьютере.",
            )
        return done(
            CULPRIT_VPN, True, describe_failure(v_control, "через VPN"),
            "Контрольный сайт напрямую открывается, через VPN — нет: смените сервер VPN или отключите его и обновите подписку напрямую.",
        )

    # Напрямую не открывается даже контрольный узел.
    if not d_control.ok:
        if v_target is not None and v_target.ok:
            return done(
                CULPRIT_BLOCK, True, describe_failure(d_target, "напрямую"),
                "Через VPN сервер подписки открывается: обновите подписку при включённом VPN.",
            )
        if v_target is not None:
            return done(CULPRIT_SERVER, False, describe_failure(v_target, "через VPN"))
        return done(
            CULPRIT_NETWORK, True, describe_failure(d_control, "напрямую"),
            "Контрольный сайт тоже не открывается: проверьте интернет." + vpn_note,
        )

    # Контроль напрямую жив: смотрим сам сервер.
    if not d_target.ok:
        where = describe_failure(d_target, "напрямую")
        if v_target is not None and v_target.ok:
            return done(
                CULPRIT_BLOCK, True, where,
                "Через VPN сервер подписки открывается: обновите подписку при включённом VPN.",
            )
        if v_target is not None:
            return done(
                CULPRIT_SERVER, True,
                where + "; " + describe_failure(v_target, "через VPN"),
                "Сервер недоступен и напрямую, и через VPN.",
            )
        return done(
            CULPRIT_BLOCK, False, where,
            "Включите VPN — приложение повторит загрузку само. Если и так не откроется, сервер подписки выключен." + vpn_note,
        )

    # Рукопожатие напрямую проходит — запрос приняли и не ответили.
    return done(
        CULPRIT_SERVER, False,
        "соединение и TLS проходят, но ответа на запрос нет",
        "Сервер принимает соединение и молчит; провайдер мог резать сам запрос. Проверьте ссылку подписки у провайдера." + vpn_note,
    )


def diagnose(
    host: str,
    port: int,
    *,
    tunnel_port: int | None,
    direct_probe: Callable[[str, int], HostProbe] = probe_direct,
    proxy_probe: Callable[[int, str, int], HostProbe] = probe_via_proxy,
) -> Diagnosis:
    return judge(
        collect_evidence(
            host, port, tunnel_port=tunnel_port, direct_probe=direct_probe, proxy_probe=proxy_probe
        )
    )


# --- ответ сервера с кодом -----------------------------------------------------


def blame_for_http(status: int | None, text: str = "") -> tuple[str, str]:
    """Виновник для ответа сервера: ``(culprit, фраза)``. Сервер ответил — сеть ни при чём."""

    lowered = str(text or "").lower()
    if status in (401, 403) or "hwid" in lowered or "лимит устройств" in lowered or "идентификатор устройства" in lowered:
        return CULPRIT_REFUSED, "сервер подписки ответил отказом клиенту"
    if status in (404, 410):
        return CULPRIT_SERVER, "сервер подписки (бот) не знает эту ссылку: она недействительна или подписка удалена"
    if status == 429:
        return CULPRIT_SERVER, "сервер подписки (бот) ограничил частоту запросов"
    if status is not None and status >= 500:
        return CULPRIT_SERVER, "сервер подписки (бот) сломан или перегружен"
    return CULPRIT_SERVER, "сервер подписки ответил, но тело не подошло"
