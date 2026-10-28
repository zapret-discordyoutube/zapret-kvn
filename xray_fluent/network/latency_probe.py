"""Задержка сервера — настоящим подключением через то же ядро, что и VPN.

Раньше задержку мерили пустым TCP-соединением к порту сервера.  Такой замер
врал в обе стороны: Hysteria2/TUIC слушают UDP и «умирали» всегда, имя сервера
разрешал провайдерский DNS (подменённый ответ — «мёртвый» сервер), а пустое
соединение без данных — не то, что видит сервер от настоящего клиента.

Теперь сервер проверяется тем ядром, которым к нему подключается VPN (Xray для
VLESS, sing-box для Trojan/VMess/Shadowsocks, официальный клиент для
Hysteria2), через временный локальный HTTP-прокси:

* на проводе — обычное подключение клиента: рукопожатие ядра с отпечатком
  Chrome (uTLS), внутри туннеля — зашифрованный запрос; пустых соединений нет;
* имя сервера разрешается своим DoH или запомненным адресом и подставляется
  ядру напрямую: провайдерский DNS имени сервера не видит; без адреса сервер
  «не измерен», а не «мёртв»;
* цель — ``www.gstatic.com/generate_204``, та же, которой Chrome проверяет
  связь, с заголовками Chrome;
* число — «тёплый» запрос.  Первый запрос открывает соединение (рукопожатие с
  сервером и TLS к цели), следующие идут по нему же, и их время — круг
  клиент → сервер → цель → обратно, то есть RTT до сервера, как у клиентов с
  «RTT-замером».  Холодное время со всеми рукопожатиями — это 800–1000 мс
  вместо настоящих 40–120.

Очередь, пауза между серверами и журнал шлюза — в ``ping_service``.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import ssl
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from ..application.protocol_core import ProtocolCore, protocol_core
from ..constants import (
    HYSTERIA_PATH_DEFAULT,
    PROXY_HOST,
    SINGBOX_PATH_DEFAULT,
    SPEED_TEST_HYSTERIA_PATH,
    SPEED_TEST_SINGBOX_PATH,
    SPEED_TEST_XRAY_PATH,
    XRAY_PATH_DEFAULT,
)
from ..engines.hysteria.config_adapter import pin_server_address
from ..engines.singbox.config_builder import build_singbox_outbound, is_singbox_endpoint_node
from ..profiles.models import Node
from .bootstrap_dns import BootstrapNameNotFound, resolve_bootstrap
from .speed_test_worker import (
    SPEED_TEST_USER_AGENT,
    _pick_port,
    _port_open,
    _speed_test_env,
    build_hysteria_speed_test_config,
    build_speed_test_config,
    is_hysteria_speed_node,
    prepare_speed_test_xray,
    should_skip_speed_test,
)

PROBE_HOST = "www.gstatic.com"
PROBE_PATH = "/generate_204"
PROBE_HTTP_PORT = 19102
CORE_START_TIMEOUT_SEC = 10.0
REQUEST_TIMEOUT_SEC = 8.0
# Тёплых запросов после первого: берётся лучший — разовая задержка в очереди
# сервера не выдаётся за его RTT.
WARM_REQUESTS = 2
_POLL_SEC = 0.05
_CREATE_NO_WINDOW = 0x08000000

_HEADERS = {
    "User-Agent": SPEED_TEST_USER_AGENT,
    "Accept": "*/*",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Accept-Language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
    "Connection": "keep-alive",
}

# Итог замера.
OK = "ok"                  # сервер ответил, ping_ms — RTT
NO_ANSWER = "no_answer"    # ядро не дошло до цели через сервер
UNMEASURED = "unmeasured"  # проверить нечем или не узнать адрес: «мёртвым» не считать


@dataclass(frozen=True)
class ProbeResult:
    state: str
    ping_ms: int | None = None
    reason: str = ""

    @property
    def measured(self) -> bool:
        return self.state != UNMEASURED


@dataclass(frozen=True)
class CorePaths:
    xray: Path = XRAY_PATH_DEFAULT
    singbox: Path = SINGBOX_PATH_DEFAULT
    hysteria: Path = HYSTERIA_PATH_DEFAULT


# Запущенные временные ядра: на выходе приложения их добивают, а не оставляют.
_live: set[subprocess.Popen] = set()
_live_lock = threading.Lock()


def terminate_all() -> None:
    with _live_lock:
        processes = list(_live)
    for process in processes:
        try:
            process.kill()
        except OSError:
            pass


# ── адрес сервера без провайдерского DNS ─────────────────────────────────


def _no_system_lookup(_host: str) -> set[str]:
    return set()


def server_addresses(host: str, resolve=resolve_bootstrap) -> list[str] | None:
    """IP сервера своим DoH или из кеша; ``None`` — не узнать без открытого DNS.

    ``BootstrapNameNotFound`` пробрасывается: доверенный резолвер подтвердил,
    что имени нет.
    """

    try:
        return [str(ipaddress.ip_address(host))]
    except ValueError:
        pass
    try:
        resolution = resolve(host, system=_no_system_lookup)
    except BootstrapNameNotFound:
        raise
    except OSError:
        return None
    addresses = sorted(resolution.addresses, key=lambda value: (ipaddress.ip_address(value).version, value))
    return addresses or None


# ── конфиги временных ядер ───────────────────────────────────────────────


def _xray_config(node: Node, port: int, host: str, addresses: list[str]) -> dict:
    config = build_speed_test_config(node, port)
    if host not in addresses:
        # Адрес сервера — из hosts встроенного DNS Xray, а не от системы.
        config["dns"] = {"hosts": {host: addresses}}
        outbound = config["outbounds"][0]
        stream = outbound.setdefault("streamSettings", {})
        sockopt = stream.setdefault("sockopt", {})
        sockopt["domainStrategy"] = "UseIP"
    return config


def _singbox_config(node: Node, port: int, host: str, addresses: list[str]) -> dict:
    config: dict = {
        "log": {"level": "panic"},
        "inbounds": [{"type": "http", "tag": "probe-in", "listen": PROXY_HOST, "listen_port": int(port)}],
        "route": {"final": "proxy"},
    }
    if is_singbox_endpoint_node(node):
        endpoint = {key: value for key, value in node.outbound.items() if not str(key).startswith("_")}
        endpoint["tag"] = "proxy"
        config["endpoints"] = [endpoint]
    else:
        config["outbounds"] = [build_singbox_outbound(node, tag="proxy")]
    if host not in addresses:
        config["dns"] = {"servers": [{"type": "hosts", "tag": "probe-hosts", "predefined": {host: addresses}}]}
        config["route"]["default_domain_resolver"] = "probe-hosts"
    return config


def _hysteria_config(node: Node, port: int, host: str, addresses: list[str]) -> dict:
    config = build_hysteria_speed_test_config(node, port)
    if host not in addresses:
        config = pin_server_address(config, addresses[0])
    return config


@dataclass(frozen=True)
class _Launch:
    config: dict
    command: list[str]
    env: dict[str, str] | None
    cwd: str | None


def _launch(node: Node, port: int, host: str, addresses: list[str], paths: CorePaths) -> _Launch | None:
    core = protocol_core(node)
    if core is ProtocolCore.XRAY:
        if not Path(paths.xray).is_file():
            return None
        exe = str(prepare_speed_test_xray(Path(paths.xray), SPEED_TEST_XRAY_PATH))
        return _Launch(
            _xray_config(node, port, host, addresses), [exe, "run", "-c"],
            _speed_test_env(Path(paths.xray)), None,
        )
    if core is ProtocolCore.HYSTERIA:
        if not is_hysteria_speed_node(node) or not Path(paths.hysteria).is_file():
            return None
        exe = str(prepare_speed_test_xray(Path(paths.hysteria), SPEED_TEST_HYSTERIA_PATH))
        return _Launch(
            _hysteria_config(node, port, host, addresses),
            [exe, "--disable-update-check", "--log-level", "error", "client", "--config"],
            None, str(Path(paths.hysteria).parent),
        )
    if core is ProtocolCore.SINGBOX:
        if not Path(paths.singbox).is_file():
            return None
        exe = str(prepare_speed_test_xray(Path(paths.singbox), SPEED_TEST_SINGBOX_PATH))
        return _Launch(
            _singbox_config(node, port, host, addresses), [exe, "run", "--disable-color", "-c"],
            None, str(Path(paths.singbox).parent),
        )
    return None  # AmneziaWG: своего прокси-режима у ядра нет


def unmeasurable_reason(node: Node) -> str:
    """Почему сервер не проверить через ядро; пусто — проверить можно."""

    core = protocol_core(node)
    if core is ProtocolCore.AMNEZIA:
        return "AmneziaWG проверяется только подключением"
    if core is ProtocolCore.XRAY:
        skip, message = should_skip_speed_test(node)
        return message if skip else ""
    if core is ProtocolCore.HYSTERIA and not is_hysteria_speed_node(node):
        return "Hysteria2 проверяется по исходной ссылке hy2://"
    return ""


# ── замер через локальный прокси ─────────────────────────────────────────


def _request(connection: http.client.HTTPSConnection) -> None:
    connection.request("GET", PROBE_PATH, headers=_HEADERS)
    response = connection.getresponse()
    response.read()
    if response.status >= 500:
        raise OSError(f"HTTP {response.status}")
    if response.will_close:
        raise OSError("цель закрыла соединение")


def warm_rtt_ms(
    port: int,
    *,
    timeout: float = REQUEST_TIMEOUT_SEC,
    warm: int = WARM_REQUESTS,
    clock: Callable[[], float] = time.perf_counter,
    context: ssl.SSLContext | None = None,
) -> int:
    """RTT через прокси на ``port``: лучший из тёплых запросов, мс.

    Бросает ``OSError``, если цель не ответила.
    """

    connection = http.client.HTTPSConnection(
        PROXY_HOST, int(port), timeout=timeout, context=context or ssl.create_default_context(),
    )
    connection.set_tunnel(PROBE_HOST, 443)
    try:
        started = clock()
        _request(connection)  # холодный: рукопожатие с сервером и TLS к цели
        best = clock() - started
        warm_best: float | None = None
        try:
            for _ in range(max(1, int(warm))):
                started = clock()
                _request(connection)
                elapsed = clock() - started
                warm_best = elapsed if warm_best is None else min(warm_best, elapsed)
        except (OSError, http.client.HTTPException, ssl.SSLError):
            pass  # сервер ответил холодным запросом: жив, число — холодное
        if warm_best is not None:
            best = warm_best
        return max(1, int(round(best * 1000.0)))
    except (http.client.HTTPException, ssl.SSLError) as exc:
        raise OSError(str(exc)) from exc
    finally:
        connection.close()


def _wait_ready(process: subprocess.Popen, port: int, cancelled: Callable[[], bool]) -> bool:
    deadline = time.monotonic() + CORE_START_TIMEOUT_SEC
    while not cancelled() and time.monotonic() < deadline:
        if process.poll() is not None:
            return False
        if _port_open(PROXY_HOST, port):
            return process.poll() is None  # порт мог открыть не наш процесс
        time.sleep(_POLL_SEC)
    return False


def probe_node(
    node: Node,
    *,
    paths: CorePaths | None = None,
    cancelled: Callable[[], bool] = lambda: False,
    measure: Callable[[int], int] = warm_rtt_ms,
    resolve=resolve_bootstrap,
) -> ProbeResult:
    """Проверить один сервер; блокирующий вызов, только из рабочего потока."""

    reason = unmeasurable_reason(node)
    if reason:
        return ProbeResult(UNMEASURED, reason=reason)
    host = str(node.server or "").strip().strip("[]")
    if not host or not node.port:
        return ProbeResult(UNMEASURED, reason="у сервера нет адреса")
    try:
        addresses = server_addresses(host, resolve)
    except BootstrapNameNotFound:
        return ProbeResult(NO_ANSWER, reason="имя сервера не существует")
    if not addresses:
        return ProbeResult(UNMEASURED, reason="адрес сервера не узнать без открытого DNS")

    port = _pick_port(PROXY_HOST, PROBE_HTTP_PORT)
    try:
        launch = _launch(node, port, host, addresses, paths or CorePaths())
    except (ValueError, KeyError, TypeError) as exc:
        return ProbeResult(UNMEASURED, reason=f"конфиг ядра не собрать: {exc}")
    if launch is None:
        return ProbeResult(UNMEASURED, reason="нет ядра для этого протокола")

    config_path: Path | None = None
    process: subprocess.Popen | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", prefix="probe_", delete=False, encoding="utf-8",
        ) as handle:
            json.dump(launch.config, handle, ensure_ascii=True)
            config_path = Path(handle.name)
        process = subprocess.Popen(
            [*launch.command, str(config_path)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=launch.env,
            cwd=launch.cwd,
            creationflags=_CREATE_NO_WINDOW,
        )
        with _live_lock:
            _live.add(process)
        ready = _wait_ready(process, port, cancelled)
        # В конфиге ключи сервера: ядро его прочитало, на диске он не нужен.
        config_path.unlink(missing_ok=True)
        config_path = None
        if cancelled():
            return ProbeResult(UNMEASURED, reason="отменено")
        if not ready:
            return ProbeResult(UNMEASURED, reason="временное ядро не запустилось")
        try:
            return ProbeResult(OK, measure(port))
        except OSError as exc:
            return ProbeResult(NO_ANSWER, reason=str(exc) or type(exc).__name__)
    except OSError as exc:
        return ProbeResult(UNMEASURED, reason=f"временное ядро: {exc}")
    finally:
        if process is not None:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
            with _live_lock:
                _live.discard(process)
        if config_path is not None:
            try:
                config_path.unlink(missing_ok=True)
            except OSError:
                pass
