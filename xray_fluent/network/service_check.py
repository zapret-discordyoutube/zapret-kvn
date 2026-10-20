"""Что открывается через узел: проверка известных сервисов по качеству ответов, а не по одному байту.

Раньше узел проверялся запросом ``generate_204`` и скоростью файла: «живой» узел мог отдавать YouTube
или Discord с паузами или не пускать к ним вовсе. Здесь через уже поднятый временный прокси к каждому
сервису идёт короткая серия запросов по одному соединению, и по времени до первого байта решается:

- ``ok`` — ответы быстрые;
- ``slow`` — обычный запрос ждёт больше двух с половиной секунд;
- ``pause`` — один-два запроса ждали секунды, остальные получили ответ за доли секунды (так видео «замирает»);
- ``partial`` — открывается не каждое имя сервиса;
- ``blocked`` — не открылось ни одно имя.

Сбор (запросы) и вывод (``judge``) разделены: вывод проверяется без сети.
"""

from __future__ import annotations

import http.client
import socket
import ssl
import statistics
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

__all__ = [
    "SERVICES",
    "ServiceSpec",
    "ServiceVerdict",
    "check_all",
    "judge",
    "probe_endpoint",
    "summary_text",
]

CODE_OK = "ok"
CODE_SLOW = "slow"
CODE_PAUSE = "pause"
CODE_PARTIAL = "partial"
CODE_BLOCKED = "blocked"
CODE_UNKNOWN = "unknown"

# Сколько запросов по одному соединению; первый (с подключением и рукопожатием) во время не входит.
REQUESTS_PER_ENDPOINT = 5
CONNECT_TIMEOUT_S = 6.0
READ_TIMEOUT_S = 6.0
# Пауза — запрос ждал не меньше этого и не меньше чем в столько раз дольше обычного.
PAUSE_MS = 2500.0
PAUSE_RATIO = 20.0
SLOW_MEDIAN_MS = 2500.0
# Сколько служб проверять одновременно: каждая — своё соединение через один и тот же прокси.
PARALLEL = 6


@dataclass(frozen=True, slots=True)
class ServiceSpec:
    key: str
    title: str
    # (хост, путь): каждое имя сервиса, которое должно открываться.
    endpoints: tuple[tuple[str, str], ...]


SERVICES: tuple[ServiceSpec, ...] = (
    ServiceSpec("youtube", "YouTube", (("www.youtube.com", "/generate_204"), ("i.ytimg.com", "/generate_204"))),
    ServiceSpec("discord", "Discord", (("discord.com", "/"), ("gateway.discord.gg", "/"), ("cdn.discordapp.com", "/"))),
    ServiceSpec("telegram", "Telegram", (("telegram.org", "/"), ("web.telegram.org", "/"))),
    ServiceSpec("instagram", "Instagram", (("www.instagram.com", "/"),)),
    ServiceSpec("facebook", "Facebook", (("www.facebook.com", "/"),)),
    ServiceSpec("x", "X", (("x.com", "/"),)),
    ServiceSpec("whatsapp", "WhatsApp", (("web.whatsapp.com", "/"),)),
    ServiceSpec("spotify", "Spotify", (("www.spotify.com", "/"),)),
    ServiceSpec("chatgpt", "ChatGPT", (("chatgpt.com", "/"),)),
    ServiceSpec("twitch", "Twitch", (("www.twitch.tv", "/"),)),
    ServiceSpec("linkedin", "LinkedIn", (("www.linkedin.com", "/"),)),
)


@dataclass(frozen=True, slots=True)
class ServiceVerdict:
    key: str
    code: str
    text: str = ""
    ttfb_median_ms: float = 0.0
    ttfb_max_ms: float = 0.0

    def as_dict(self) -> dict:
        return {
            "key": self.key,
            "code": self.code,
            "text": self.text,
            "ttfb_median_ms": round(self.ttfb_median_ms),
            "ttfb_max_ms": round(self.ttfb_max_ms),
        }


@dataclass(frozen=True, slots=True)
class EndpointRun:
    """Итог серии запросов к одному имени: время до первого байта у каждого удавшегося запроса и сбой, если был."""

    host: str
    ttfb_ms: tuple[float, ...] = ()
    failed: bool = False
    reason: str = ""


def _open_connection(proxy_host: str, proxy_port: int, host: str) -> http.client.HTTPSConnection:
    connection = http.client.HTTPSConnection(
        proxy_host, proxy_port, timeout=CONNECT_TIMEOUT_S, context=ssl.create_default_context()
    )
    connection.set_tunnel(host, 443, headers={"User-Agent": _USER_AGENT})
    return connection


_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
)


def probe_endpoint(
    proxy_host: str,
    proxy_port: int,
    host: str,
    path: str,
    *,
    cancelled: Callable[[], bool] = lambda: False,
    connect: Callable[..., http.client.HTTPSConnection] = _open_connection,
    clock: Callable[[], float] = time.perf_counter,
) -> EndpointRun:
    """Серия запросов по одному соединению через прокси. Время — от отправки запроса до заголовков ответа."""
    times: list[float] = []
    try:
        connection = connect(proxy_host, proxy_port, host)
    except (OSError, ValueError) as error:
        return EndpointRun(host, failed=True, reason=str(error)[:80])
    try:
        for number in range(REQUESTS_PER_ENDPOINT):
            if cancelled():
                break
            started = clock()
            try:
                connection.request("GET", path, headers={"User-Agent": _USER_AGENT, "Accept": "*/*"})
                response = connection.getresponse()
                response.read(8192)
            except (OSError, http.client.HTTPException, ssl.SSLError, socket.timeout) as error:
                if not times:
                    return EndpointRun(host, failed=True, reason=type(error).__name__)
                # Соединение оборвалось посреди серии: что успели, то и есть.
                return EndpointRun(host, tuple(times[1:] if len(times) > 1 else times), failed=True, reason=type(error).__name__)
            times.append((clock() - started) * 1000)
            # Сервис, который закрывает соединение после ответа, серию не продолжит: хватит одного замера.
            if response.will_close and number == 0:
                break
    finally:
        try:
            connection.close()
        except OSError:
            pass
    # Первый запрос по новому соединению — с подключением и рукопожатием: в оценку пауз не входит.
    return EndpointRun(host, tuple(times[1:] if len(times) > 1 else times))


def judge(spec: ServiceSpec, runs: list[EndpointRun]) -> ServiceVerdict:
    """Вывод по сервису из серий по всем его именам. Новых запросов не делает."""
    if not runs:
        return ServiceVerdict(spec.key, CODE_UNKNOWN, "не проверялся")
    opened = [run for run in runs if run.ttfb_ms]
    if not opened:
        reason = next((run.reason for run in runs if run.reason), "")
        return ServiceVerdict(spec.key, CODE_BLOCKED, f"не открывается через этот узел{f' ({reason})' if reason else ''}")
    closed = [run.host for run in runs if not run.ttfb_ms]
    all_times = [value for run in opened for value in run.ttfb_ms]
    median = statistics.median(all_times)
    worst = max(all_times)
    if closed:
        return ServiceVerdict(spec.key, CODE_PARTIAL, f"не открылось: {', '.join(closed)}", median, worst)
    if len(all_times) >= 3 and worst >= PAUSE_MS and worst >= PAUSE_RATIO * max(median, 1.0) and median < 1200:
        return ServiceVerdict(
            spec.key, CODE_PAUSE, f"ответы идут с паузами: обычно {median:.0f} мс, но один ждал {worst / 1000:.1f} с", median, worst
        )
    if median >= SLOW_MEDIAN_MS:
        return ServiceVerdict(spec.key, CODE_SLOW, f"отвечает медленно: обычно {median / 1000:.1f} с до первого байта", median, worst)
    return ServiceVerdict(spec.key, CODE_OK, f"ответы быстрые: обычно {median:.0f} мс", median, worst)


def check_service(proxy_host: str, proxy_port: int, spec: ServiceSpec, *, cancelled=lambda: False, probe=probe_endpoint) -> ServiceVerdict:
    runs = [probe(proxy_host, proxy_port, host, path, cancelled=cancelled) for host, path in spec.endpoints]
    return judge(spec, runs)


def check_all(
    proxy_host: str,
    proxy_port: int,
    *,
    services: tuple[ServiceSpec, ...] = SERVICES,
    cancelled: Callable[[], bool] = lambda: False,
    probe=probe_endpoint,
) -> dict[str, ServiceVerdict]:
    """Все сервисы каталога через один поднятый прокси; по ``PARALLEL`` одновременно."""
    with ThreadPoolExecutor(max_workers=PARALLEL, thread_name_prefix="service-check") as pool:
        futures = {
            spec.key: pool.submit(check_service, proxy_host, proxy_port, spec, cancelled=cancelled, probe=probe) for spec in services
        }
        return {key: future.result() for key, future in futures.items()}


def summary_text(verdicts: dict[str, dict] | dict[str, ServiceVerdict]) -> str:
    """Одна строка для карточки узла: значок и название каждого сервиса, о проблемах — словами."""
    icons = {CODE_OK: "✓", CODE_SLOW: "⚠", CODE_PAUSE: "⚠", CODE_PARTIAL: "⚠", CODE_BLOCKED: "✗", CODE_UNKNOWN: "?"}
    titles = {spec.key: spec.title for spec in SERVICES}
    parts = []
    for key, verdict in verdicts.items():
        code = verdict.code if isinstance(verdict, ServiceVerdict) else str(verdict.get("code") or CODE_UNKNOWN)
        parts.append(f"{icons.get(code, '?')} {titles.get(key, key)}")
    return "  ".join(parts)
