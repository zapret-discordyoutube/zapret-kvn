"""Воркер тестирования скорости — измеряет скорость загрузки через каждый прокси-узел."""

from __future__ import annotations

import json
import subprocess
import tempfile
import time
from pathlib import Path
from urllib.request import ProxyHandler, Request

from PyQt6.QtCore import QThread, pyqtSignal

from ..engines.xray import build_xray_config
from ..constants import (
    PROXY_HOST,
    SPEED_TEST_DEFAULT_URL,
    SPEED_TEST_ROUNDS,
    SPEED_TEST_TEMP_HTTP_PORT,
    SPEED_TEST_TEMP_SOCKS_PORT,
    SPEED_TEST_TIMEOUT,
    SPEED_TEST_URLS_BY_COUNTRY,
)
from .http_utils import build_opener
from ..profiles.models import AppSettings, Node, RoutingSettings

def measure_download_bps(
    opener,
    url: str,
    *,
    timeout: float,
    max_bytes: int | None = None,
    cancelled=lambda: False,
    on_fraction=None,
    partial_on_error: bool = False,
    user_agent: str = "ZapretKVN/SpeedTest",
) -> float | None:
    """Скачать файл через ``opener`` и вернуть скорость в байтах/с.

    Замер ограничен и по времени (``timeout`` — и на ответ, и на всю загрузку),
    и по объёму (``max_bytes``).  ``None`` — ничего не скачано или отмена.
    ``partial_on_error`` — обрыв/таймаут посреди загрузки считается замером по
    уже пришедшим байтам (для «умной проверки»: зависающий сервер — медленный);
    по умолчанию, как и прежде у теста скорости, такой раунд не засчитывается.
    Блокирующий вызов: только из рабочего потока.
    """

    req = Request(url, headers={"User-Agent": user_agent})
    start = time.perf_counter()
    total_bytes = 0
    try:
        with opener.open(req, timeout=timeout) as resp:
            length_header = resp.headers.get("Content-Length") or ""
            try:
                total_length = int(length_header)
            except (TypeError, ValueError):
                total_length = 0
            if max_bytes:
                total_length = min(total_length, max_bytes) if total_length > 0 else max_bytes
            while True:
                chunk = resp.read(64 * 1024)
                if not chunk:
                    break
                total_bytes += len(chunk)
                if cancelled():
                    return None
                elapsed = time.perf_counter() - start
                if on_fraction is not None:
                    if total_length > 0:
                        fraction = min(1.0, total_bytes / total_length)
                    else:
                        fraction = min(1.0, elapsed / max(timeout, 0.1))
                    on_fraction(fraction)
                if max_bytes and total_bytes >= max_bytes:
                    break
                if elapsed > timeout:
                    break
    except Exception:
        if cancelled() or total_bytes <= 0 or not partial_on_error:
            return None
    elapsed = time.perf_counter() - start
    if elapsed <= 0 or total_bytes <= 0:
        return None
    return total_bytes / elapsed


def _get_speed_url(country_code: str) -> str:
    """Возвращает URL тестового файла по стране сервера с явным fallback."""
    return SPEED_TEST_URLS_BY_COUNTRY.get(country_code.lower(), SPEED_TEST_DEFAULT_URL)


def should_skip_speed_test(node: Node) -> tuple[bool, str]:
    """Тест скорости работает через временный xray — native sing-box ноды
    (включая endpoint-ноды WireGuard/AWG) пропускаются мягко, без is_alive=False."""
    outbound = node.outbound if isinstance(node.outbound, dict) else {}
    if outbound.get("type") and not outbound.get("protocol"):
        protocol = str(outbound.get("type") or node.scheme or "native").upper()
        return True, f"Тест скорости для {node.name} пропущен: протокол {protocol} не поддерживается ядром xray."
    return False, ""


class SpeedTestWorker(QThread):
    """Тестирует скорость загрузки через каждый узел с помощью временного экземпляра xray."""

    result = pyqtSignal(str, object, bool)   # node_id, speed_mbps (float|None), is_alive
    progress = pyqtSignal(int, int)          # current, total
    node_progress = pyqtSignal(str, int)     # node_id, percent 0..100
    skipped = pyqtSignal(str, str)           # node_id, короткое сообщение о пропуске
    completed = pyqtSignal()

    def __init__(
        self,
        nodes: list[Node],
        xray_path: str,
        routing: RoutingSettings | None = None,
        timeout: float = SPEED_TEST_TIMEOUT,
        *,
        rounds: int = SPEED_TEST_ROUNDS,
        max_bytes: int | None = None,
        url: str | None = None,
        socks_port: int = SPEED_TEST_TEMP_SOCKS_PORT,
        http_port: int = SPEED_TEST_TEMP_HTTP_PORT,
    ):
        super().__init__()
        self._nodes = list(nodes)
        self._xray_path = xray_path
        self._routing = routing or RoutingSettings()
        self._timeout = timeout
        # Необязательные параметры — для короткого замера «умной проверки»
        # авто-переключения: один раунд, ограниченный объём, общий URL и свои
        # временные порты, чтобы не мешать ручному тесту скорости.
        self._rounds = max(1, int(rounds))
        self._max_bytes = max_bytes
        self._url = url
        self._socks_port = int(socks_port)
        self._http_port = int(http_port)
        self._cancelled = False
        self._completed_nodes = 0
        self._current_proc: subprocess.Popen | None = None

    def cancel(self) -> None:
        """Отмена тестирования."""
        self._cancelled = True
        proc = self._current_proc
        if proc and proc.poll() is None:
            try:
                proc.terminate()
            except Exception:
                pass

    @property
    def completed_nodes(self) -> int:
        return self._completed_nodes

    @property
    def was_cancelled(self) -> bool:
        return self._cancelled

    # ------------------------------------------------------------------

    def run(self) -> None:
        total = len(self._nodes)
        self._completed_nodes = 0
        try:
            for node in self._nodes:
                if self._cancelled:
                    break
                skip, skip_message = should_skip_speed_test(node)
                if skip:
                    self._completed_nodes += 1
                    self.skipped.emit(node.id, skip_message)
                    self.progress.emit(self._completed_nodes, total)
                    continue
                self.node_progress.emit(node.id, 0)
                finished, speed, alive = self._test_node(node)
                if not finished:
                    break
                self._completed_nodes += 1
                self.node_progress.emit(node.id, 100)
                self.result.emit(node.id, speed, alive)
                self.progress.emit(self._completed_nodes, total)
        finally:
            self.completed.emit()

    # ------------------------------------------------------------------

    def _test_node(self, node: Node) -> tuple[bool, float | None, bool]:
        """Запускает временный xray, скачивает тестовый файл.

        Возвращает кортеж (finished, speed_mbps, is_alive), где finished=False
        означает ручную отмену текущего измерения и отсутствие результата для ноды.
        """
        if not Path(self._xray_path).is_file():
            return True, None, False

        # Минимальные настройки для временного xray
        settings = AppSettings()
        settings.log_level = "none"

        try:
            config = build_xray_config(
                node,
                self._routing,
                settings,
                socks_port=self._socks_port,
                http_port=self._http_port,
            )
        except Exception:
            return True, None, False

        # Убираем stats/api — для теста скорости не нужны
        config.pop("stats", None)
        config.pop("api", None)
        config.pop("policy", None)
        config["inbounds"] = [
            ib for ib in config.get("inbounds", [])
            if ib.get("tag") in ("socks-in", "http-in")
        ]
        routing_obj = config.get("routing", {})
        routing_obj["rules"] = [
            r for r in routing_obj.get("rules", [])
            if r.get("inboundTag") != ["api"]
        ]
        config["routing"] = routing_obj
        config["outbounds"] = [
            ob for ob in config.get("outbounds", [])
            if ob.get("tag") != "api"
        ]

        tmp = None
        proc = None
        try:
            tmp = tempfile.NamedTemporaryFile(
                mode="w",
                suffix=".json",
                prefix="xray_speed_",
                delete=False,
                encoding="utf-8",
            )
            json.dump(config, tmp, ensure_ascii=True)
            tmp.close()

            proc = subprocess.Popen(
                [self._xray_path, "run", "-c", tmp.name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=0x08000000,  # CREATE_NO_WINDOW
            )
            self._current_proc = proc

            # Даём xray время на запуск (с проверкой отмены)
            for _ in range(10):
                if self._cancelled:
                    return False, None, False
                self.node_progress.emit(node.id, 2 + _ * 2)
                time.sleep(0.1)

            if proc.poll() is not None:
                if self._cancelled:
                    return False, None, False
                return True, None, False

            url = self._url or _get_speed_url(node.country_code)
            rounds = self._rounds
            results: list[float] = []
            for round_index in range(rounds):
                if self._cancelled:
                    return False, None, False
                s = self._measure_speed(url, node.id, round_index, rounds)
                if self._cancelled:
                    return False, None, False
                if s is not None and s > 0:
                    results.append(s)

            if not results:
                return True, None, False

            # Отбрасываем худший замер, берём среднее оставшихся
            if len(results) > 1:
                results.sort()
                results = results[1:]  # убираем самый медленный
            speed = round(sum(results) / len(results), 2)
            return True, speed, True

        except Exception:
            if self._cancelled:
                return False, None, False
            return True, None, False
        finally:
            self._current_proc = None
            if proc and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
            if tmp:
                try:
                    Path(tmp.name).unlink(missing_ok=True)
                except Exception:
                    pass

    def _measure_speed(self, url: str, node_id: str, round_index: int, total_rounds: int) -> float | None:
        """Скачивает тестовый файл через временный прокси, возвращает скорость в МБ/с."""
        proxy_url = f"http://{PROXY_HOST}:{self._http_port}"
        handler = ProxyHandler({"http": proxy_url, "https": proxy_url})
        opener = build_opener(handler)

        percent_start = 20 + int(70 * round_index / max(total_rounds, 1))
        percent_end = 20 + int(70 * (round_index + 1) / max(total_rounds, 1))

        def _progress(fraction: float) -> None:
            percent = percent_start + int((percent_end - percent_start) * fraction)
            self.node_progress.emit(node_id, max(percent_start, min(percent_end, percent)))

        bps = measure_download_bps(
            opener,
            url,
            timeout=self._timeout,
            max_bytes=self._max_bytes,
            cancelled=lambda: self._cancelled,
            on_fraction=_progress,
        )
        if bps is None:
            return None
        self.node_progress.emit(node_id, percent_end)
        return round(bps / (1024 * 1024), 2)


class ActiveProxySpeedProbeWorker(QThread):
    """Короткий замер скорости ТЕКУЩЕГО сервера через работающий локальный прокси.

    ``http_port`` > 0 — через HTTP-inbound запущенного ядра; ``None`` в режиме
    TUN — обычным соединением, которое сам TUN уводит в туннель (как у
    ``ConnectivityTestWorker``).  Результат — байты/с или ``None``.
    """

    measured = pyqtSignal(object)  # bytes/sec (float) | None

    def __init__(self, http_port: int | None, url: str, *, timeout: float, max_bytes: int):
        super().__init__()
        self._http_port = http_port
        self._url = url
        self._timeout = timeout
        self._max_bytes = max_bytes
        self._cancelled = False

    def cancel(self) -> None:
        self._cancelled = True

    def run(self) -> None:
        if self._http_port:
            proxy_url = f"http://{PROXY_HOST}:{int(self._http_port)}"
            opener = build_opener(ProxyHandler({"http": proxy_url, "https": proxy_url}))
        else:
            opener = build_opener()
        bps: float | None = None
        try:
            bps = measure_download_bps(
                opener,
                self._url,
                timeout=self._timeout,
                max_bytes=self._max_bytes,
                cancelled=lambda: self._cancelled,
                partial_on_error=True,
            )
        finally:
            if not self._cancelled:
                self.measured.emit(bps)
