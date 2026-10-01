"""Воркер тестирования скорости — измеряет скорость загрузки через каждый прокси-узел."""

from __future__ import annotations

import json
import os
import random
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from urllib.request import ProxyHandler, Request

from PyQt6.QtCore import QThread, pyqtSignal

from ..constants import (
    PROXY_HOST,
    HYSTERIA_PATH_DEFAULT,
    SPEED_TEST_DEFAULT_URL,
    SPEED_TEST_HYSTERIA_PATH,
    SPEED_TEST_ROUNDS,
    SPEED_TEST_TEMP_HTTP_PORT,
    SPEED_TEST_TIMEOUT,
    SPEED_TEST_URLS_BY_COUNTRY,
    SPEED_TEST_XRAY_PATH,
)
from ..engines.hysteria.config_adapter import build_uri_client_config
from ..engines.hysteria.runtime_contract import classify_hysteria_uri
from .http_utils import build_opener
from ..profiles.models import Node

# Обычный браузерный User-Agent: хост тестового файла не должен видеть, что с
# адреса прокси-сервера ходит именно это приложение.
SPEED_TEST_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
)

# Окно короче этого не считается установившимся замером.
_MIN_WINDOW_SEC = 0.5


def measure_download_bps(
    opener,
    url: str,
    *,
    timeout: float,
    max_bytes: int | None = None,
    cancelled=lambda: False,
    on_fraction=None,
    partial_on_error: bool = False,
    user_agent: str = SPEED_TEST_USER_AGENT,
    warmup: float = 0.0,
    window: float | None = None,
) -> float | None:
    """Скачать файл через ``opener`` и вернуть скорость в байтах/с.

    Замер ограничен и по времени (``timeout`` — и на ответ, и на всю загрузку),
    и по объёму (``max_bytes``).  ``None`` — ничего не скачано или отмена.
    ``partial_on_error`` — обрыв/таймаут посреди загрузки считается замером по
    уже пришедшим байтам (для «умной проверки»: зависающий сервер — медленный);
    по умолчанию такой раунд не засчитывается.

    ``window`` включает оконный замер ручного теста скорости: первые
    ``warmup`` секунд после первого байта (разгон TCP) отбрасываются, затем
    ``window`` секунд считаются скоростью.  Загрузка заканчивается сама, не
    дожидаясь конца файла.  Если объём кончился раньше разгона, скорость
    считается от первого байта.  Без ``window`` поведение прежнее: время идёт
    от отправки запроса — так меряет «умная проверка», и обе её стороны
    (текущий сервер и кандидат) обязаны мериться одинаково.
    Блокирующий вызов: только из рабочего потока.
    """

    req = Request(url, headers={"User-Agent": user_agent})
    start = time.perf_counter()
    total_bytes = 0
    windowed = window is not None and window > 0
    warmup = max(0.0, float(warmup)) if windowed else 0.0
    first_byte_at: float | None = None
    first_chunk_bytes = 0
    mark_at: float | None = None
    mark_bytes = 0
    now = start
    try:
        with opener.open(req, timeout=timeout) as resp:
            length_header = resp.headers.get("Content-Length") or ""
            try:
                total_length = int(length_header)
            except (TypeError, ValueError):
                total_length = 0
            if max_bytes:
                total_length = min(total_length, max_bytes) if total_length > 0 else max_bytes
            # read1 отдаёт то, что уже пришло, не дожидаясь полного чанка: на
            # еле живом канале цикл всё равно доходит до проверок окна.
            read = getattr(resp, "read1", None) if windowed else None
            if read is None:
                read = resp.read
            while True:
                chunk = read(64 * 1024)
                if not chunk:
                    break
                total_bytes += len(chunk)
                if cancelled():
                    return None
                now = time.perf_counter()
                elapsed = now - start
                if first_byte_at is None:
                    first_byte_at = now
                    first_chunk_bytes = total_bytes
                since_first = now - first_byte_at
                if windowed and mark_at is None and since_first >= warmup:
                    mark_at, mark_bytes = now, total_bytes
                if on_fraction is not None:
                    if windowed:
                        fraction = since_first / (warmup + window)
                        if total_length > 0:
                            fraction = max(fraction, total_bytes / total_length)
                        fraction = min(1.0, fraction)
                    elif total_length > 0:
                        fraction = min(1.0, total_bytes / total_length)
                    else:
                        fraction = min(1.0, elapsed / max(timeout, 0.1))
                    on_fraction(fraction)
                if max_bytes and total_bytes >= max_bytes:
                    break
                if windowed:
                    if mark_at is not None and now - mark_at >= window:
                        break
                    if elapsed > timeout + warmup + window:
                        break
                elif elapsed > timeout:
                    break
    except Exception:
        if cancelled() or total_bytes <= 0 or not partial_on_error:
            return None
        now = time.perf_counter()
    if total_bytes <= 0:
        return None
    if windowed and first_byte_at is not None:
        if mark_at is not None and now - mark_at >= _MIN_WINDOW_SEC and total_bytes > mark_bytes:
            return (total_bytes - mark_bytes) / (now - mark_at)
        # Окна не получилось (объём или соединение кончились раньше разгона).
        # Первый чанк пришёл В момент отсчёта, а не после него, поэтому в
        # числитель не входит.  Совсем короткий ответ — пара чанков подряд —
        # скоростью канала не является: его делим на всё время запроса.
        since_first = now - first_byte_at
        if since_first >= _MIN_WINDOW_SEC and total_bytes > first_chunk_bytes:
            return (total_bytes - first_chunk_bytes) / since_first
    elapsed = time.perf_counter() - start
    if elapsed <= 0:
        return None
    return total_bytes / elapsed


def _same_binary(source: Path, target: Path) -> bool:
    try:
        src, dst = source.stat(), target.stat()
    except OSError:
        return False
    return src.st_size == dst.st_size and abs(src.st_mtime - dst.st_mtime) < 2.0


def prepare_speed_test_xray(source: Path, target: Path = SPEED_TEST_XRAY_PATH) -> Path:
    """Путь, из которого запускать временный xray теста скорости.

    Тот же бинарь, но под своим именем (жёсткая ссылка, иначе копия):
    правило ``process_path → direct`` в плане sing-box TUN
    (``runtime_planner._ensure_speed_test_process_direct_route``) выводит его
    трафик мимо туннеля, не задевая ``xray.exe`` гибридного сайдкара.  Если
    источник обновился, ссылка пересоздаётся (сверка размера и mtime).  Любой
    сбой — запуск из исходного пути: замер важнее обхода TUN.
    Блокирующий вызов: только из рабочего потока.
    """

    source = Path(source)
    if not source.is_file():
        return source
    try:
        if source.resolve() == target.resolve():
            return source
    except OSError:
        return source
    if _same_binary(source, target):
        return target
    tmp = target.with_name(target.name + ".tmp")
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp.unlink(missing_ok=True)
        try:
            os.link(source, tmp)
        except OSError:
            shutil.copy2(source, tmp)
        os.replace(tmp, target)
    except OSError:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        return source
    return target if _same_binary(source, target) else source


def _speed_test_env(source: Path) -> dict[str, str]:
    """geoip.dat/geosite.dat лежат рядом с исходным xray, а не с его ссылкой."""

    env = dict(os.environ)
    env.setdefault("XRAY_LOCATION_ASSET", str(Path(source).parent))
    return env


# Метка места, куда в команду запуска подставляется путь к конфигу.
_CONFIG = object()

# Сколько ждать готовности временного ядра.
SPEED_TEST_CORE_START_TIMEOUT = 20.0
_CORE_POLL_SEC = 0.1


def _port_open(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, int(port)), timeout=0.5):
            return True
    except OSError:
        return False


def _free_port(host: str) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind((host, 0))
        return int(probe.getsockname()[1])


def _pick_port(host: str, preferred: int) -> int:
    """Предпочитаемый порт, а если он занят — любой свободный.

    Порт может держать ``xray-speedtest.exe``, осиротевший после падения
    приложения: новый xray тогда не стартует, а «порт открыт» выглядел бы как
    готовность — и замер ушёл бы через чужой сервер.
    """

    if not _port_open(host, preferred):
        return int(preferred)
    try:
        return _free_port(host)
    except OSError:
        return int(preferred)


def build_speed_test_config(node: Node, http_port: int) -> dict:
    """Минимальный конфиг временного xray: один HTTP-inbound → сервер.

    Правил маршрутизации нет намеренно.  Весь трафик замера обязан идти через
    проверяемый сервер (правила «напрямую» дали бы скорость провайдера), а без
    ссылок на ``geosite:``/``geoip:`` xray не читает гео-базы и стартует за
    доли секунды вместо 9–16 с на холодном диске.
    """

    outbound = json.loads(json.dumps(node.outbound))
    outbound["tag"] = "proxy"
    return {
        "log": {"loglevel": "none"},
        "inbounds": [
            {
                "tag": "http-in",
                "listen": PROXY_HOST,
                "port": int(http_port),
                "protocol": "http",
                "settings": {},
            }
        ],
        "outbounds": [outbound],
    }


def _get_speed_url(country_code: str) -> str:
    """Возвращает URL тестового файла по стране сервера с явным fallback."""
    return SPEED_TEST_URLS_BY_COUNTRY.get(country_code.lower(), SPEED_TEST_DEFAULT_URL)


def is_hysteria_speed_node(node: Node) -> bool:
    """Hysteria2 из ссылки hy2:// — её меряет официальный клиент Hysteria."""
    outbound = node.outbound if isinstance(node.outbound, dict) else {}
    if str(outbound.get("type") or "").strip().lower() != "hysteria2":
        return False
    link = str(node.link or "").strip()
    return link.partition(":")[0].lower() in {"hy2", "hysteria2"}


def should_skip_speed_test(node: Node) -> tuple[bool, str]:
    """Кого тест скорости не умеет мерить; пропуск мягкий, без is_alive=False.

    Временное ядро — то же, которым приложение подключается к серверу: xray
    для нод в формате xray, официальный клиент для Hysteria2.  Остальные
    native sing-box ноды (включая endpoint-ноды WireGuard/AWG) пропускаются.
    """
    outbound = node.outbound if isinstance(node.outbound, dict) else {}
    if not (outbound.get("type") and not outbound.get("protocol")):
        return False, ""
    protocol = str(outbound.get("type") or node.scheme or "native").upper()
    if is_hysteria_speed_node(node):
        capability = classify_hysteria_uri(str(node.link or "").strip(), platform="windows")
        if capability.valid:
            return False, ""
        reason = capability.validation_message or "ссылка несовместима с клиентом Hysteria"
        return True, f"Тест скорости для {node.name} пропущен: {reason}."
    if str(outbound.get("type") or "").strip().lower() == "hysteria2":
        return True, (
            f"Тест скорости для {node.name} пропущен: Hysteria2 меряется только "
            "по исходной ссылке hy2:// — импортируйте сервер ссылкой."
        )
    return True, f"Тест скорости для {node.name} пропущен: протокол {protocol} пока не измеряется."


def build_hysteria_speed_test_config(node: Node, http_port: int) -> dict:
    """Конфиг временного клиента Hysteria: локальный HTTP-прокси → сервер.

    Собирается тем же адаптером, что и рабочее подключение (обфускация,
    закрепление сертификата, port hopping, полоса), только вместо SOCKS-relay
    с паролем — HTTP-прокси на loopback, через который идёт замер.
    """

    config = build_uri_client_config(
        str(node.link or "").strip(),
        node.outbound if isinstance(node.outbound, dict) else {},
        relay_host=PROXY_HOST,
        relay_port=int(http_port),
        relay_username="",
        relay_password="",
    )
    config.pop("socks5", None)
    config["http"] = {"listen": f"{PROXY_HOST}:{int(http_port)}"}
    return config


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
        timeout: float = SPEED_TEST_TIMEOUT,
        *,
        rounds: int = SPEED_TEST_ROUNDS,
        max_bytes: int | None = None,
        url: str | None = None,
        http_port: int = SPEED_TEST_TEMP_HTTP_PORT,
        retries: int = 0,
        warmup: float = 0.0,
        window: float | None = None,
        partial_on_error: bool = False,
        pause_range: tuple[float, float] | None = None,
        hysteria_path: str | None = None,
    ):
        super().__init__()
        self._nodes = list(nodes)
        self._xray_path = xray_path
        self._hysteria_path = str(hysteria_path or HYSTERIA_PATH_DEFAULT)
        self._hysteria_launch_path: str | None = None
        self._timeout = timeout
        # ``rounds`` — сколько удачных замеров усреднять; ``retries`` — сколько
        # лишних попыток дать серверу, пока удачных меньше.  Ручной тест берёт
        # один оконный замер (``warmup``/``window``) и одну повторную попытку;
        # «умная проверка» авто-переключения — один короткий замер без окна,
        # с общим URL и своим временным портом.
        self._rounds = max(1, int(rounds))
        self._retries = max(0, int(retries))
        self._max_bytes = max_bytes
        self._url = url
        self._http_port = int(http_port)
        self._warmup = warmup
        self._window = window
        self._partial_on_error = bool(partial_on_error)
        # Случайная пауза между серверами: подряд идущие объёмные потоки на
        # каждый адрес списка без передышки — самый заметный след теста.
        self._pause_range = pause_range
        self._cancelled = False
        self._completed_nodes = 0
        self._current_proc: subprocess.Popen | None = None
        self._last_percent: tuple[str, int] | None = None

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
        self._launch_path = str(prepare_speed_test_xray(Path(self._xray_path)))
        measured_any = False
        try:
            for node in self._nodes:
                if self._cancelled:
                    break
                skip, skip_message = should_skip_speed_test(node)
                if not skip and is_hysteria_speed_node(node) and not Path(self._hysteria_path).is_file():
                    skip, skip_message = True, (
                        f"Тест скорости для {node.name} пропущен: не найдено ядро Hysteria."
                    )
                if skip:
                    self._completed_nodes += 1
                    self.skipped.emit(node.id, skip_message)
                    self.progress.emit(self._completed_nodes, total)
                    continue
                if measured_any and not self._pause():
                    break
                measured_any = True
                self._emit_percent(node.id, 0)
                finished, speed, alive = self._test_node(node)
                if not finished:
                    break
                self._completed_nodes += 1
                self._emit_percent(node.id, 100)
                self.result.emit(node.id, speed, alive)
                self.progress.emit(self._completed_nodes, total)
        finally:
            self.completed.emit()

    # ------------------------------------------------------------------

    def _emit_percent(self, node_id: str, percent: int) -> None:
        """Прогресс строки — только когда процент изменился.

        Чанк 64 КБ приходит сотни раз в секунду, а процент меняется пару
        десятков раз за замер: без этого фильтра очередь сигналов в GUI-поток
        забивалась дубликатами.
        """

        key = (node_id, int(percent))
        if key == self._last_percent:
            return
        self._last_percent = key
        self.node_progress.emit(node_id, int(percent))

    def _pause(self) -> bool:
        """Пауза перед следующим сервером; ``False`` — отменили."""

        if not self._pause_range:
            return not self._cancelled
        low, high = self._pause_range
        deadline = time.monotonic() + random.uniform(low, max(low, high))
        while time.monotonic() < deadline:
            if self._cancelled:
                return False
            time.sleep(_CORE_POLL_SEC)
        return not self._cancelled

    def _wait_core_ready(self, proc: subprocess.Popen, node_id: str, http_port: int) -> bool:
        """Дождаться HTTP-inbound временного xray; ``False`` — не поднялся."""

        started = time.monotonic()
        deadline = started + SPEED_TEST_CORE_START_TIMEOUT
        while not self._cancelled:
            if proc.poll() is not None:
                return False
            if _port_open(PROXY_HOST, http_port):
                # Порт мог открыть не наш процесс: свой обязан быть жив.
                return proc.poll() is None
            now = time.monotonic()
            if now >= deadline:
                return False
            self._emit_percent(node_id, 2 + int(16 * (now - started) / SPEED_TEST_CORE_START_TIMEOUT))
            time.sleep(_CORE_POLL_SEC)
        return False

    def _core_launch(self, node: Node, http_port: int):
        """(конфиг, команда, окружение, рабочий каталог) временного ядра или ``None``.

        В команде на месте пути к конфигу стоит метка ``_CONFIG``.
        """

        if is_hysteria_speed_node(node):
            source = Path(self._hysteria_path)
            if not source.is_file():
                return None
            if self._hysteria_launch_path is None:
                self._hysteria_launch_path = str(
                    prepare_speed_test_xray(source, SPEED_TEST_HYSTERIA_PATH)
                )
            command = [
                self._hysteria_launch_path,
                "--config", _CONFIG,
                "--disable-update-check",
                "--log-level", "error",
                "client",
            ]
            return build_hysteria_speed_test_config(node, http_port), command, None, str(source.parent)

        if not Path(self._xray_path).is_file():
            return None
        command = [getattr(self, "_launch_path", "") or self._xray_path, "run", "-c", _CONFIG]
        return build_speed_test_config(node, http_port), command, _speed_test_env(Path(self._xray_path)), None

    def _test_node(self, node: Node) -> tuple[bool, float | None, bool]:
        """Запускает временный xray, скачивает тестовый файл.

        Возвращает кортеж (finished, speed_mbps, is_alive), где finished=False
        означает ручную отмену текущего измерения и отсутствие результата для ноды.
        """
        http_port = _pick_port(PROXY_HOST, self._http_port)
        try:
            launch = self._core_launch(node, http_port)
        except Exception:
            return True, None, False
        if launch is None:
            return True, None, False
        config, command, env, cwd = launch

        config_path: Path | None = None
        proc = None
        try:
            tmp = tempfile.NamedTemporaryFile(
                mode="w",
                suffix=".json",
                prefix="xray_speed_",
                delete=False,
                encoding="utf-8",
            )
            config_path = Path(tmp.name)
            json.dump(config, tmp, ensure_ascii=True)
            tmp.close()

            proc = subprocess.Popen(
                [part if part is not _CONFIG else str(config_path) for part in command],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=env,
                cwd=cwd,
                creationflags=0x08000000,  # CREATE_NO_WINDOW
            )
            self._current_proc = proc

            ready = self._wait_core_ready(proc, node.id, http_port)
            # Конфиг содержит ключи сервера: ядро его уже прочитало, на диске
            # он больше не нужен.
            _unlink_quietly(config_path)
            config_path = None
            if self._cancelled:
                return False, None, False
            if not ready:
                return True, None, False

            url = self._url or _get_speed_url(node.country_code)
            attempts = self._rounds + self._retries
            results: list[float] = []
            for attempt in range(attempts):
                if self._cancelled:
                    return False, None, False
                s = self._measure_speed(url, node.id, http_port, attempt, attempts)
                if self._cancelled:
                    return False, None, False
                if s is not None and s > 0:
                    results.append(s)
                    if len(results) >= self._rounds:
                        break

            if not results:
                return True, None, False

            # Несколько раундов: отбрасываем худший замер, берём среднее оставшихся
            if len(results) > 1:
                results.sort()
                results = results[1:]
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
            if config_path is not None:
                _unlink_quietly(config_path)

    def _measure_speed(
        self, url: str, node_id: str, http_port: int, attempt: int, attempts: int,
    ) -> float | None:
        """Скачивает тестовый файл через временный прокси, возвращает скорость в МБ/с."""
        proxy_url = f"http://{PROXY_HOST}:{http_port}"
        handler = ProxyHandler({"http": proxy_url, "https": proxy_url})
        opener = build_opener(handler)

        percent_start = 20 + int(70 * attempt / max(attempts, 1))
        percent_end = 20 + int(70 * (attempt + 1) / max(attempts, 1))

        def _progress(fraction: float) -> None:
            percent = percent_start + int((percent_end - percent_start) * fraction)
            self._emit_percent(node_id, max(percent_start, min(percent_end, percent)))

        bps = measure_download_bps(
            opener,
            url,
            timeout=self._timeout,
            max_bytes=self._max_bytes,
            cancelled=lambda: self._cancelled,
            on_fraction=_progress,
            partial_on_error=self._partial_on_error,
            warmup=self._warmup,
            window=self._window,
        )
        if bps is None:
            return None
        self._emit_percent(node_id, percent_end)
        return round(bps / (1024 * 1024), 2)


def _unlink_quietly(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass


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
