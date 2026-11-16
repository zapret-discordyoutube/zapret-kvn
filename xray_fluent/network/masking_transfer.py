"""One "Подбор" transfer through the running tunnel (blocking: worker thread only).

Reads ``tester.TRANSFER_BYTES`` of the same neutral file the speed check uses
(``SPEED_TEST_DEFAULT_URL``), on a fresh connection, with a browser User-Agent. A sampler thread
records the byte count every ``SAMPLE_SEC`` while the read runs, so a blocked read shows up as a
stall at its offset; ``masking.tester.verdict`` decides what it means. Same as Android
``MaskingTransferProbe``: the inner stream is measured, and the per-connection freeze of the
tunnel's outer connection stops it a few percent of bytes earlier (tunnel overhead).
"""

from __future__ import annotations

import socket
import threading
import time
from typing import Callable
from urllib.error import URLError
from urllib.request import Request

from ..masking.tester import TRANSFER_BYTES, End, Transfer
from .speed_test_worker import SPEED_TEST_USER_AGENT

SAMPLE_SEC = 0.5
# Longer than tester.STALL_MS: a read that gives up earlier could not show the freeze.
READ_TIMEOUT_SEC = 12.0
MAX_TRANSFER_SEC = 40.0
_CHUNK = 16 * 1024


class TransferRecorder:
    """Samples and the end of one transfer; the reader and the sampler threads share it."""

    def __init__(self, clock: Callable[[], float] = time.perf_counter):
        self._clock = clock
        self._started = clock()
        self._lock = threading.Lock()
        self._bytes = 0
        self._samples: list[tuple[int, int]] = []
        self.end: End | None = None
        self.first_byte_ms: int | None = None

    def elapsed_ms(self) -> int:
        return int((self._clock() - self._started) * 1000)

    def sample(self) -> None:
        with self._lock:
            self._samples.append((self.elapsed_ms(), self._bytes))

    def add(self, count: int) -> None:
        if count > 0 and self.first_byte_ms is None:
            self.first_byte_ms = self.elapsed_ms()
        with self._lock:
            self._bytes += count

    @property
    def bytes(self) -> int:
        with self._lock:
            return self._bytes

    def finish(self, end: End) -> None:
        if self.end is None:
            self.end = end

    def transfer(self) -> Transfer:
        self.sample()
        with self._lock:
            samples = tuple(self._samples)
        return Transfer(samples, self.end or End.ERROR, TRANSFER_BYTES)


def end_of(error: BaseException) -> End:
    """A read timeout is the stall itself; a reset or an early close is FIN/RST (inconclusive)."""
    if isinstance(error, URLError) and isinstance(error.reason, BaseException):
        return end_of(error.reason)
    if isinstance(error, (socket.timeout, TimeoutError)):
        return End.TIMEOUT
    if isinstance(error, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)):
        return End.RESET
    return End.ERROR


def run_transfer(
    opener,
    url: str,
    *,
    cancelled: Callable[[], bool] = lambda: False,
    clock: Callable[[], float] = time.perf_counter,
    sample_sec: float = SAMPLE_SEC,
) -> tuple[Transfer, int | None]:
    recorder = TransferRecorder(clock)
    done = threading.Event()

    def sampler() -> None:
        while not done.wait(sample_sec):
            recorder.sample()

    thread = threading.Thread(target=sampler, name="masking-transfer-sampler", daemon=True)
    thread.start()
    try:
        request = Request(url, headers={
            "User-Agent": SPEED_TEST_USER_AGENT,
            "Accept-Encoding": "identity",
            "Connection": "close",
            "Range": f"bytes=0-{TRANSFER_BYTES - 1}",
        })
        with opener.open(request, timeout=READ_TIMEOUT_SEC) as response:
            if getattr(response, "status", 200) not in (200, 206):
                recorder.finish(End.ERROR)
            while recorder.end is None:
                if cancelled():
                    recorder.finish(End.ERROR)
                    break
                if recorder.elapsed_ms() >= MAX_TRANSFER_SEC * 1000:
                    recorder.finish(End.TIMEOUT)
                    break
                wanted = min(_CHUNK, TRANSFER_BYTES - recorder.bytes)
                chunk = response.read(wanted)
                if not chunk:
                    recorder.finish(End.RESET)
                    break
                recorder.add(len(chunk))
                if recorder.bytes >= TRANSFER_BYTES:
                    recorder.finish(End.COMPLETED)
    except Exception as exc:  # network errors of every kind end the transfer, never the app
        recorder.finish(end_of(exc))
    finally:
        done.set()
        thread.join(timeout=1.0)
    return recorder.transfer(), recorder.first_byte_ms
