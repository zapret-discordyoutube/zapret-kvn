"""Какие страницы памяти нужны программе и как вернуть их с диска одним заходом.

Пока окно свёрнуто или в трее, Windows отбирает у программы страницы памяти
(рабочий набор). Когда окно возвращают, главный поток снова обращается к этим
страницам, и каждое обращение — отдельный поход на диск за 4 КБ. Замер на win10:
после выгрузки возврат окна стоит ~11 000 таких обращений на ~50 МБ; на быстром
диске это лишние 0,3 с, на обычном жёстком (около 8–10 мс на чтение) — минуты.

Здесь два действия, оба без Qt:

- ``snapshot_working_set`` — какие адреса сейчас в оперативной памяти программы
  (QueryWorkingSet), слитые в непрерывные куски;
- ``prefetch_working_set`` — просит Windows подтянуть эти куски большими
  пачками (PrefetchVirtualMemory). Система читает диск одним планом, а не по
  странице, и это идёт в отдельном потоке, пока окно рисуется.

Принудительной выгрузки памяти здесь нет и быть не должно: она как раз и
заставляет окно открываться медленно.
"""

from __future__ import annotations

import ctypes
import sys
import time
from dataclasses import dataclass

PAGE_SIZE = 4096
# Сколько кусков отдаём Windows за один вызов: система принимает массивом, но
# очень длинный массив лучше резать.
_PREFETCH_CHUNK = 2048
# Начальный размер буфера QueryWorkingSet в страницах (хватает на ~1 ГБ); при нехватке растёт.
_INITIAL_PAGES = 1 << 18


@dataclass(frozen=True, slots=True)
class WorkingSetSnapshot:
    """Куски адресов (начало, длина в байтах), лежавшие в памяти программы."""

    ranges: tuple[tuple[int, int], ...]
    total_bytes: int
    taken_ms: float


@dataclass(frozen=True, slots=True)
class PrefetchResult:
    ranges: int
    total_bytes: int
    elapsed_ms: float
    ok: bool


class _MemoryRange(ctypes.Structure):
    # WIN32_MEMORY_RANGE_ENTRY
    _fields_ = [("VirtualAddress", ctypes.c_void_p), ("NumberOfBytes", ctypes.c_size_t)]


def _merge_pages(pages: list[int]) -> list[tuple[int, int]]:
    """Отсортированные адреса страниц → куски подряд идущих страниц."""
    merged: list[list[int]] = []
    for address in pages:
        if merged and merged[-1][0] + merged[-1][1] == address:
            merged[-1][1] += PAGE_SIZE
        else:
            merged.append([address, PAGE_SIZE])
    return [(start, length) for start, length in merged]


def snapshot_working_set() -> WorkingSetSnapshot | None:
    """Адреса страниц, лежащих сейчас в памяти этого процесса. Не Windows или сбой — None."""
    if sys.platform != "win32":
        return None
    started = time.perf_counter()
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        kernel32.GetCurrentProcess.restype = ctypes.c_void_p
        psapi.QueryWorkingSet.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong]
        process = kernel32.GetCurrentProcess()
        capacity = _INITIAL_PAGES
        for _attempt in range(6):
            # Первое слово — число записей, дальше по слову на страницу.
            buffer = (ctypes.c_size_t * (capacity + 1))()
            if psapi.QueryWorkingSet(process, buffer, ctypes.sizeof(buffer)):
                break
            capacity *= 2
        else:
            return None
        count = int(buffer[0])
        # Младшие 12 бит записи — признаки страницы, остальное — адрес.
        pages = sorted({(int(buffer[index + 1]) >> 12) << 12 for index in range(min(count, capacity))})
        ranges = _merge_pages(pages)
    except Exception:
        return None
    return WorkingSetSnapshot(
        ranges=tuple(ranges),
        total_bytes=len(pages) * PAGE_SIZE,
        taken_ms=(time.perf_counter() - started) * 1000,
    )


def prefetch_working_set(snapshot: WorkingSetSnapshot | None) -> PrefetchResult | None:
    """Просит Windows подтянуть страницы снимка в память. Блокирует вызывающий поток — звать из фонового."""
    if snapshot is None or not snapshot.ranges or sys.platform != "win32":
        return None
    started = time.perf_counter()
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        prefetch = getattr(kernel32, "PrefetchVirtualMemory", None)
        if prefetch is None:  # Windows 7
            return None
        kernel32.GetCurrentProcess.restype = ctypes.c_void_p
        prefetch.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_ulong]
        process = kernel32.GetCurrentProcess()
        ok = True
        ranges = snapshot.ranges
        for offset in range(0, len(ranges), _PREFETCH_CHUNK):
            chunk = ranges[offset : offset + _PREFETCH_CHUNK]
            entries = (_MemoryRange * len(chunk))()
            for index, (start, length) in enumerate(chunk):
                entries[index].VirtualAddress = start
                entries[index].NumberOfBytes = length
            ok = bool(prefetch(process, len(chunk), entries, 0)) and ok
    except Exception:
        return None
    return PrefetchResult(
        ranges=len(snapshot.ranges),
        total_bytes=snapshot.total_bytes,
        elapsed_ms=(time.perf_counter() - started) * 1000,
        ok=ok,
    )


__all__ = [
    "PAGE_SIZE",
    "PrefetchResult",
    "WorkingSetSnapshot",
    "prefetch_working_set",
    "snapshot_working_set",
]
