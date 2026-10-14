"""Частичная загрузка обновления: только изменившиеся файлы архива выпуска.

Полный архив ``ZapretKVN-vX-windows-x64.zip`` весит ~140 МБ, а между соседними
версиями меняется несколько файлов. Forgejo отдаёт архив с ``Range``, поэтому
программа читает конец zip (каталог файлов), сравнивает его с подписанным
списком выпуска и установленной копией и докачивает только нужные куски.

Почему это не слабее загрузки целого архива
-------------------------------------------
Доверие даёт только подписанный список выпуска (``update-manifest.json``):
в нём для каждого файла сборки записаны путь, размер и SHA-256. Каталог zip
с сервера — всего лишь подсказка, где что лежит, ему не верят:

* состав файлов каталога обязан совпасть с подписанным списком до последнего
  имени; лишнее или недостающее — отказ (и обычная загрузка целого архива);
* файл из установленной копии берётся, только если его SHA-256 равен
  подписанному; копия тут же перепроверяется по хешу;
* файл из архива распаковывается с жёстким пределом размера и принимается,
  только если его размер, CRC-32 и SHA-256 равны подписанным.

В итоге в каталог установки попадает ровно то множество файлов, которое
подписано, и каждый файл проверен криптографическим хешем из подписи.
При любом сомнении вызывающий код качает архив целиком и проверяет его
SHA-256 по тому же списку, как раньше.
"""

from __future__ import annotations

import hashlib
import logging
import os
import shutil
import struct
import threading
import re
import urllib.request
import zlib
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

_log = logging.getLogger(__name__)

_EOCD_SIG = b"PK\x05\x06"
_EOCD64_LOC_SIG = b"PK\x06\x07"
_EOCD64_SIG = b"PK\x06\x06"
_CD_SIG = b"PK\x01\x02"
_LOCAL_SIG = b"PK\x03\x04"
_EOCD_SIZE = 22
_EOCD64_LOC_SIZE = 20
_EOCD64_SIZE = 56
_CD_FIXED = 46
_LOCAL_FIXED = 30
_MAX_COMMENT = 0xFFFF
_U16 = 0xFFFF
_U32 = 0xFFFFFFFF

TAIL_BYTES = 256 * 1024
MAX_DIRECTORY_BYTES = 32 * 1024 * 1024
MAX_ENTRIES = 50_000
# Доля полного архива, начиная с которой частичная загрузка не нужна.
MAX_DELTA_RATIO = 0.6
# Куски архива ближе друг к другу докачиваются одним запросом.
MERGE_GAP_BYTES = 64 * 1024
MAX_RANGES = 8
PIECE_BYTES = 4 * 1024 * 1024
MAX_PIECES_PER_RANGE = 4
PARALLEL_REQUESTS = 4
_CHUNK = 1024 * 1024

_METHOD_STORED = 0
_METHOD_DEFLATE = 8


class DeltaUnavailable(Exception):
    """Частичная загрузка не годится; нужно качать архив целиком.

    Сетевые сбои (``OSError`` и подобные) этим исключением не оборачиваются:
    по ним вызывающий код выбирает другой путь (прокси).
    """


class RangeSource(Protocol):
    """Источник байтов архива по диапазону ``[start, end]`` включительно."""

    def read_range(self, start: int, end: int) -> bytes: ...

    def stream_range(self, start: int, end: int, sink: Callable[[bytes], None]) -> None: ...


@dataclass(frozen=True, slots=True)
class ZipEntry:
    name: str
    raw_name: bytes
    flags: int
    method: int
    crc32: int
    compressed_size: int
    size: int
    offset: int

    @property
    def is_dir(self) -> bool:
        return self.name.endswith("/")


@dataclass(frozen=True, slots=True)
class ZipDirectory:
    entries: list[ZipEntry]
    # Начало каталога: верхний предел данных последней записи.
    offset: int
    # Сколько байт и запросов ушло на чтение каталога.
    fetched: int
    requests: int


@dataclass(frozen=True, slots=True)
class SignedFile:
    """Запись подписанного списка: путь, размер, SHA-256."""

    path: str
    size: int
    sha256: str


@dataclass(slots=True)
class DeltaStats:
    full_size: int = 0
    downloaded: int = 0
    reused_files: int = 0
    fetched_files: int = 0
    requests: int = 0

    @property
    def saved(self) -> int:
        return max(0, self.full_size - self.downloaded)


# ── HTTP Range ──────────────────────────────────────────────────────────────

_CONTENT_RANGE_RE = re.compile(r"bytes (\d+)-(\d+)/(\d+|\*)")


class HttpRangeSource:
    """Диапазоны файла по HTTP: ответ обязан быть ``206`` ровно на запрошенное."""

    def __init__(
        self,
        url: str,
        opener: urllib.request.OpenerDirector,
        *,
        total: int,
        user_agent: str,
        timeout: float = 30.0,
    ) -> None:
        self._url = url
        self._opener = opener
        self._total = total
        self._user_agent = user_agent
        self._timeout = timeout

    def stream_range(self, start: int, end: int, sink: Callable[[bytes], None]) -> None:
        request = urllib.request.Request(
            self._url, headers={"User-Agent": self._user_agent, "Range": f"bytes={start}-{end}"}
        )
        with self._opener.open(request, timeout=self._timeout) as response:
            match = _CONTENT_RANGE_RE.fullmatch(response.headers.get("Content-Range", "").strip())
            if getattr(response, "status", None) != 206 or match is None:
                # 200 — сервер не умеет Range и сейчас пошлёт весь файл: не читаем.
                raise DeltaUnavailable("сервер не поддерживает частичную загрузку")
            got_start, got_end, got_total = match.groups()
            if int(got_start) != start or int(got_end) != end or (got_total != "*" and int(got_total) != self._total):
                raise DeltaUnavailable("сервер вернул не тот диапазон архива")
            received = 0
            while True:
                chunk = response.read(_CHUNK)
                if not chunk:
                    break
                received += len(chunk)
                if received > end - start + 1:
                    raise DeltaUnavailable("сервер вернул лишние байты диапазона")
                sink(chunk)
            if received != end - start + 1:
                raise OSError("сервер оборвал загрузку диапазона")

    def read_range(self, start: int, end: int) -> bytes:
        parts: list[bytes] = []
        self.stream_range(start, end, parts.append)
        return b"".join(parts)


# ── каталог zip ─────────────────────────────────────────────────────────────


def _find_eocd(tail: bytes) -> int:
    position = len(tail)
    while True:
        position = tail.rfind(_EOCD_SIG, 0, position)
        if position < 0:
            raise DeltaUnavailable("в конце архива нет записи EOCD")
        if len(tail) - position < _EOCD_SIZE:
            continue
        comment_len = struct.unpack_from("<H", tail, position + 20)[0]
        if position + _EOCD_SIZE + comment_len == len(tail):
            return position


def read_directory(source: RangeSource, total: int) -> ZipDirectory:
    """Каталог файлов удалённого zip (в том числе ZIP64): один-два запроса."""
    if total < _EOCD_SIZE:
        raise DeltaUnavailable("архив слишком мал")
    tail_start = max(0, total - TAIL_BYTES)
    tail = source.read_range(tail_start, total - 1)
    fetched = len(tail)
    requests = 1
    if len(tail) != total - tail_start:
        raise DeltaUnavailable("сервер вернул неполный конец архива")
    eocd_at = _find_eocd(tail)
    (_sig, disk, cd_disk, _n_disk, n_total, cd_size, cd_offset, _comment) = struct.unpack_from(
        "<4s4H2LH", tail, eocd_at
    )
    if disk not in (0, _U16) or cd_disk not in (0, _U16):
        raise DeltaUnavailable("многотомный архив")
    eocd_abs = tail_start + eocd_at
    loc_at = eocd_at - _EOCD64_LOC_SIZE
    needs64 = n_total == _U16 or _U32 in (cd_size, cd_offset)
    if loc_at >= 0 and tail[loc_at : loc_at + 4] == _EOCD64_LOC_SIG:
        needs64 = True
    if needs64:
        if loc_at < 0 or tail[loc_at : loc_at + 4] != _EOCD64_LOC_SIG:
            raise DeltaUnavailable("ZIP64 без указателя на расширенную запись")
        _s, loc_disk, eocd64_offset, disks = struct.unpack_from("<4sLQL", tail, loc_at)
        if loc_disk != 0 or disks > 1 or eocd64_offset + _EOCD64_SIZE > eocd_abs:
            raise DeltaUnavailable("ZIP64: неверный указатель")
        if eocd64_offset >= tail_start:
            record = tail[eocd64_offset - tail_start : eocd64_offset - tail_start + _EOCD64_SIZE]
        else:
            record = source.read_range(eocd64_offset, eocd64_offset + _EOCD64_SIZE - 1)
            fetched += len(record)
            requests += 1
        if len(record) != _EOCD64_SIZE or record[:4] != _EOCD64_SIG:
            raise DeltaUnavailable("ZIP64: нет расширенной записи конца архива")
        (_s, _rec, _vm, _vn, disk64, cd_disk64, _n_disk64, n_total, cd_size, cd_offset) = struct.unpack(
            "<4sQ2H2L4Q", record
        )
        if disk64 != 0 or cd_disk64 != 0:
            raise DeltaUnavailable("многотомный архив")
    if n_total > MAX_ENTRIES or cd_size > MAX_DIRECTORY_BYTES:
        raise DeltaUnavailable("каталог архива слишком велик")
    if cd_offset + cd_size > eocd_abs or cd_offset + cd_size > total:
        raise DeltaUnavailable("каталог архива выходит за его границы")
    if cd_offset >= tail_start:
        directory = tail[cd_offset - tail_start : cd_offset - tail_start + cd_size]
    else:
        head = source.read_range(cd_offset, tail_start - 1)
        fetched += len(head)
        requests += 1
        directory = head + tail[: cd_offset + cd_size - tail_start]
    if len(directory) != cd_size:
        raise DeltaUnavailable("каталог архива прочитан не полностью")
    return ZipDirectory(_parse_entries(directory, n_total), cd_offset, fetched, requests)


def _zip64_fields(extra: bytes, usize: int, csize: int, offset: int) -> tuple[int, int, int]:
    position = 0
    while position + 4 <= len(extra):
        header_id, length = struct.unpack_from("<HH", extra, position)
        body = extra[position + 4 : position + 4 + length]
        position += 4 + length
        if header_id != 1:
            continue
        cursor = 0

        def take() -> int:
            nonlocal cursor
            if cursor + 8 > len(body):
                raise DeltaUnavailable("ZIP64: усечено расширение записи")
            value = struct.unpack_from("<Q", body, cursor)[0]
            cursor += 8
            return value

        if usize == _U32:
            usize = take()
        if csize == _U32:
            csize = take()
        if offset == _U32:
            offset = take()
        return usize, csize, offset
    if _U32 in (usize, csize, offset):
        raise DeltaUnavailable("ZIP64: размеры не указаны")
    return usize, csize, offset


def _decode_name(raw: bytes, flags: int) -> str:
    try:
        return raw.decode("utf-8" if flags & 0x800 else "cp437")
    except UnicodeDecodeError:
        raise DeltaUnavailable("имя файла в архиве не читается") from None


def _unicode_path(extra: bytes, raw_name: bytes) -> str | None:
    """Имя из расширения Info-ZIP Unicode Path (0x7075), как пишет 7-Zip."""
    position = 0
    while position + 4 <= len(extra):
        header_id, length = struct.unpack_from("<HH", extra, position)
        body = extra[position + 4 : position + 4 + length]
        position += 4 + length
        if header_id == 0x7075 and len(body) > 5 and body[0] == 1:
            if struct.unpack_from("<L", body, 1)[0] != (zlib.crc32(raw_name) & _U32):
                return None
            try:
                return body[5:].decode("utf-8")
            except UnicodeDecodeError:
                return None
    return None


def _parse_entries(directory: bytes, count: int) -> list[ZipEntry]:
    entries: list[ZipEntry] = []
    position = 0
    while position < len(directory):
        if position + _CD_FIXED > len(directory) or directory[position : position + 4] != _CD_SIG:
            raise DeltaUnavailable("каталог архива повреждён")
        (_sig, _vm, _vn, flags, method, _t, _d, crc, csize, usize, nlen, elen, clen, _disk, _ia, _ea, offset) = (
            struct.unpack_from("<4s6H3L5H2L", directory, position)
        )
        end = position + _CD_FIXED + nlen + elen + clen
        if end > len(directory):
            raise DeltaUnavailable("каталог архива усечён")
        raw_name = directory[position + _CD_FIXED : position + _CD_FIXED + nlen]
        extra = directory[position + _CD_FIXED + nlen : position + _CD_FIXED + nlen + elen]
        usize, csize, offset = _zip64_fields(extra, usize, csize, offset)
        name = _unicode_path(extra, bytes(raw_name)) or _decode_name(raw_name, flags)
        entries.append(
            ZipEntry(name, bytes(raw_name), flags, method, crc, csize, usize, offset)
        )
        position = end
    if len(entries) != count:
        raise DeltaUnavailable("число записей каталога не сходится с заявленным")
    return entries


# ── план ────────────────────────────────────────────────────────────────────


@dataclass(slots=True)
class DeltaPlan:
    reuse: dict[str, Path]
    fetch: list[ZipEntry]
    spans: dict[str, tuple[int, int]]  # имя -> [начало, конец) записи в архиве
    ranges: list[tuple[int, int]]  # объединённые куски [начало, конец)
    directories: list[str]

    @property
    def range_bytes(self) -> int:
        return sum(end - start for start, end in self.ranges)


def _sha256_path(path: Path) -> str | None:
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            while chunk := handle.read(_CHUNK):
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


def _local_candidate(local_root: Path | None, relative: str, size: int) -> Path | None:
    if local_root is None:
        return None
    path = local_root.joinpath(*relative.split("/"))
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size != size:
            return None
    except OSError:
        return None
    return path


def _merge_ranges(spans: list[tuple[int, int]], gap_limit: int, max_ranges: int) -> list[tuple[int, int]]:
    merged: list[list[int]] = []
    for start, end in sorted(spans):
        if merged and start - merged[-1][1] <= gap_limit:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    while len(merged) > max_ranges:
        gaps = [merged[i + 1][0] - merged[i][1] for i in range(len(merged) - 1)]
        i = gaps.index(min(gaps))
        merged[i][1] = merged[i + 1][1]
        del merged[i + 1]
    return [(start, end) for start, end in merged]


def build_plan(
    entries: Sequence[ZipEntry],
    signed: Sequence[SignedFile],
    *,
    local_root: Path | None,
    directory_offset: int,
    merge_gap: int = MERGE_GAP_BYTES,
    max_ranges: int = MAX_RANGES,
) -> DeltaPlan:
    files = [entry for entry in entries if not entry.is_dir]
    names = [entry.name for entry in files]
    if len(set(names)) != len(names):
        raise DeltaUnavailable("в архиве повторяются имена файлов")
    signed_by_path = {item.path: item for item in signed}
    if set(names) != set(signed_by_path):
        raise DeltaUnavailable("состав архива не совпадает с подписанным списком выпуска")
    ordered = sorted(entries, key=lambda item: item.offset)
    span_end: dict[str, int] = {}
    for index, entry in enumerate(ordered):
        following = ordered[index + 1].offset if index + 1 < len(ordered) else directory_offset
        if following < entry.offset + _LOCAL_FIXED + len(entry.raw_name):
            raise DeltaUnavailable("записи архива пересекаются")
        span_end[entry.name] = following
    reuse: dict[str, Path] = {}
    fetch: list[ZipEntry] = []
    for entry in files:
        want = signed_by_path[entry.name]
        if entry.flags & 0x1 or entry.method not in (_METHOD_STORED, _METHOD_DEFLATE):
            raise DeltaUnavailable(f"способ упаковки {entry.name} не поддержан")
        if entry.size != want.size:
            raise DeltaUnavailable(f"размер {entry.name} в архиве не совпадает с подписанным")
        if entry.offset + _LOCAL_FIXED + len(entry.raw_name) + entry.compressed_size > span_end[entry.name]:
            raise DeltaUnavailable(f"данные {entry.name} выходят за свою запись")
        local = _local_candidate(local_root, entry.name, want.size)
        if local is not None and _sha256_path(local) == want.sha256:
            reuse[entry.name] = local
        else:
            fetch.append(entry)
    spans = {entry.name: (entry.offset, span_end[entry.name]) for entry in fetch}
    ranges = _merge_ranges(list(spans.values()), merge_gap, max_ranges)
    directories = [entry.name.rstrip("/") for entry in entries if entry.is_dir]
    return DeltaPlan(reuse, fetch, spans, ranges, directories)


# ── загрузка и сборка ───────────────────────────────────────────────────────


def _pieces(start: int, end: int) -> list[tuple[int, int]]:
    length = end - start
    count = max(1, min(MAX_PIECES_PER_RANGE, length // PIECE_BYTES))
    step = -(-length // count)
    return [(a, min(end, a + step)) for a in range(start, end, step)]


def _download_ranges(
    source: RangeSource,
    plan: DeltaPlan,
    work_dir: Path,
    report: Callable[[int], None],
) -> tuple[list[tuple[int, int, Path]], int]:
    work_dir.mkdir(parents=True, exist_ok=True)
    files: list[tuple[int, int, Path]] = []
    jobs: list[tuple[Path, int, int, int]] = []
    for index, (start, end) in enumerate(plan.ranges):
        path = work_dir / f"range_{index}"
        with open(path, "wb") as handle:
            handle.truncate(end - start)
        files.append((start, end, path))
        for piece_start, piece_end in _pieces(start, end):
            jobs.append((path, start, piece_start, piece_end))
    lock = threading.Lock()
    done = 0

    def fetch(job: tuple[Path, int, int, int]) -> None:
        nonlocal done
        path, base, piece_start, piece_end = job
        with open(path, "r+b") as handle:
            handle.seek(piece_start - base)
            written = 0

            def sink(chunk: bytes) -> None:
                nonlocal written, done
                handle.write(chunk)
                written += len(chunk)
                with lock:
                    done += len(chunk)
                    report(done)

            source.stream_range(piece_start, piece_end - 1, sink)
            if written != piece_end - piece_start:
                raise OSError("сервер вернул неполный кусок архива")

    with ThreadPoolExecutor(max_workers=min(PARALLEL_REQUESTS, len(jobs)) or 1) as pool:
        for future in [pool.submit(fetch, job) for job in jobs]:
            future.result()
    files.sort()
    return files, len(jobs)


def _safe_target(root: Path, relative: str) -> Path:
    target = root.joinpath(*relative.split("/"))
    resolved_root = os.path.abspath(root)
    if os.path.commonpath([resolved_root, os.path.abspath(target)]) != resolved_root:
        raise DeltaUnavailable(f"путь выходит за каталог распаковки: {relative}")
    return target


def _extract_entry(
    entry: ZipEntry,
    want: SignedFile,
    ranges: list[tuple[int, int, Path]],
    span: tuple[int, int],
    target: Path,
) -> None:
    holder = next((item for item in ranges if item[0] <= span[0] and span[1] <= item[1]), None)
    if holder is None:
        raise DeltaUnavailable(f"кусок архива для {entry.name} не скачан")
    base, _end, path = holder
    sha = hashlib.sha256()
    crc = 0
    written = 0
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "rb") as source, open(target, "wb") as out:
        source.seek(entry.offset - base)
        header = source.read(_LOCAL_FIXED)
        if len(header) != _LOCAL_FIXED or header[:4] != _LOCAL_SIG:
            raise DeltaUnavailable(f"у {entry.name} нет локального заголовка")
        (_s, _v, _f, method, _t, _d, _c, _cs, _us, nlen, elen) = struct.unpack("<4s5H3L2H", header)
        if method != entry.method or source.read(nlen) != entry.raw_name:
            raise DeltaUnavailable(f"локальный заголовок {entry.name} не совпадает с каталогом")
        source.seek(elen, os.SEEK_CUR)
        if source.tell() - (entry.offset - base) + entry.compressed_size > span[1] - span[0]:
            raise DeltaUnavailable(f"данные {entry.name} выходят за свою запись")
        remaining = entry.compressed_size
        inflater = zlib.decompressobj(-15) if method == _METHOD_DEFLATE else None

        def emit(block: bytes) -> None:
            nonlocal crc, written
            if not block:
                return
            written += len(block)
            if written > want.size:
                raise DeltaUnavailable(f"{entry.name} больше подписанного размера")
            crc = zlib.crc32(block, crc)
            sha.update(block)
            out.write(block)

        while remaining:
            chunk = source.read(min(_CHUNK, remaining))
            if not chunk:
                raise DeltaUnavailable(f"данные {entry.name} оборваны")
            remaining -= len(chunk)
            if inflater is None:
                emit(chunk)
                continue
            data = chunk
            while data:
                try:
                    emit(inflater.decompress(data, min(_CHUNK, want.size - written + 1)))
                except zlib.error:
                    raise DeltaUnavailable(f"{entry.name}: повреждённый сжатый поток") from None
                data = inflater.unconsumed_tail
        if inflater is not None:
            try:
                emit(inflater.flush())
            except zlib.error:
                raise DeltaUnavailable(f"{entry.name}: повреждённый сжатый поток") from None
            if not inflater.eof:
                raise DeltaUnavailable(f"поток {entry.name} не завершён")
    if written != want.size or (crc & _U32) != entry.crc32 or sha.hexdigest() != want.sha256:
        raise DeltaUnavailable(f"{entry.name}: проверка размера или хеша не прошла")


def _copy_reused(source: Path, target: Path, want: SignedFile) -> None:
    sha = hashlib.sha256()
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(source, "rb") as src, open(target, "wb") as out:
        while chunk := src.read(_CHUNK):
            sha.update(chunk)
            out.write(chunk)
    if sha.hexdigest() != want.sha256:
        raise DeltaUnavailable(f"установленный файл {want.path} изменился во время копирования")


def prepare_delta(
    *,
    source: RangeSource,
    total_size: int,
    signed: Sequence[SignedFile],
    local_root: Path | None,
    destination: Path,
    work_dir: Path,
    progress: Callable[[int, int], None] | None = None,
    announce: Callable[[int, int], None] | None = None,
    max_ratio: float = MAX_DELTA_RATIO,
) -> DeltaStats:
    """Собрать в ``destination`` сборку из установленных и докачанных файлов.

    ``announce(к_загрузке, полный_размер)`` вызывается, когда решено качать
    частично; ``progress(скачано, к_загрузке)`` — по ходу загрузки.
    Любая негодность — ``DeltaUnavailable``; сетевой сбой — ``OSError``.
    """
    if not signed:
        raise DeltaUnavailable("в подписанном списке выпуска нет списка файлов")
    stats = DeltaStats(full_size=total_size)
    directory = read_directory(source, total_size)
    stats.requests = directory.requests
    plan = build_plan(directory.entries, signed, local_root=local_root, directory_offset=directory.offset)
    wanted = plan.range_bytes
    # Хвост архива с каталогом уже скачан.
    stats.downloaded = directory.fetched
    if wanted + directory.fetched > total_size * max_ratio:
        raise DeltaUnavailable(f"выигрыш мал: нужно {wanted + directory.fetched} из {total_size} байт")
    if announce is not None:
        announce(wanted + directory.fetched, total_size)
    by_path = {item.path: item for item in signed}
    destination.mkdir(parents=True, exist_ok=True)
    try:
        ranges, requests = _download_ranges(
            source,
            plan,
            work_dir,
            (lambda done: progress(done, wanted)) if progress is not None else (lambda _done: None),
        )
        stats.requests += requests
        stats.downloaded += wanted
        for name in plan.directories:
            _safe_target(destination, name).mkdir(parents=True, exist_ok=True)
        for entry in plan.fetch:
            _extract_entry(entry, by_path[entry.name], ranges, plan.spans[entry.name], _safe_target(destination, entry.name))
        for name, local in plan.reuse.items():
            _copy_reused(local, _safe_target(destination, name), by_path[name])
    finally:
        _remove_tree(work_dir)
    stats.fetched_files = len(plan.fetch)
    stats.reused_files = len(plan.reuse)
    return stats


def _remove_tree(path: Path) -> None:
    shutil.rmtree(path, ignore_errors=True)
