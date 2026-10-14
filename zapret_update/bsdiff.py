"""Заплатки bsdiff: применение на чистом Python.

Заплатка zstd (``store.make_patch``) хороша, когда новый файл повторяет
прежний кусками. У ``Zapret.exe`` не так: между версиями сдвигаются адреса
внутри всего файла, и одинаковых кусков почти нет — замер 21.1.7.155 → 156:
файл целиком 19,99 МБ, заплатка zstd 13,84 МБ, заплатка bsdiff 2,36 МБ.
bsdiff записывает разницу байтов «новый минус прежний» на совпавших местах —
она почти вся из нулей и сжимается в разы.

Формат — обычный ``BSDIFF40`` (как у ``bsdiff`` и ``bsdiff4``): заголовок,
три блока bz2 — управление, разница, добавка. Делает заплатки машина сборки
(``bsdiff4``), программа только применяет: здесь, стандартной библиотекой.
Блоки распаковываются по ходу, поэтому памяти нужно на прежний и новый файл,
а не ещё на полную разницу. Сложение байтов идёт сразу по большому куску
(целые Python произвольной длины), без цикла по байтам.
"""

from __future__ import annotations

import bz2

MAGIC = b"BSDIFF40"
HEADER_SIZE = 32
# Сложение идёт кусками не больше этого: так временные целые не раздувают память.
STEP = 1024 * 1024


class BsdiffError(ValueError):
    """Заплатка bsdiff повреждена или не подходит к файлу."""


def _offtin(buf: bytes) -> int:
    value = int.from_bytes(buf[:8], "little")
    if value & (1 << 63):
        value = -(value & ((1 << 63) - 1))
    return value


class _Stream:
    """Блок bz2, который читается по частям."""

    def __init__(self, data: bytes) -> None:
        self._decompressor = bz2.BZ2Decompressor()
        self._pending = bytes(data)

    def read(self, size: int) -> bytes:
        out = bytearray()
        while len(out) < size:
            try:
                chunk = self._decompressor.decompress(self._pending, max_length=size - len(out))
            except (OSError, EOFError, ValueError) as exc:
                raise BsdiffError(f"блок заплатки не распаковался: {exc}") from None
            self._pending = b""
            if not chunk and (self._decompressor.eof or self._decompressor.needs_input):
                raise BsdiffError("блок заплатки кончился раньше времени")
            out += chunk
        return bytes(out)


def _add_bytes(base: bytes, delta: bytes) -> bytes:
    """Побайтное сложение по модулю 256 сразу для всего куска.

    Старшие биты байтов складываются отдельно через XOR, поэтому перенос из
    одного байта в соседний не возникает (0x7f + 0x7f < 0x100).
    """
    size = len(delta)
    d = int.from_bytes(delta, "little")
    if not d:
        return base
    a = int.from_bytes(base, "little")
    low = int.from_bytes(b"\x7f" * size, "little")
    high = int.from_bytes(b"\x80" * size, "little")
    return (((a & low) + (d & low)) ^ ((a ^ d) & high)).to_bytes(size, "little")


def _old_slice(old: bytes, position: int, size: int) -> bytes:
    """Кусок прежнего файла; за его границами — нули (как в ``bspatch``)."""
    if position >= 0 and position + size <= len(old):
        return old[position:position + size]
    out = bytearray(size)
    start, stop = max(position, 0), min(position + size, len(old))
    if start < stop:
        out[start - position:stop - position] = old[start:stop]
    return bytes(out)


def new_size(patch: bytes) -> int:
    """Размер нового файла по заголовку заплатки."""
    if len(patch) < HEADER_SIZE or patch[:8] != MAGIC:
        raise BsdiffError("это не заплатка bsdiff")
    return _offtin(patch[24:32])


def apply(old: bytes, patch: bytes, *, expected_size: int | None = None) -> bytearray:
    """Новый файл из прежнего и заплатки ``BSDIFF40`` (без лишней копии — ``bytearray``)."""
    size = new_size(patch)
    control_size, diff_size = _offtin(patch[8:16]), _offtin(patch[16:24])
    if control_size < 0 or diff_size < 0 or size < 0 or HEADER_SIZE + control_size + diff_size > len(patch):
        raise BsdiffError("заголовок заплатки bsdiff повреждён")
    if expected_size is not None and size != expected_size:
        # Проверка до выделения памяти: чужая заплатка не заставит занять гигабайты.
        raise BsdiffError("заплатка bsdiff ведёт к файлу другого размера")
    try:
        control = bz2.decompress(patch[HEADER_SIZE:HEADER_SIZE + control_size])
    except (OSError, EOFError, ValueError) as exc:
        raise BsdiffError(f"блок управления не распаковался: {exc}") from None
    if len(control) % 24:
        raise BsdiffError("блок управления заплатки bsdiff повреждён")
    diff = _Stream(patch[HEADER_SIZE + control_size:HEADER_SIZE + control_size + diff_size])
    extra = _Stream(patch[HEADER_SIZE + control_size + diff_size:])

    out = bytearray(size)
    new_pos = old_pos = 0
    for index in range(0, len(control), 24):
        copy, insert, seek = (_offtin(control[index + shift:index + shift + 8]) for shift in (0, 8, 16))
        if copy < 0 or insert < 0 or new_pos + copy + insert > size:
            raise BsdiffError("заплатка bsdiff выходит за размер нового файла")
        for done in range(0, copy, STEP):
            part = min(STEP, copy - done)
            out[new_pos:new_pos + part] = _add_bytes(_old_slice(old, old_pos, part), diff.read(part))
            new_pos += part
            old_pos += part
        out[new_pos:new_pos + insert] = extra.read(insert)
        new_pos += insert
        old_pos += seek
    if new_pos != size:
        raise BsdiffError("заплатка bsdiff собрала файл не целиком")
    return out


__all__ = ["BsdiffError", "MAGIC", "apply", "new_size"]
