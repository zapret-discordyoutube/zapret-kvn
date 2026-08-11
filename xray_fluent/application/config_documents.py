from __future__ import annotations

from pathlib import Path

from ..engines.singbox import SingboxDocumentState, inspect_singbox_document_text


class RawConfigTextCache:
    """(mtime_ns, size)-keyed text cache, generalising the SingboxDocumentCache
    pattern for raw config files that are re-read several times per transition."""

    def __init__(self) -> None:
        self._entries: dict[str, tuple[int, int, str]] = {}

    def clear(self) -> None:
        self._entries.clear()

    def read_text(self, path: Path) -> str:
        key = str(path)
        try:
            stat = path.stat()
        except OSError:
            self._entries.pop(key, None)
            return path.read_text(encoding="utf-8")
        mtime_ns = int(getattr(stat, "st_mtime_ns", 0))
        size = int(getattr(stat, "st_size", 0))
        entry = self._entries.get(key)
        if entry is not None and entry[0] == mtime_ns and entry[1] == size:
            return entry[2]
        text = path.read_text(encoding="utf-8")
        self._entries[key] = (mtime_ns, size, text)
        return text

    def store(self, path: Path, text: str) -> None:
        """Seed the cache right after writing ``text`` to ``path``.

        Filesystem mtime granularity can be coarser than a write cycle, so the
        writer must refresh the cache itself instead of relying on stat()."""
        key = str(path)
        try:
            stat = path.stat()
        except OSError:
            self._entries.pop(key, None)
            return
        self._entries[key] = (
            int(getattr(stat, "st_mtime_ns", 0)),
            int(getattr(stat, "st_size", 0)),
            text,
        )


class SingboxDocumentCache:
    def __init__(self) -> None:
        self._state: SingboxDocumentState | None = None

    def clear(self) -> None:
        self._state = None

    def cache_state(self, path: Path, text: str) -> SingboxDocumentState:
        state = inspect_singbox_document_text(path, text)
        try:
            stat = path.stat()
        except OSError:
            stat = None
        if stat is not None:
            state.file_mtime_ns = int(getattr(stat, "st_mtime_ns", 0))
            state.file_size = int(getattr(stat, "st_size", 0))
        self._state = state
        return state

    def get_state(self, path: Path) -> SingboxDocumentState:
        if self._state is not None and self._state.source_path == path:
            try:
                stat = path.stat()
            except OSError:
                stat = None
            if stat is not None:
                current_mtime_ns = int(getattr(stat, "st_mtime_ns", 0))
                current_size = int(getattr(stat, "st_size", 0))
                if self._state.file_mtime_ns == current_mtime_ns and self._state.file_size == current_size:
                    return self._state
        text = path.read_text(encoding="utf-8")
        return self.cache_state(path, text)
