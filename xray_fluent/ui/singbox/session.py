"""One editing session of the active sing-box config for all routing sub-pages.

Direction of truth: the session keeps the editor text. Structured pages edit
the parsed document in place and call :meth:`SingboxSession.mark_edited`; the
text is regenerated from the document only when it is actually needed. The raw
JSON page sets text directly; it is parsed when the user leaves that page. If
the text is not valid JSON, structured pages become read-only instead of ever
serialising a stale document over the user's raw edits.
"""

from __future__ import annotations

import json
from pathlib import Path

from PyQt6.QtCore import QObject, pyqtSignal

from ...singbox_config.document import dump_document, parse_document


class SingboxSession(QObject):
    #: A new document was loaded or the raw text was re-parsed; pages rebuild.
    document_replaced = pyqtSignal()
    #: Dirty flag or validity changed; toolbars refresh.
    state_changed = pyqtSignal()

    def __init__(self, parent: QObject | None = None):
        super().__init__(parent)
        self.path: Path | None = None
        self.template_path: Path | None = None
        self.stock: dict | None = None
        self.document: dict | None = None
        self.parse_error = ""
        self._saved_text = ""
        self._text = ""
        self._text_stale = False

    # -- loading ------------------------------------------------------------

    def load(self, path: Path, text: str) -> None:
        unchanged = (
            path == self.path
            and text == self._saved_text
            and not self._text_stale
            and text == self._text
        )
        self.path = path
        self._saved_text = text
        if unchanged:
            # Same file, same text: keep the built pages (no widget churn).
            self.state_changed.emit()
            return
        self._set_text(text)

    def set_template(self, path: Path | None) -> None:
        self.template_path = path
        self.stock = None
        if path is not None:
            try:
                stock = json.loads(path.read_text(encoding="utf-8-sig"))
            except (OSError, UnicodeError, json.JSONDecodeError):
                stock = None
            self.stock = stock if isinstance(stock, dict) else None
        self.state_changed.emit()

    def replace_text(self, text: str) -> None:
        """Replace the whole document with new text (repair, raw edit)."""

        self._set_text(text)

    def _set_text(self, text: str) -> None:
        self._text = text
        self._text_stale = False
        document, error = parse_document(text)
        self.document = document
        self.parse_error = error
        self.document_replaced.emit()
        self.state_changed.emit()

    # -- editing ------------------------------------------------------------

    @property
    def editable(self) -> bool:
        return self.document is not None

    def mark_edited(self) -> None:
        if self.document is None:
            return
        self._text_stale = True
        self.state_changed.emit()

    def text(self) -> str:
        if self._text_stale and self.document is not None:
            self._text = dump_document(self.document)
            self._text_stale = False
        return self._text

    def is_dirty(self) -> bool:
        if self._text_stale:
            # Structured edits that ended up back at the loaded state are clean.
            saved, _error = parse_document(self._saved_text)
            return saved != self.document
        return self._text != self._saved_text

    def mark_saved(self, path: Path | None = None, text: str | None = None) -> None:
        if path is not None:
            self.path = path
        self._saved_text = self.text() if text is None else text
        if text is not None and text != self.text():
            self._set_text(text)
            return
        self.state_changed.emit()

    def revert(self) -> None:
        self._set_text(self._saved_text)

    # -- stock --------------------------------------------------------------

    def reset_section(self, key: str) -> bool:
        """Replace one top-level section with the stock template's version."""

        if self.document is None or self.stock is None:
            return False
        if key in self.stock:
            self.document[key] = json.loads(json.dumps(self.stock[key]))
        else:
            self.document.pop(key, None)
        self.mark_edited()
        self.document_replaced.emit()
        return True
