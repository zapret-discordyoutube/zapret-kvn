"""«Подобрать»: ход подбора и таблица вариантов с кнопкой «Оставить».

Только показывает состояние ``MaskingTuneRunner`` и передаёт нажатия; порядок, паузы и вердикты
решает ``xray_fluent.masking.tester``.
"""

from __future__ import annotations

from PyQt6.QtWidgets import QHBoxLayout, QVBoxLayout, QWidget
from qfluentwidgets import BodyLabel, CaptionLabel, MessageBoxBase, PushButton, SubtitleLabel

from ..application.masking_tune_service import MaskingTuneRunner, TuneDone, TuneFailed, TuneIdle, TuneRunning

_VERDICT_COLORS = {"pass": "#2e9e5b", "frozen": "#d13438"}


def status_text(state: object) -> str:
    if isinstance(state, TuneRunning):
        return (
            f"{state.server_name}: вариант {state.candidate} из {state.candidates} — «{state.title}». "
            "VPN переподключается для каждого варианта, подбор занимает 1-3 минуты."
        )
    if isinstance(state, TuneDone):
        return f"{state.server_name}: лучшие сверху. «Оставить» сохраняет вариант как выбор этого сервера."
    if isinstance(state, TuneFailed):
        return state.message
    return (
        "Запросы идут по одному, с паузами, к одному адресу. Сохранённые настройки не меняются, "
        "пока вы не нажмёте «Оставить»."
    )


class MaskingTuneDialog(MessageBoxBase):
    def __init__(self, runner: MaskingTuneRunner, parent=None):
        super().__init__(parent)
        self._runner = runner
        self.viewLayout.addWidget(SubtitleLabel("Подбор маскировки", self))
        self.status_label = BodyLabel("", self)
        self.status_label.setWordWrap(True)
        self.viewLayout.addWidget(self.status_label)
        self._rows_holder = QWidget(self)
        self._rows = QVBoxLayout(self._rows_holder)
        self._rows.setContentsMargins(0, 0, 0, 0)
        self.viewLayout.addWidget(self._rows_holder)
        self.widget.setMinimumWidth(600)
        self.cancelButton.hide()
        runner.state_changed.connect(self._render)
        self.destroyed.connect(lambda *_: self._disconnect(runner))
        self._render(runner.state)

    def _disconnect(self, runner: MaskingTuneRunner) -> None:
        try:
            runner.state_changed.disconnect(self._render)
        except (TypeError, RuntimeError):
            pass

    def validate(self) -> bool:
        # The one button reads «Остановить» while a run is going: closing stops it and restores the session.
        if self._runner.running:
            self._runner.cancel()
        return True

    def _render(self, state: object) -> None:
        self.status_label.setText(status_text(state))
        self.yesButton.setText("Остановить" if isinstance(state, TuneRunning) else "Закрыть")
        while self._rows.count():
            item = self._rows.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
        if not isinstance(state, TuneDone):
            return
        for ranked in state.ranked:
            self._rows.addWidget(self._row(ranked, kept=ranked.candidate.id == state.kept))

    def _row(self, ranked, *, kept: bool) -> QWidget:
        row = QWidget(self._rows_holder)
        layout = QHBoxLayout(row)
        layout.setContentsMargins(0, 4, 0, 4)
        text = QVBoxLayout()
        text.addWidget(BodyLabel(ranked.candidate.title, row))
        reason = CaptionLabel(ranked.reason, row)
        color = _VERDICT_COLORS.get(ranked.verdict.kind)
        if color:
            reason.setTextColor(color, color)
        text.addWidget(reason)
        layout.addLayout(text, 1)
        button = PushButton("Оставлен" if kept else "Оставить", row)
        button.setEnabled(not kept)
        button.setObjectName(f"masking-tune-keep-{ranked.candidate.id}")
        button.clicked.connect(lambda *_, candidate=ranked.candidate: self._runner.keep(candidate))
        layout.addWidget(button)
        return row


__all__ = ["MaskingTuneDialog", "status_text", "TuneIdle"]
