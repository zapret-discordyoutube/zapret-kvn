"""«Свои значения» маскировки: все числа общего набора в формате, общем с Android.

Только показывает и проверяет: разбор и проверка — в пакете ``xray_fluent.masking``.
Набор с ошибкой не сохраняется: ядро не получает то, что оно отвергло бы.
"""

from __future__ import annotations

import json

from qfluentwidgets import CaptionLabel, MessageBoxBase, PlainTextEdit, SubtitleLabel

from ..masking import codec, singbox, wireguard, xray
from ..masking.model import Masking, errors


def masking_problems(masking: Masking) -> list[str]:
    problems = []
    if masking.wireguard is not None:
        problems += wireguard.validate(masking.wireguard)
    if masking.xray is not None:
        problems += xray.validate(masking.xray)
    if masking.singbox is not None:
        problems += singbox.validate(masking.singbox)
    return [problem.message for problem in errors(problems)]


def parse_custom(text: str) -> tuple[Masking | None, list[str]]:
    try:
        root = json.loads(text)
    except ValueError as exc:
        return None, [f"Это не JSON: {exc.msg} (строка {exc.lineno})."]
    if not isinstance(root, dict):
        return None, ["Нужен JSON-объект с разделами wireguard, xray, singbox."]
    unknown = sorted(set(root) - {"wireguard", "xray", "singbox"})
    if unknown:
        return None, [f"Неизвестные разделы: {', '.join(unknown)}."]
    masking = codec.decode_masking(root)
    problems = masking_problems(masking)
    return (None, problems) if problems else (masking, [])


class MaskingCustomDialog(MessageBoxBase):
    def __init__(self, masking: Masking, parent=None):
        super().__init__(parent)
        self.result_masking: Masking | None = None
        self.viewLayout.addWidget(SubtitleLabel("Свои значения маскировки", self))
        hint = CaptionLabel(
            "Все числа общего набора. Формат тот же, что в приложении для Android: набор можно перенести. "
            "Диапазоны пишутся строкой, например \"8-16\".",
            self,
        )
        hint.setWordWrap(True)
        self.viewLayout.addWidget(hint)
        self.editor = PlainTextEdit(self)
        self.editor.setPlainText(json.dumps(codec.encode_masking(masking), ensure_ascii=False, indent=2))
        self.editor.setMinimumSize(560, 360)
        self.viewLayout.addWidget(self.editor)
        self.error_label = CaptionLabel("", self)
        self.error_label.setWordWrap(True)
        self.viewLayout.addWidget(self.error_label)
        self.yesButton.setText("Сохранить")
        self.cancelButton.setText("Отмена")

    def validate(self) -> bool:
        masking, problems = parse_custom(self.editor.toPlainText())
        if problems:
            self.error_label.setText("\n".join(problems))
            return False
        self.result_masking = masking
        return True
