from __future__ import annotations

from urllib.parse import urlsplit

from PyQt6.QtGui import QImage


class QrDecodeError(ValueError):
    pass


def decode_subscription_qr(image: QImage) -> str:
    if image.isNull():
        raise QrDecodeError("Изображение пустое")
    try:
        import zxingcpp
    except ImportError as exc:
        raise QrDecodeError("Модуль zxing-cpp не установлен") from exc
    result = zxingcpp.read_barcode(
        image,
        formats=zxingcpp.BarcodeFormat.QRCode,
        try_rotate=True,
        try_invert=True,
    )
    if result is None or not str(result.text or "").strip():
        raise QrDecodeError("QR-код не найден")
    text = str(result.text).strip()
    parsed = urlsplit(text)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise QrDecodeError("QR-код не содержит HTTP/HTTPS URL подписки")
    return text
