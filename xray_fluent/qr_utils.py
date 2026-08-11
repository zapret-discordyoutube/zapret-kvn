from __future__ import annotations

from PyQt6.QtGui import QImage

from .subscription_http import SubscriptionFetchError, resolve_subscription_source


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
    try:
        resolve_subscription_source(text)
    except SubscriptionFetchError as exc:
        raise QrDecodeError(
            "QR-код не содержит URL подписки или открытую add/import-ссылку"
        ) from exc
    return text
