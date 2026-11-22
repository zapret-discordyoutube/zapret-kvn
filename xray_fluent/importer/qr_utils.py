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
    # zxing-cpp 3 reads only buffers (QImage has no buffer protocol: every QR import crashed with TypeError until
    # 0.8.105, app errors crash:TypeError from 0.8.103). An 8-bit grey copy is passed as raw bytes with its stride.
    # ImageView does not keep its buffer alive: ``pixels`` must outlive read_barcode (a temporary was freed first).
    gray = image.convertToFormat(QImage.Format.Format_Grayscale8)
    pixels = bytes(gray.constBits().asstring(gray.sizeInBytes()))
    view = zxingcpp.ImageView(
        pixels,
        gray.width(),
        gray.height(),
        zxingcpp.ImageFormat.Lum,
        gray.bytesPerLine(),
    )
    result = zxingcpp.read_barcode(
        view,
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
