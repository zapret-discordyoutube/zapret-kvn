"""Ed25519 на чистом Python: проверка подписи в программах и подпись на машине сборки.

Сторонних библиотек нет ни у программ, ни у сборки. Подпись здесь не
защищена от утечки по времени — она делается только на своей машине сборки,
где измерять её некому; проверка открытых данных такой защиты не требует.
"""

from __future__ import annotations

import hashlib


_P = 2**255 - 19
_Q = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)
_IDENTITY = (0, 1)


def verify_ed25519_signature(public_key: bytes, signature: bytes, message: bytes) -> bool:
    try:
        public_key = bytes(public_key)
        signature = bytes(signature)
        message = bytes(message)
        if len(public_key) != 32 or len(signature) != 64:
            return False

        r_encoded = signature[:32]
        s = int.from_bytes(signature[32:], "little")
        if s >= _Q:
            return False

        public_point = _decode_point(public_key)
        r_point = _decode_point(r_encoded)
        h = int.from_bytes(hashlib.sha512(r_encoded + public_key + message).digest(), "little") % _Q

        left = _scalarmult(_BASE_POINT, s)
        right = _edwards_add(r_point, _scalarmult(public_point, h))
        return _encode_point(left) == _encode_point(right)
    except Exception:
        return False


def _clamped_scalar(seed: bytes) -> tuple[int, bytes]:
    digest = hashlib.sha512(bytes(seed)).digest()
    scalar = int.from_bytes(digest[:32], "little")
    scalar &= (1 << 254) - 8
    scalar |= 1 << 254
    return scalar, digest[32:]


def public_key_from_seed(seed: bytes) -> bytes:
    """Открытый ключ (32 байта) по закрытому (32 байта)."""
    if len(seed) != 32:
        raise ValueError("закрытый ключ Ed25519 — 32 байта")
    scalar, _prefix = _clamped_scalar(seed)
    return _encode_point(_scalarmult(_BASE_POINT, scalar))


def sign_ed25519(seed: bytes, message: bytes) -> bytes:
    """Подпись Ed25519 (RFC 8032), 64 байта."""
    if len(seed) != 32:
        raise ValueError("закрытый ключ Ed25519 — 32 байта")
    message = bytes(message)
    scalar, prefix = _clamped_scalar(seed)
    public_key = _encode_point(_scalarmult(_BASE_POINT, scalar))
    r = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % _Q
    r_encoded = _encode_point(_scalarmult(_BASE_POINT, r))
    h = int.from_bytes(hashlib.sha512(r_encoded + public_key + message).digest(), "little") % _Q
    return r_encoded + ((r + h * scalar) % _Q).to_bytes(32, "little")


def _inv(x: int) -> int:
    return pow(x, _P - 2, _P)


def _recover_x(y: int) -> int:
    xx = ((y * y - 1) * _inv(_D * y * y + 1)) % _P
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = (x * _I) % _P
    if x & 1:
        x = _P - x
    return x


def _is_on_curve(point: tuple[int, int]) -> bool:
    x, y = point
    return (-x * x + y * y - 1 - _D * x * x * y * y) % _P == 0


def _decode_point(encoded: bytes) -> tuple[int, int]:
    y = int.from_bytes(encoded, "little") & ((1 << 255) - 1)
    sign = encoded[31] >> 7
    if y >= _P:
        raise ValueError("bad Ed25519 point")
    x = _recover_x(y)
    if (x & 1) != sign:
        x = _P - x
    point = (x, y)
    if not _is_on_curve(point):
        raise ValueError("bad Ed25519 point")
    return point


def _encode_point(point: tuple[int, int]) -> bytes:
    x, y = point
    encoded = bytearray((y % _P).to_bytes(32, "little"))
    encoded[31] |= (x & 1) << 7
    return bytes(encoded)


def _edwards_add(left: tuple[int, int], right: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = left
    x2, y2 = right
    xyxy = x1 * x2 * y1 * y2
    x3 = ((x1 * y2 + x2 * y1) * _inv(1 + _D * xyxy)) % _P
    y3 = ((y1 * y2 + x1 * x2) * _inv(1 - _D * xyxy)) % _P
    return x3, y3


def _scalarmult(point: tuple[int, int], scalar: int) -> tuple[int, int]:
    result = _IDENTITY
    addend = point
    scalar = int(scalar)
    while scalar > 0:
        if scalar & 1:
            result = _edwards_add(result, addend)
        addend = _edwards_add(addend, addend)
        scalar >>= 1
    return result


_BASE_POINT = (_recover_x(4 * _inv(5) % _P), 4 * _inv(5) % _P)


__all__ = ["public_key_from_seed", "sign_ed25519", "verify_ed25519_signature"]
