"""Расшифровка ссылок ``happ://crypt*`` клиента Happ.

Ссылка-контейнер прячет внутри одну строку — как правило, URL подписки. Поддержаны
все пять поколений формата:

``crypt``           RSA-1024, PKCS#1 v1.5
``crypt2``…``crypt4`` RSA-4096, PKCS#1 v1.5
``crypt5``          RSA-4096 поверх ChaCha20-Poly1305 с байтовыми перестановками

В первых четырёх поколениях шифротекст режется на блоки размером с модуль ключа,
каждый расшифровывается отдельно, результаты склеиваются. В пятом поколении ключ
выбирается по маркеру, извлекаемому из самого payload; см. :func:`_decrypt_crypt5`.

Ключевой материал — в :mod:`xray_fluent.happ_keys`.
"""

from __future__ import annotations

import base64
import binascii
import re

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.serialization import load_der_private_key

from .happ_keys import CRYPT1_4_KEYS, CRYPT5_KEYS


#: Схемы в порядке убывания длины префикса — важно, чтобы ``crypt5`` не был
#: перехвачен префиксом ``crypt``.
CRYPT_SCHEMES: tuple[tuple[str, int], ...] = (
    ("happ://crypt5/", 4),
    ("happ://crypt4/", 3),
    ("happ://crypt3/", 2),
    ("happ://crypt2/", 1),
    ("happ://crypt/", 0),
)

_CHACHA_KEY_SIZE = 32
_CRYPT5_NONCE_SIZE = 12
_CRYPT5_SALT_SIZE = 8
#: Смещение соли в salted-раскладке: nonce(12) + tag(2).
_CRYPT5_SALT_OFFSET = 14
_MARKER_SIZE = 4


class HappCryptError(ValueError):
    """Ссылку ``happ://crypt*`` не удалось расшифровать."""


def is_happ_crypt_link(value: str) -> bool:
    lowered = str(value or "").strip().lower()
    return any(lowered.startswith(prefix) for prefix, _ in CRYPT_SCHEMES)


def decrypt_happ_link(value: str) -> tuple[str, str]:
    """Расшифровать ссылку. Возвращает ``(имя схемы, открытый текст)``."""

    text = str(value or "").strip()
    lowered = text.lower()
    for prefix, ordinal in CRYPT_SCHEMES:
        if not lowered.startswith(prefix):
            continue
        payload = text[len(prefix) :].strip()
        if not payload:
            raise HappCryptError("Ссылка Happ не содержит зашифрованных данных")
        scheme = prefix[len("happ://") :].rstrip("/")
        if ordinal == 4:
            return scheme, _decrypt_crypt5(payload)
        return scheme, _decrypt_crypt1to4(payload, ordinal)
    raise HappCryptError("Ссылка не является happ://crypt")


def _b64decode(value: str | bytes) -> bytes:
    """Декодировать base64, принимая url-safe алфавит и отсутствующий padding."""

    text = value.decode("latin-1") if isinstance(value, bytes) else value
    compact = re.sub(r"\s", "", text).replace("-", "+").replace("_", "/").rstrip("=")
    try:
        return base64.b64decode(compact + "=" * (-len(compact) % 4))
    except (binascii.Error, ValueError) as exc:
        raise HappCryptError("Повреждённые данные ссылки Happ (base64)") from exc


def _load_key(encoded: str):
    try:
        return load_der_private_key(base64.b64decode(encoded), None)
    except Exception as exc:  # pragma: no cover - таблица ключей проверяется тестом
        raise HappCryptError("Ключ Happ повреждён") from exc


def _swap_pairs(data: bytes) -> bytes:
    """``AB`` -> ``BA`` в каждой паре байт. Операция обратна самой себе."""

    buffer = bytearray(data)
    for index in range(0, len(buffer) - 1, 2):
        buffer[index], buffer[index + 1] = buffer[index + 1], buffer[index]
    return bytes(buffer)


def _swap_block_halves(data: bytes) -> bytes:
    """``ABCD`` -> ``CDAB`` в каждом блоке из 4 байт; хвост короче блока не трогается."""

    buffer = bytearray(data)
    for index in range(0, len(buffer) - len(buffer) % 4, 4):
        buffer[index], buffer[index + 2] = buffer[index + 2], buffer[index]
        buffer[index + 1], buffer[index + 3] = buffer[index + 3], buffer[index + 1]
    return bytes(buffer)


def _decrypt_crypt1to4(payload: str, ordinal: int) -> str:
    key = _load_key(CRYPT1_4_KEYS[ordinal])
    ciphertext = _b64decode(payload)
    block_size = key.key_size // 8
    if not ciphertext or len(ciphertext) % block_size:
        raise HappCryptError("Длина зашифрованных данных не кратна размеру ключа Happ")
    chunks = []
    for offset in range(0, len(ciphertext), block_size):
        try:
            chunks.append(key.decrypt(ciphertext[offset : offset + block_size], padding.PKCS1v15()))
        except Exception as exc:
            raise HappCryptError("Ссылка зашифрована ключом Happ, которого нет в таблице") from exc
    return _decode_text(b"".join(chunks))


def _decrypt_crypt5(payload: str) -> str:
    swapped = _swap_block_halves(payload.encode("latin-1", "ignore"))
    if len(swapped) < _MARKER_SIZE * 2 + _CRYPT5_NONCE_SIZE:
        raise HappCryptError("Ссылка happ://crypt5 слишком короткая")
    marker = (swapped[:_MARKER_SIZE] + swapped[-_MARKER_SIZE:]).decode("latin-1")
    encoded_key = CRYPT5_KEYS.get(marker)
    if encoded_key is None:
        raise HappCryptError(
            f"Ключ Happ для этой ссылки неизвестен (маркер {marker}). "
            "Скорее всего, ссылка выпущена более новой версией Happ"
        )
    key = _load_key(encoded_key)
    body = swapped[_MARKER_SIZE:-_MARKER_SIZE]

    # Раскладку тела различает первый байт после nonce: цифра — legacy, иначе salted.
    # Порядок попыток задаётся эвристикой, но пробуются обе.
    salted_first = not _is_digit(body, _CRYPT5_NONCE_SIZE)
    first_error: Exception | None = None
    for salted in (salted_first, not salted_first):
        try:
            return _decrypt_crypt5_body(body, key, salted=salted)
        except Exception as exc:
            first_error = first_error or exc
    raise HappCryptError("Не удалось расшифровать ссылку happ://crypt5") from first_error


def _is_digit(data: bytes, index: int) -> bool:
    return index < len(data) and 48 <= data[index] <= 57


def _decrypt_crypt5_body(body: bytes, key, *, salted: bool) -> str:
    nonce = body[:_CRYPT5_NONCE_SIZE]
    if salted:
        salt = body[_CRYPT5_SALT_OFFSET : _CRYPT5_SALT_OFFSET + _CRYPT5_SALT_SIZE]
        cursor = _CRYPT5_SALT_OFFSET + _CRYPT5_SALT_SIZE
    else:
        salt = b""
        cursor = _CRYPT5_NONCE_SIZE

    length_end = cursor
    while _is_digit(body, length_end):
        length_end += 1
    if length_end == cursor:
        raise HappCryptError("В теле happ://crypt5 нет длины сегмента")
    segment_length = int(body[cursor:length_end])

    # Байт-разделитель произвольный: он пропускается по позиции, а не сравнивается.
    packed = body[length_end:]
    if not packed or segment_length > len(packed) - 1:
        raise HappCryptError("Тело happ://crypt5 обрезано")
    segment = packed[1 : 1 + segment_length]
    rsa_ciphertext = packed[1 + segment_length :]

    chacha_key = _b64decode(_swap_pairs(key.decrypt(_b64decode(rsa_ciphertext), padding.PKCS1v15())))
    if len(chacha_key) != _CHACHA_KEY_SIZE:
        raise HappCryptError("Ключ ChaCha20 в ссылке happ://crypt5 имеет неверный размер")
    if salt:
        chacha_key = bytes(
            byte ^ salt[index % len(salt)] for index, byte in enumerate(chacha_key)
        )

    try:
        opened = ChaCha20Poly1305(chacha_key).decrypt(nonce, _b64decode(segment), None)
    except InvalidTag as exc:
        raise HappCryptError("Проверка целостности ссылки happ://crypt5 не прошла") from exc
    return _decode_text(_b64decode(_swap_pairs(opened)))


def _decode_text(data: bytes) -> str:
    try:
        return data.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise HappCryptError("Расшифрованные данные Happ не являются текстом") from exc
