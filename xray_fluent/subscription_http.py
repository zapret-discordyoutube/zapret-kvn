from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
import locale
import platform
import re
import urllib.error
import urllib.request
from urllib.parse import parse_qs, unquote, urlsplit

from .constants import APP_VERSION, PROXY_HOST
from .happ_crypt import HappCryptError, decrypt_happ_link, is_happ_crypt_link
from .http_utils import build_opener
from .models import Subscription


MAX_SUBSCRIPTION_BYTES = 10 * 1024 * 1024
_LOCALE_CODE = re.compile(r"[A-Za-z]{2,3}(?:[_-][A-Za-z0-9]{2,8})*")
_PANEL_HWID = re.compile(r"[A-Za-z0-9=-]{10,64}")
CLIENT_PROFILES = ("zapret", "happ", "incy", "v2raytun", "custom")
_PROFILE_DEFAULT_USER_AGENTS = {
    "happ": "Happ/3.13.0",
    "incy": "INCY/1.0/Windows",
    "v2raytun": "v2rayTun/2.3.5",
}
_WRAPPED_SOURCE_PREFIXES = {
    "happ://add/": "happ",
    "incy://add/": "incy",
    "incy://import/": "incy",
    "v2raytun://import/": "v2raytun",
}


class SubscriptionFetchError(RuntimeError):
    pass


@dataclass(slots=True)
class SubscriptionFetchResult:
    data: bytes = b""
    headers: dict[str, str] = field(default_factory=dict)
    status: int = 200
    not_modified: bool = False
    via_proxy: bool = False


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urlsplit(newurl).scheme.lower() not in {"http", "https"}:
            raise SubscriptionFetchError("Перенаправление подписки использует небезопасную схему")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def default_subscription_user_agent() -> str:
    return f"ZapretKVN/{APP_VERSION}"


def normalize_client_profile(value: str) -> str:
    profile = str(value or "").strip().lower()
    return profile if profile in CLIENT_PROFILES else "custom"


def profile_default_user_agent(profile: str) -> str:
    return _PROFILE_DEFAULT_USER_AGENTS.get(
        normalize_client_profile(profile), default_subscription_user_agent()
    )


def resolve_subscription_source(value: str) -> tuple[str, str | None]:
    text = str(value or "").strip()
    lowered = text.lower()
    parsed = urlsplit(text)
    if parsed.scheme.lower() in {"http", "https"} and parsed.hostname:
        return text, None

    if is_happ_crypt_link(text):
        return _resolve_happ_crypt_source(text)

    if parsed.scheme.lower() in {"happ", "incy", "v2raytun"}:
        if "crypt" in parsed.netloc.lower() or parsed.path.lower().lstrip("/").startswith("crypt"):
            raise SubscriptionFetchError(
                "Зашифрованные proprietary deep links этим клиентом не расшифровываются"
            )
        query = parse_qs(parsed.query)
        query_url = (query.get("url") or query.get("data") or [""])[0]
        if query_url:
            candidate = unquote(query_url).strip()
            hint = parsed.scheme.lower()
        else:
            candidate = ""
            hint = None
            for prefix, profile in _WRAPPED_SOURCE_PREFIXES.items():
                if lowered.startswith(prefix):
                    candidate = unquote(text[len(prefix) :]).strip()
                    hint = profile
                    break
        if candidate and hint:
            candidate = _decode_wrapped_http_url(candidate)
            inner = urlsplit(candidate)
            if inner.scheme.lower() in {"http", "https"} and inner.hostname:
                return candidate, hint
    raise SubscriptionFetchError(
        "URL подписки должен использовать HTTP/HTTPS или открытую add/import-ссылку Happ, INCY, v2RayTun"
    )


def _resolve_happ_crypt_source(link: str) -> tuple[str, str]:
    """Развернуть ``happ://crypt*`` в обычный URL подписки."""

    try:
        _, payload = decrypt_happ_link(link)
    except HappCryptError as exc:
        raise SubscriptionFetchError(str(exc)) from exc
    candidate = _decode_wrapped_http_url(payload.strip())
    inner = urlsplit(candidate)
    if inner.scheme.lower() in {"http", "https"} and inner.hostname:
        return candidate, "happ"
    raise SubscriptionFetchError(
        "Расшифрованная ссылка Happ не содержит адрес подписки HTTP/HTTPS"
    )


def _decode_wrapped_http_url(value: str) -> str:
    if value.lower().startswith(("http://", "https://")):
        return value
    compact = "".join(value.split())
    if not compact or not re.fullmatch(r"[A-Za-z0-9_+/=-]+", compact):
        return value
    padded = compact + "=" * ((4 - len(compact) % 4) % 4)
    try:
        return base64.b64decode(
            padded.replace("-", "+").replace("_", "/"), validate=True
        ).decode("utf-8").strip()
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return value


def validate_subscription_url(url: str) -> str:
    return resolve_subscription_source(url)[0]


def validate_hwid(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise SubscriptionFetchError("HWID не задан")
    if len(text) > 128 or any(ord(char) < 32 or ord(char) == 127 for char in text):
        raise SubscriptionFetchError("HWID содержит недопустимые символы или слишком длинный")
    return text


def is_panel_compatible_hwid(value: str) -> bool:
    """Проверить идентификатор по образцу Happ, который принимают панели.

    Панель с лимитом устройств принимает латиницу, цифры, ``-`` и ``=`` длиной
    10..64 символа. Идентификатор вне этого образца она молча игнорирует, и
    лимит устройств перестаёт работать вместо явной ошибки, поэтому несовпадение
    стоит показать пользователю до отправки.
    """

    return bool(_PANEL_HWID.fullmatch(str(value or "").strip()))


def subscription_request_headers(subscription: Subscription) -> dict[str, str]:
    """Собрать заголовки запроса подписки.

    Имитация клиента должна совпадать с оригиналом, а не быть похожей: панели
    сопоставляют запрос правилами по заголовкам, и лишний заголовок выдаёт
    подделку не хуже отсутствующего. Набор Happ снят с реального клиента — там
    нет ни ``Accept``, ни ``X-App-Version``, а локаль короткая (``ru``).
    """

    profile = normalize_client_profile(subscription.client_profile)
    user_agent = subscription.user_agent.strip() or profile_default_user_agent(profile)
    headers = {
        "Accept-Encoding": "identity",
        "User-Agent": _safe_header_value(user_agent, "User-Agent"),
    }
    app_version = {
        "incy": "1.0",
        "v2raytun": "2.3.5",
    }.get(profile, APP_VERSION)
    if profile in {"incy", "v2raytun"}:
        headers["Accept"] = "*/*"
        headers["X-App-Version"] = app_version
    elif profile != "happ":
        headers["Accept"] = "text/plain, application/json;q=0.9, */*;q=0.5"
    if profile == "incy":
        headers["X-Client"] = "INCY"
        headers["X-Device-Locale"] = _safe_header_value(_device_locale(), "X-Device-Locale")
    if subscription.send_hwid:
        hwid = validate_hwid(subscription.hwid)
        headers.update(
            {
                "X-HWID": hwid,
                "X-Device-OS": "Windows",
                "X-Ver-OS": _safe_header_value(platform.release() or "Windows", "X-Ver-OS"),
                "X-Device-Model": _safe_header_value(
                    platform.machine() or "Desktop", "X-Device-Model"
                ),
            }
        )
        if profile == "incy":
            headers["X-Device-ID"] = hwid
        if profile == "happ":
            headers["X-Device-Locale"] = _safe_header_value(
                _short_locale(_device_locale()), "X-Device-Locale"
            )
    return headers


def _device_locale() -> str:
    """Вернуть локаль в форме ``ru-RU``.

    На Windows ``locale.getlocale()`` отдаёт человекочитаемое имя вида
    ``Russian_Russia``, которое ни один клиент в заголовок не пишет, поэтому
    оно переводится в код языка через таблицу ``locale.windows_locale``.
    """

    value = locale.getlocale()[0] or "ru_RU"
    if not _LOCALE_CODE.fullmatch(value):
        value = _windows_locale_code(value) or "ru_RU"
    return value.replace("_", "-")


def _windows_locale_code(value: str) -> str | None:
    """Перевести ``Russian_Russia`` в ``ru_RU`` через таблицу псевдонимов locale.

    Полное имя в таблице обычно отсутствует, поэтому запасной путь — имя языка:
    регион при этом может огрубиться (``English_United States`` -> ``en_EN``),
    но Happ всё равно берёт из локали только язык.
    """

    text = value.strip()
    for candidate in (text, text.split("_")[0]):
        if not candidate:
            continue
        try:
            normalized = locale.normalize(candidate).split(".")[0]
        except (TypeError, ValueError):
            continue
        if normalized and _LOCALE_CODE.fullmatch(normalized):
            return normalized
    return None


def _short_locale(value: str) -> str:
    """Happ передаёт только язык: ``ru``, а не ``ru-RU``."""

    return value.split("-")[0].split("_")[0] or "ru"


def _safe_header_value(value: str, name: str) -> str:
    text = str(value or "").strip()
    if not text or any(char in text for char in "\r\n"):
        raise SubscriptionFetchError(f"{name} содержит недопустимое значение")
    return text


def mask_subscription_url(url: str) -> str:
    """Hide the complete subscription URL on screenshot-visible surfaces."""
    return "********" if str(url or "").strip() else ""


def describe_http_failure(status: int, headers: dict[str, str]) -> str:
    """Объяснить отказ сервера подписки.

    Панели с лимитом устройств (Remnawave и совместимые) отвечают обычным 404 и
    сообщают причину отдельным заголовком. Без их разбора пользователь видит
    «HTTP 404» и не понимает, что упёрся в лимит устройств.
    """

    normalized = {str(key).lower(): str(value) for key, value in (headers or {}).items()}
    if "x-hwid-max-devices-reached" in normalized or "x-hwid-limit" in normalized:
        return (
            "Достигнут лимит устройств подписки. Отвяжите лишнее устройство "
            "в личном кабинете или у провайдера"
        )
    if "x-hwid-not-supported" in normalized:
        return (
            "Провайдер требует идентификатор устройства (HWID). "
            "Включите отправку HWID в настройках подписки"
        )
    if status == 403:
        # Панели сопоставляют запрос правилами по заголовкам и отвечают 403, когда
        # ни одно правило не подошло либо сработало правило блокировки клиента.
        # Cloudflare перед панелью отдаёт тот же код, но со своей HTML-страницей.
        if "cf-ray" in normalized or "cf-mitigated" in normalized:
            return (
                "Защита сайта провайдера отклонила запрос (HTTP 403). "
                "Попробуйте обновить подписку через прокси"
            )
        return (
            "Провайдер отклонил запрос клиента (HTTP 403). "
            "Смените профиль клиента или User-Agent в настройках подписки"
        )
    return f"HTTP {status}"


def sanitize_fetch_error(error: BaseException) -> str:
    text = str(error) or error.__class__.__name__
    text = re.sub(r"https?://[^\s'\"]+", "<URL скрыт>", text)
    return text[:500]


def fetch_subscription(
    subscription: Subscription,
    *,
    mode: str = "auto",
    proxy_port: int | None = None,
    timeout: float = 15,
    max_bytes: int = MAX_SUBSCRIPTION_BYTES,
) -> SubscriptionFetchResult:
    url = validate_subscription_url(subscription.url)
    if mode not in {"auto", "direct", "proxy"}:
        raise SubscriptionFetchError(f"Неизвестный режим загрузки: {mode}")
    attempts: list[tuple[bool, int | None]] = []
    if mode in {"auto", "direct"}:
        attempts.append((False, None))
    if mode in {"auto", "proxy"} and proxy_port and proxy_port > 0:
        attempts.append((True, int(proxy_port)))
    if mode == "proxy" and not attempts:
        raise SubscriptionFetchError("Активный HTTP-прокси недоступен")

    errors: list[str] = []
    for via_proxy, port in attempts:
        try:
            return _fetch_once(
                subscription,
                url=url,
                via_proxy=via_proxy,
                proxy_port=port,
                timeout=timeout,
                max_bytes=max_bytes,
            )
        except Exception as exc:
            errors.append(sanitize_fetch_error(exc))
    detail = "; ".join(dict.fromkeys(errors)) or "неизвестная ошибка"
    raise SubscriptionFetchError(f"Не удалось загрузить подписку: {detail}")


def _fetch_once(
    subscription: Subscription,
    *,
    url: str,
    via_proxy: bool,
    proxy_port: int | None,
    timeout: float,
    max_bytes: int,
) -> SubscriptionFetchResult:
    proxy_handler = (
        urllib.request.ProxyHandler(
            {
                "http": f"http://{PROXY_HOST}:{proxy_port}",
                "https": f"http://{PROXY_HOST}:{proxy_port}",
            }
        )
        if via_proxy and proxy_port
        else urllib.request.ProxyHandler({})
    )
    opener = build_opener(proxy_handler, _SafeRedirectHandler())
    headers = subscription_request_headers(subscription)
    if subscription.etag:
        headers["If-None-Match"] = subscription.etag
    if subscription.last_modified:
        headers["If-Modified-Since"] = subscription.last_modified
    request = urllib.request.Request(url, headers=headers)
    try:
        response = opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as exc:
        if exc.code == 304:
            return SubscriptionFetchResult(
                headers=_response_headers(exc.headers),
                status=304,
                not_modified=True,
                via_proxy=via_proxy,
            )
        raise SubscriptionFetchError(
            describe_http_failure(exc.code, _response_headers(exc.headers))
        ) from exc
    with response:
        final_url = response.geturl()
        if urlsplit(final_url).scheme.lower() not in {"http", "https"}:
            raise SubscriptionFetchError("Ответ подписки пришёл по небезопасной схеме")
        data = response.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise SubscriptionFetchError(f"Ответ подписки превышает {max_bytes // (1024 * 1024)} МиБ")
        return SubscriptionFetchResult(
            data=data,
            headers=_response_headers(response.headers),
            status=int(getattr(response, "status", 200) or 200),
            via_proxy=via_proxy,
        )


def _response_headers(headers) -> dict[str, str]:
    return {str(key).lower(): str(value) for key, value in headers.items()}
