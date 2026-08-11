from __future__ import annotations

from dataclasses import dataclass, field
import re
import urllib.error
import urllib.request
from urllib.parse import urlsplit, urlunsplit

from .constants import APP_VERSION, PROXY_HOST
from .http_utils import build_opener
from .models import Subscription


MAX_SUBSCRIPTION_BYTES = 10 * 1024 * 1024


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


def validate_subscription_url(url: str) -> str:
    text = str(url or "").strip()
    parsed = urlsplit(text)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise SubscriptionFetchError("URL подписки должен использовать HTTP или HTTPS")
    return text


def mask_subscription_url(url: str) -> str:
    try:
        parsed = urlsplit(url)
    except ValueError:
        return "<скрыто>"
    hostname = parsed.hostname or ""
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"
    try:
        port = parsed.port
    except ValueError:
        port = None
    netloc = f"{hostname}:{port}" if port else hostname
    path = "/…" if parsed.path and parsed.path != "/" else parsed.path
    return urlunsplit((parsed.scheme, netloc, path, "", ""))


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
    headers = {
        "Accept": "text/plain, application/json;q=0.9, */*;q=0.5",
        "Accept-Encoding": "identity",
        "User-Agent": subscription.user_agent.strip() or default_subscription_user_agent(),
    }
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
        raise SubscriptionFetchError(f"HTTP {exc.code}") from exc
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
