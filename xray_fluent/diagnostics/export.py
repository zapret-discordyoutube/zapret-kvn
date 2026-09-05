from __future__ import annotations

from datetime import datetime, timezone
from dataclasses import asdict
import json
from pathlib import Path
import platform
import re
import zipfile

from ..profiles.models import AppState
from ..constants import APP_VERSION
from .runtime_logging import redact_runtime_log


REDACT_KEYS = {
    "id",
    "password",
    "pass",
    "token",
    "publickey",
    "privatekey",
    "private_key",
    "secretkey",
    "secret_key",
    "pre_shared_key",
    "presharedkey",
    "shortid",
    "sid",
    "uuid",
    "url",
    "pending_url",
    "web_page_url",
    "support_url",
    "link",
    "auth",
    "auth_str",
    "username",
    "hwid",
    "subscription_device_id",
    "uri",
    "raw_uri",
    "public_key",
    "header_protection_key",
    "client_key",
    "key",
    "encryption",
    "pin_sha256",
    "certificate_sha256",
    "certificate_public_key_sha256",
    "password_hash",
    "salt",
    "authorization",
    "proxy_authorization",
    "cookie",
    "set_cookie",
    "obfs_password",
}

_NORMALIZED_REDACT_KEYS = {key.replace("_", "").replace("-", "") for key in REDACT_KEYS}

_URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)


def _redact(value):
    if isinstance(value, dict):
        redacted = {}
        for key, item in value.items():
            if str(key).casefold().replace("_", "").replace("-", "") in _NORMALIZED_REDACT_KEYS:
                redacted[key] = "***"
            else:
                redacted[key] = _redact(item)
        return redacted
    if isinstance(value, (list, tuple)):
        return [_redact(item) for item in value]
    if isinstance(value, str):
        return _redact_log_line(value)
    return value


def _redact_log_line(line: str) -> str:
    return _URL_RE.sub("<URL скрыт>", redact_runtime_log(str(line)))


def capture_runtime_config(executable: Path, config: dict) -> dict:
    """Snapshot the JSON written by a manager, retaining no transport secrets."""
    return {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "executable": str(executable),
        "config": _redact(config),
    }


def collect_runtime_diagnostics(controller) -> dict:
    """Use manager-owned snapshots, never reconstruct a supposed active config."""
    contexts = getattr(controller, "_core_log_contexts", {})
    components = {}
    for component, attribute in (("sing-box", "singbox"), ("xray", "xray"), ("hysteria", "hysteria"), ("amnezia", "amnezia")):
        manager = getattr(controller, attribute, None)
        context = contexts.get(component)
        components[component] = {
            "running": bool(manager and manager.is_running),
            "log_context": asdict(context) if context is not None else None,
            "last_written_config": getattr(manager, "diagnostic_config", None),
            "transport_stats": getattr(manager, "stats", None) if component == "amnezia" else None,
        }
    return _redact({
        "schema": 1,
        "connected": bool(controller.connected),
        "components": components,
    })


def export_diagnostics(zip_path: Path, state: AppState, logs: list[str], *, runtime_errors=(), runtime=None) -> Path:
    zip_path.parent.mkdir(parents=True, exist_ok=True)

    safe_state = _redact(state.to_dict())
    meta = {
        "app_version": APP_VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "platform": platform.platform(),
        "python": platform.python_version(),
    }

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("state_redacted.json", json.dumps(safe_state, ensure_ascii=True, indent=2))
        archive.writestr("meta.json", json.dumps(meta, ensure_ascii=True, indent=2))
        archive.writestr("recent_logs.txt", "\n".join(_redact_log_line(line) for line in logs[-2000:]))
        archive.writestr("runtime_errors.json", json.dumps(
            _redact([asdict(record) for record in runtime_errors]), ensure_ascii=False, indent=2,
        ))
        archive.writestr("runtime_redacted.json", json.dumps(
            _redact(runtime) if runtime is not None else {"schema": 1, "components": {}, "available": False},
            ensure_ascii=False, indent=2,
        ))

    return zip_path
