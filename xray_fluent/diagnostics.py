from __future__ import annotations

from datetime import datetime, timezone
from dataclasses import asdict
import json
from pathlib import Path
import platform
import re
import zipfile

from .models import AppState


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
}

_URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)


def _redact(value):
    if isinstance(value, dict):
        redacted = {}
        for key, item in value.items():
            if str(key).casefold() in REDACT_KEYS:
                redacted[key] = "***"
            else:
                redacted[key] = _redact(item)
        return redacted
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value


def _redact_log_line(line: str) -> str:
    return _URL_RE.sub("<URL скрыт>", str(line))


def export_diagnostics(zip_path: Path, state: AppState, logs: list[str], *, runtime_errors=()) -> Path:
    zip_path.parent.mkdir(parents=True, exist_ok=True)

    safe_state = _redact(state.to_dict())
    meta = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "platform": platform.platform(),
        "python": platform.python_version(),
    }

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("state_redacted.json", json.dumps(safe_state, ensure_ascii=True, indent=2))
        archive.writestr("meta.json", json.dumps(meta, ensure_ascii=True, indent=2))
        archive.writestr("recent_logs.txt", "\n".join(_redact_log_line(line) for line in logs[-2000:]))
        archive.writestr("runtime_errors.json", json.dumps(
            [asdict(record) for record in runtime_errors], ensure_ascii=False, indent=2,
        ))

    return zip_path
