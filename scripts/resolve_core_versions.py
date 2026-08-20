#!/usr/bin/env python3
"""Resolve and pin the latest stable Windows core assets.

The normal Windows build is deliberately lock-driven.  This command is the
explicit online boundary that may inspect GitHub and refresh only the Xray and
extended sing-box entries in ``scripts/core-lock.windows-x64.json``.  Both
``--check`` and ``--write`` download the selected archives and verify their
actual bytes against the digest published by GitHub before a result is
reported.  ``--write`` replaces the lock atomically; a network or digest error
therefore leaves the previous lock untouched.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOCK_PATH = ROOT / "scripts" / "core-lock.windows-x64.json"
GITHUB_API_ROOT = "https://api.github.com"
USER_AGENT = "ZapretKVN-core-resolver/1"
# A GitHub page includes every release asset entry.  The current extended
# sing-box page is a little over 4 MiB, so keep a bounded but sufficient cap
# rather than making the API read unbounded.
METADATA_LIMIT = 16 * 1024 * 1024
ARCHIVE_LIMIT = 512 * 1024 * 1024

XRAY_REPOSITORY = "XTLS/Xray-core"
XRAY_ASSET_NAME = "Xray-windows-64.zip"
SINGBOX_REPOSITORY = "shtorm-7/sing-box-extended"

_XRAY_TAG_RE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")
_SINGBOX_TAG_RE = re.compile(
    r"^v(\d+)\.(\d+)\.(\d+)-extended-(\d+)\.(\d+)\.(\d+)$"
)
_SHA256_RE = re.compile(r"(?i)(?:sha256\s*:\s*)?([0-9a-f]{64})")
_FILE_MAPPING_RE = re.compile(
    r'\{\n\s+"match": ("(?:\\.|[^"\\])*"),\n'
    r'\s+"target": ("(?:\\.|[^"\\])*")\n\s+\}'
)


class ResolverError(RuntimeError):
    """A safe, user-actionable failure while resolving a core release."""


def _request_headers(url: str, accept: str) -> dict[str, str]:
    """Build request headers without exposing protected API credentials.

    Anonymous GitHub API limits are deliberately small.  The release host may
    provide ``GITHUB_TOKEN`` through its protected environment; it is used only
    for api.github.com and is never printed or persisted in the lock file.
    """

    headers = {"Accept": accept, "User-Agent": USER_AGENT}
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if token and url.startswith(GITHUB_API_ROOT + "/"):
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _read_bounded(response: Any, *, limit: int) -> bytes:
    body = response.read(limit + 1)
    if len(body) > limit:
        raise ResolverError(f"response exceeds the {limit}-byte safety limit")
    return body


def fetch_bytes(url: str, *, timeout: float = 30.0, limit: int = METADATA_LIMIT) -> bytes:
    """Fetch a bounded response using the resolver's fixed public User-Agent."""

    request = Request(url, headers=_request_headers(url, "application/json"))
    try:
        with urlopen(request, timeout=timeout) as response:
            return _read_bounded(response, limit=limit)
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        raise ResolverError(f"download failed for {url}: {exc}") from exc


def fetch_json(url: str, *, timeout: float = 30.0) -> Any:
    """Fetch and decode one GitHub API JSON document."""

    try:
        return json.loads(fetch_bytes(url, timeout=timeout).decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ResolverError(f"GitHub API returned non-UTF-8 JSON: {url}") from exc
    except json.JSONDecodeError as exc:
        raise ResolverError(f"GitHub API returned malformed JSON: {url}") from exc


def github_latest_release(repository: str, *, timeout: float = 30.0) -> dict[str, Any]:
    """Read GitHub's latest stable release endpoint.

    GitHub defines ``/releases/latest`` as the latest non-draft,
    non-prerelease release.  The normal resolver still applies the explicit
    flag and tag checks below, so a changed API contract fails closed.
    """

    url = f"{GITHUB_API_ROOT}/repos/{repository}/releases/latest"
    payload = fetch_json(url, timeout=timeout)
    if not isinstance(payload, dict):
        raise ResolverError(f"GitHub latest release response is not an object: {repository}")
    return payload


def _release_is_stable(release: dict[str, Any]) -> bool:
    # Missing flags are not treated as safe defaults.  A release resolver must
    # fail closed if GitHub changes the response shape.
    return release.get("draft") is False and release.get("prerelease") is False


def _xray_version(tag: str) -> tuple[int, int, int] | None:
    match = _XRAY_TAG_RE.fullmatch(tag)
    if match is None:
        return None
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def _singbox_version(tag: str) -> tuple[int, int, int, int, int, int] | None:
    match = _SINGBOX_TAG_RE.fullmatch(tag)
    if match is None:
        return None
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def _stable_release(
    releases: list[dict[str, Any]],
    *,
    version_parser: Any,
    component: str,
) -> dict[str, Any]:
    candidates: list[tuple[tuple[int, ...], dict[str, Any]]] = []
    for release in releases:
        if not _release_is_stable(release):
            continue
        tag = str(release.get("tag_name") or "")
        version = version_parser(tag)
        if version is not None:
            candidates.append((version, release))
    if not candidates:
        raise ResolverError(f"no stable {component} release with a valid tag was found")
    return max(candidates, key=lambda item: item[0])[1]


def select_stable_xray(releases: list[dict[str, Any]]) -> dict[str, Any]:
    """Select the highest non-draft, non-prerelease Xray release."""

    return _stable_release(
        releases,
        version_parser=_xray_version,
        component="Xray",
    )


def select_stable_singbox(releases: list[dict[str, Any]]) -> dict[str, Any]:
    """Select the highest stable extended sing-box release."""

    return _stable_release(
        releases,
        version_parser=_singbox_version,
        component="sing-box Extended",
    )


def _expected_asset_url(repository: str, tag: str, asset_name: str) -> str:
    return (
        f"https://github.com/{repository}/releases/download/"
        f"{quote(tag, safe='')}/{quote(asset_name, safe='')}"
    )


def select_exact_asset(
    release: dict[str, Any],
    *,
    repository: str,
    asset_name: str,
) -> dict[str, Any]:
    """Select one exact uploaded asset and reject wrong-architecture variants."""

    assets = release.get("assets")
    if not isinstance(assets, list):
        raise ResolverError(f"release {release.get('tag_name', '')} has no assets list")
    matches = [
        asset
        for asset in assets
        if isinstance(asset, dict) and asset.get("name") == asset_name
    ]
    if len(matches) != 1:
        raise ResolverError(
            f"release {release.get('tag_name', '')} must contain exactly one "
            f"{asset_name}, found {len(matches)}"
        )
    asset = matches[0]
    if asset.get("state") not in (None, "uploaded"):
        raise ResolverError(f"asset {asset_name} is not uploaded")
    try:
        size = int(asset.get("size") or 0)
    except (TypeError, ValueError) as exc:
        raise ResolverError(f"asset {asset_name} has an invalid size") from exc
    if size <= 0:
        raise ResolverError(f"asset {asset_name} has an empty or missing size")

    expected_url = _expected_asset_url(
        repository,
        str(release.get("tag_name") or ""),
        asset_name,
    )
    if asset.get("browser_download_url") != expected_url:
        raise ResolverError(f"asset {asset_name} has an unexpected download URL")
    return asset


def _digest_from_text(text: str) -> str | None:
    matches = _SHA256_RE.findall(text)
    if len(matches) != 1:
        return None
    return matches[0].lower()


def asset_digest(
    release: dict[str, Any],
    asset: dict[str, Any],
    *,
    repository: str,
    timeout: float = 30.0,
) -> str:
    """Return the trusted SHA-256 for an asset or its exact upstream sidecar."""

    raw_digest = asset.get("digest")
    if isinstance(raw_digest, str):
        parsed = _digest_from_text(raw_digest)
        if parsed is not None and raw_digest.lower().strip().startswith("sha256:"):
            return parsed
        raise ResolverError(f"asset {asset.get('name', '')} has an invalid SHA-256 digest")

    # Older GitHub API responses may omit ``digest``.  A sidecar is accepted
    # only when its name is exactly the selected archive plus ``.dgst`` and its
    # URL is the corresponding GitHub release URL.
    asset_name = str(asset.get("name") or "")
    sidecar_name = asset_name + ".dgst"
    sidecar = select_exact_asset(
        release,
        repository=repository,
        asset_name=sidecar_name,
    )
    body = fetch_bytes(str(sidecar["browser_download_url"]), timeout=timeout, limit=16 * 1024)
    parsed = _digest_from_text(body.decode("utf-8", errors="replace"))
    if parsed is None:
        raise ResolverError(f"sidecar {sidecar_name} has no unique SHA-256 digest")
    return parsed


def download_and_verify(
    url: str,
    expected_sha256: str,
    *,
    timeout: float = 120.0,
) -> int:
    """Download an archive to a private temporary file and verify every byte."""

    expected = expected_sha256.lower()
    if re.fullmatch(r"[0-9a-f]{64}", expected) is None:
        raise ResolverError(f"invalid expected SHA-256: {expected_sha256}")

    fd, temporary_name = tempfile.mkstemp(prefix="zapret-kvn-core-", suffix=".part")
    temporary = Path(temporary_name)
    total = 0
    digest = hashlib.sha256()
    try:
        request = Request(url, headers=_request_headers(url, "application/octet-stream"))
        try:
            with urlopen(request, timeout=timeout) as response, os.fdopen(fd, "wb") as output:
                fd = -1
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > ARCHIVE_LIMIT:
                        raise ResolverError(
                            f"archive exceeds the {ARCHIVE_LIMIT}-byte safety limit"
                        )
                    digest.update(chunk)
                    output.write(chunk)
        except (HTTPError, URLError, TimeoutError, OSError) as exc:
            raise ResolverError(f"archive download failed for {url}: {exc}") from exc
        if total <= 0:
            raise ResolverError(f"archive download was empty: {url}")
        actual = digest.hexdigest()
        if actual != expected:
            raise ResolverError(
                f"SHA-256 mismatch for {url}: expected {expected}, got {actual}"
            )
        return total
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _validate_lock(lock: dict[str, Any]) -> None:
    if lock.get("schema") != 1 or lock.get("platform") != "windows-x64":
        raise ResolverError("unsupported core lock schema or platform")
    sources = lock.get("sources")
    if not isinstance(sources, list):
        raise ResolverError("core lock sources must be a list")
    ids = [source.get("id") for source in sources if isinstance(source, dict)]
    if len(ids) != len(sources) or len(set(ids)) != len(ids):
        raise ResolverError("core lock sources must contain unique object ids")
    for required in ("sing-box-extended", "xray-core"):
        if required not in ids:
            raise ResolverError(f"core lock is missing {required}")


def read_lock(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ResolverError(f"cannot read core lock {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ResolverError("core lock root must be a JSON object")
    _validate_lock(payload)
    return payload


def _source_by_id(lock: dict[str, Any], source_id: str) -> dict[str, Any]:
    for source in lock["sources"]:
        if source.get("id") == source_id:
            return source
    raise ResolverError(f"core lock is missing {source_id}")


def _replace_source(
    source: dict[str, Any],
    *,
    release: dict[str, Any],
    repository: str,
    asset_name: str,
    timeout: float,
) -> dict[str, Any]:
    tag = str(release.get("tag_name") or "")
    asset = select_exact_asset(release, repository=repository, asset_name=asset_name)
    url = str(asset.get("browser_download_url") or "")
    digest = asset_digest(
        release,
        asset,
        repository=repository,
        timeout=timeout,
    )
    size = download_and_verify(url, digest, timeout=max(timeout, 120.0))
    api_size = int(asset["size"])
    if size != api_size:
        raise ResolverError(
            f"downloaded size mismatch for {asset_name}: expected {api_size}, got {size}"
        )

    updated = copy.deepcopy(source)
    updated["version"] = tag
    updated["archive"] = asset_name
    updated["url"] = url
    updated["sha256"] = digest
    updated["repository"] = repository
    updated["channel"] = "stable"
    updated["release_tag"] = tag
    updated["release_prerelease"] = False
    updated["asset_name"] = asset_name
    updated["asset_size"] = int(asset["size"])
    return updated


def resolve_lock(lock: dict[str, Any], *, timeout: float = 30.0) -> dict[str, Any]:
    """Resolve both stable sources while preserving all other lock entries."""

    _validate_lock(lock)
    candidate = copy.deepcopy(lock)
    xray_release = select_stable_xray(
        [github_latest_release(XRAY_REPOSITORY, timeout=timeout)]
    )
    singbox_release = select_stable_singbox(
        [github_latest_release(SINGBOX_REPOSITORY, timeout=timeout)]
    )

    xray_source = _source_by_id(candidate, "xray-core")
    singbox_source = _source_by_id(candidate, "sing-box-extended")
    replacement_xray = _replace_source(
        xray_source,
        release=xray_release,
        repository=XRAY_REPOSITORY,
        asset_name=XRAY_ASSET_NAME,
        timeout=timeout,
    )
    singbox_tag = str(singbox_release.get("tag_name") or "")
    singbox_asset_name = f"sing-box-{singbox_tag.lstrip('v')}-windows-amd64-purego.zip"
    replacement_singbox = _replace_source(
        singbox_source,
        release=singbox_release,
        repository=SINGBOX_REPOSITORY,
        asset_name=singbox_asset_name,
        timeout=timeout,
    )

    for index, source in enumerate(candidate["sources"]):
        if source.get("id") == "xray-core":
            candidate["sources"][index] = replacement_xray
        elif source.get("id") == "sing-box-extended":
            candidate["sources"][index] = replacement_singbox
    return candidate


def lock_text(lock: dict[str, Any]) -> str:
    # Keep the repository's compact two-field file mappings while using a
    # deterministic JSON serializer for every other field.  This avoids
    # reformatting unrelated sources when --write changes one core pin.
    text = json.dumps(lock, ensure_ascii=False, indent=2)
    text = _FILE_MAPPING_RE.sub(
        lambda match: f'{{ "match": {match.group(1)}, "target": {match.group(2)} }}',
        text,
    )
    return text + "\n"


def atomic_write_lock(path: Path, lock: dict[str, Any]) -> None:
    """Write a lock by same-directory fsync + replace, never delete-first."""

    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as output:
            fd = -1
            output.write(lock_text(lock))
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        try:
            directory_fd = os.open(path.parent, os.O_RDONLY)
        except OSError:
            directory_fd = -1
        if directory_fd >= 0:
            try:
                try:
                    os.fsync(directory_fd)
                except OSError:
                    # Directory fsync is unavailable on some Windows filesystems.
                    # The file itself was already flushed before os.replace;
                    # do not report failure after the atomic replacement succeeded.
                    pass
            finally:
                os.close(directory_fd)
    except Exception:
        if fd >= 0:
            os.close(fd)
        raise
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _source_summary(lock: dict[str, Any]) -> list[str]:
    summaries: list[str] = []
    for source_id in ("xray-core", "sing-box-extended"):
        source = _source_by_id(lock, source_id)
        summaries.append(f"{source_id}: {source['version']} sha256={source['sha256']}")
    return summaries


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Resolve the latest stable Xray and extended sing-box Windows assets "
            "and optionally atomically update the pinned core lock."
        )
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="resolve and verify without writing")
    mode.add_argument(
        "--write",
        action="store_true",
        help="resolve, verify, and atomically replace the lock",
    )
    parser.add_argument("--lock-file", type=Path, default=DEFAULT_LOCK_PATH)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument(
        "--require-current",
        action="store_true",
        help="with --check, return an error when the verified stable lock differs",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        current = read_lock(args.lock_file)
        candidate = resolve_lock(current, timeout=args.timeout)
        print("Resolved stable core sources:")
        for summary in _source_summary(candidate):
            print(f"  {summary}")
        if args.check:
            if candidate == current:
                print("Core lock is already up to date.")
            else:
                print("Core lock update is available; no files were written.")
                if args.require_current:
                    return 2
            return 0
        if candidate == current:
            print("Core lock is already up to date; no files were written.")
            return 0
        atomic_write_lock(args.lock_file, candidate)
        print(f"Updated core lock atomically: {args.lock_file}")
        return 0
    except (ResolverError, OSError) as exc:
        print(f"core resolver error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
