#!/usr/bin/env python3
"""One-command Zapret KVN Windows stable release orchestrator."""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import json
import mimetypes
import os
import re
import stat
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
CONSTANTS_PATH = ROOT / "xray_fluent" / "constants.py"
GEOIP_LOCK_PATH = ROOT / "scripts" / "geoip-lock.json"
CORE_LOCK_PATH = ROOT / "scripts" / "core-lock.windows-x64.json"
CORE_RESOLVER_PATH = ROOT / "scripts" / "resolve_core_versions.py"
STATE_PATH = ROOT / ".git" / "zapret-kvn-release-state.json"
LAST_RESULT_PATH = ROOT / ".git" / "zapret-kvn-release-last.json"
WINDOWS_HOST = os.getenv("ZAPRETKVN_WINDOWS_REMOTE_HOST", "win10")
WINDOWS_ROOT = os.getenv(
    "ZAPRETKVN_WINDOWS_RELEASE_ROOT",
    r"C:\Users\privacy\ZapretKVN-local-release",
)
WINDOWS_SCP_ROOT = WINDOWS_ROOT.replace("\\", "/")
RELEASE_ROOT = Path(
    os.getenv("ZAPRETKVN_RELEASE_ROOT", "/home/codex-pve/releases/zapret-kvn")
)
FORGEJO_BASE = os.getenv("FORGEJO_URL", "https://git.zapret.moe").rstrip("/")
FORGEJO_REPO = os.getenv("ZAPRETKVN_FORGEJO_REPO", "zapretkvn/zapret-kvn")
FORGEJO_TOKEN_PATH = Path(
    os.getenv(
        "ZAPRETKVN_FORGEJO_TOKEN",
        "/home/codex-pve/.config/forgejo/zapret-kvn-release-token",
    )
)
PUBLISHER_PYTHON = Path("/home/codex-pve/zapretgpt/.venv/bin/python")
PUBLISHER_SYNC = Path("/home/codex-pve/zapretgpt/zapretkvn_publisher.py")
PUBLISHER_COMMAND = Path(
    "/home/codex-pve/zapretgpt/scripts/publish_zapretkvn_stable.py"
)
PUBLISHER_STATE = Path(
    "/home/codex-pve/zapretgpt/data/zapretkvn_publisher_state.json"
)
EXPECTED_ASSET_NAMES = (
    "ZapretKVN-v{version}-windows-x64.exe",
    "ZapretKVN-v{version}-windows-x64.zip",
    "ZapretKVN-v{version}-windows-x64.zip.sha256",
    "ZapretKVN-v{version}-windows-x64.7z",
    "ZapretKVN-cores-v{version}-windows-x64.7z",
)
PHASES = (
    "source_prepared",
    "dev_verified",
    "stable_verified",
    "assets_verified",
    "tag_pushed",
    "draft_created",
    "assets_uploaded",
    "release_published",
    "telegram_published",
    "complete",
)


class ReleaseError(RuntimeError):
    pass


def log(message: str) -> None:
    print(f"[release] {message}", flush=True)


def run(
    args: Iterable[str | os.PathLike[str]],
    *,
    cwd: Path = ROOT,
    capture: bool = False,
    timeout: int | None = None,
) -> subprocess.CompletedProcess[str]:
    command = [str(value) for value in args]
    log("+ " + " ".join(command))
    return subprocess.run(
        command,
        cwd=cwd,
        check=True,
        text=True,
        capture_output=capture,
        timeout=timeout,
    )


def output(args: Iterable[str | os.PathLike[str]], *, cwd: Path = ROOT) -> str:
    return run(args, cwd=cwd, capture=True).stdout.strip()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def parse_version(value: str) -> tuple[int, int, int]:
    match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", value.strip())
    if match is None:
        raise ReleaseError(f"invalid stable version: {value}")
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def version_text(parts: tuple[int, int, int]) -> str:
    return ".".join(str(part) for part in parts)


def latest_stable_tag() -> str:
    tags = output(["git", "tag", "--list", "v[0-9]*.[0-9]*.[0-9]*"]).splitlines()
    parsed: list[tuple[tuple[int, int, int], str]] = []
    for tag in tags:
        if not tag.strip():
            continue
        try:
            parsed.append((parse_version(tag), tag))
        except ReleaseError:
            # The Git glob also matches prerelease suffixes. Stable publication
            # must derive its next version from exact x.y.z tags only.
            continue
    if not parsed:
        raise ReleaseError("no stable Git tag found")
    return max(parsed)[1]


def next_patch(tag: str) -> str:
    major, minor, patch = parse_version(tag)
    return version_text((major, minor, patch + 1))


def next_minor(tag: str) -> str:
    major, minor, _patch = parse_version(tag)
    return version_text((major, minor + 1, 0))


def validate_next_stable_version(latest_tag: str, requested: str | None) -> str:
    patch_version = next_patch(latest_tag)
    version = requested or patch_version
    allowed = {patch_version, next_minor(latest_tag)}
    if version not in allowed:
        raise ReleaseError(
            "next stable must be the next patch "
            f"({patch_version}) or explicit next minor ({next_minor(latest_tag)}), not {version}"
        )
    return version


def current_app_version() -> str:
    source = CONSTANTS_PATH.read_text(encoding="utf-8")
    match = re.search(r'^APP_VERSION\s*=\s*"(\d+\.\d+\.\d+)"\s*$', source, re.M)
    if match is None:
        raise ReleaseError("APP_VERSION assignment not found")
    return match.group(1)


def set_app_version(version: str) -> None:
    source = CONSTANTS_PATH.read_text(encoding="utf-8")
    updated, count = re.subn(
        r'^APP_VERSION\s*=\s*"\d+\.\d+\.\d+"\s*$',
        f'APP_VERSION = "{version}"',
        source,
        count=1,
        flags=re.M,
    )
    if count != 1:
        raise ReleaseError("could not update APP_VERSION exactly once")
    CONSTANTS_PATH.write_text(updated, encoding="utf-8")


def normalize_changes(values: list[str], *, allow_empty: bool = False) -> list[str]:
    changes: list[str] = []
    for value in values:
        for item in value.split(";"):
            normalized = " ".join(item.split()).strip(" -•\t")
            if normalized:
                changes.append(normalized)
    if not changes and allow_empty:
        return []
    if not 1 <= len(changes) <= 6:
        raise ReleaseError("changelog must contain 1 to 6 items")
    if any(len(item) > 180 for item in changes):
        raise ReleaseError("each changelog item must be at most 180 characters")
    if len("; ".join(changes)) > 700:
        raise ReleaseError("changelog must be at most 700 characters")
    return changes


def phase_index(state: dict[str, Any]) -> int:
    phase = state.get("phase", "")
    return PHASES.index(phase) if phase in PHASES else -1


def phase_done(state: dict[str, Any], phase: str) -> bool:
    return phase_index(state) >= PHASES.index(phase)


def mark_phase(state: dict[str, Any], phase: str, **updates: Any) -> None:
    if phase not in PHASES:
        raise ReleaseError(f"unknown release phase: {phase}")
    state.update(updates)
    state["phase"] = phase
    atomic_json(STATE_PATH, state)
    log(f"phase complete: {phase}")


def require_clean_main() -> None:
    if output(["git", "branch", "--show-current"]) != "main":
        raise ReleaseError("stable release must run on main")
    status = output(["git", "status", "--porcelain=v1", "--untracked-files=all"])
    if status:
        raise ReleaseError("working tree must be clean before starting the release:\n" + status)


def refresh_stable_core_lock(*, write: bool) -> None:
    """Resolve exact Windows cores and routing data before source is pinned.

    The online resolver is the only moving boundary.  Once it has verified the
    core bytes, captured one immutable runetfreedom snapshot, and atomically
    updated the lock, every Windows build remains fully lock-driven and
    reproducible from the release commit.
    """

    if not CORE_RESOLVER_PATH.is_file():
        raise ReleaseError(f"core resolver is missing: {CORE_RESOLVER_PATH}")
    command = [
        sys.executable,
        str(CORE_RESOLVER_PATH.relative_to(ROOT)),
        "--write" if write else "--check",
    ]
    if not write:
        command.append("--require-current")
    else:
        command.append("--update-runtime")
    run(command)


def refresh_stable_geoip_lock(*, write: bool) -> None:
    python = sys.executable
    if write:
        import importlib.util
        if importlib.util.find_spec("maxminddb") is None:
            environment = ROOT / ".cache" / "geoip-tools"
            python_path = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
            if not python_path.exists():
                run([sys.executable, "-m", "venv", str(environment)])
            run([str(python_path), "-m", "pip", "install", "maxminddb==3.1.1"])
            python = str(python_path)
    run([python, "scripts/prepare_geoip.py", "--refresh" if write else "--check"])


def prepare_source(version: str) -> str:
    require_clean_main()
    run(["git", "fetch", "origin", "main", "--tags"])
    local_head = output(["git", "rev-parse", "HEAD"])
    origin_main = output(["git", "rev-parse", "origin/main"])
    ancestor = subprocess.run(
        ["git", "merge-base", "--is-ancestor", origin_main, local_head],
        cwd=ROOT,
    )
    if ancestor.returncode != 0:
        raise ReleaseError("local main does not contain origin/main; reconcile it first")
    previous_geoip = GEOIP_LOCK_PATH.read_bytes()
    refresh_stable_geoip_lock(write=True)
    try:
        freeze_path = ROOT / "core-release-freeze.json"
        freeze = json.loads(freeze_path.read_text(encoding="utf-8")) if freeze_path.exists() else None
        if freeze is not None and freeze.get("releases", {}).get("windows") == version:
            if __package__:
                from .check_core_release_freeze import verify
            else:
                from check_core_release_freeze import verify
            verify(ROOT, "windows", version)
            log("using the coordinated core freeze; no second upstream version selection")
        else:
            refresh_stable_core_lock(write=True)
    except Exception:
        GEOIP_LOCK_PATH.write_bytes(previous_geoip)
        raise
    set_app_version(version)
    run(["git", "diff", "--check"])
    run([sys.executable, "-m", "compileall", "-q", "xray_fluent", "tests"])
    release_paths = [
        str(CONSTANTS_PATH.relative_to(ROOT)),
        str(CORE_LOCK_PATH.relative_to(ROOT)),
        str(GEOIP_LOCK_PATH.relative_to(ROOT)),
        "runtime/amnezia/go.mod",
        "runtime/amnezia/go.sum",
    ]
    run(["git", "add", "--", *release_paths])
    staged = output(["git", "diff", "--cached", "--name-only"]).splitlines()
    allowed = set(release_paths)
    if str(CONSTANTS_PATH.relative_to(ROOT)) not in staged or not set(staged).issubset(allowed):
        raise ReleaseError(f"unexpected staged release files: {staged}")
    run(["git", "commit", "-m", f"release: prepare v{version}"])
    run(["git", "push", "origin", "main"])
    commit = output(["git", "rev-parse", "HEAD"])
    if output(["git", "rev-parse", "origin/main"]) != commit:
        raise ReleaseError("origin/main did not advance to the release commit")
    return commit


def powershell_bootstrap(mode: str, commit: str, version: str) -> None:
    release_dir = rf"{WINDOWS_ROOT}\.cache\release\v{version}"
    manifest = rf"{release_dir}\{mode}-manifest.json"
    # The gate runs as a child process with process-level output redirection
    # to remote log files, keeping the ssh channel down to bootstrap lines
    # plus a log tail. Two failure classes forced this shape: PowerShell 5.1
    # over non-tty ssh wraps host output in CLIXML records and a long verbose
    # stream (pip + unittest -v + PyInstaller) deadlocked that channel
    # mid-gate; and PowerShell-level stream redirection (*>) converts native
    # stderr (e.g. "git: warning: redirecting") into terminating
    # NativeCommandError under the gate's own ErrorActionPreference=Stop.
    # Start-Process redirection is invisible to the child's PowerShell, so
    # native stderr lands in the file without conversion.
    log_file = rf"{release_dir}\{mode}-gate.log"
    err_file = rf"{release_dir}\{mode}-gate.err.log"
    gate_args = (
        "'-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass',"
        "'-File','.\\scripts\\release_windows_gate.ps1',"
        f"'-Mode','{mode}','-Commit','{commit}','-Version','{version}',"
        f"'-RepoRoot','{WINDOWS_ROOT}','-ManifestPath','{manifest}'"
    )
    command = (
        "$ErrorActionPreference='Stop';"
        f"$root='{WINDOWS_ROOT}';"
        "Set-Location -LiteralPath $root;"
        "git fetch origin main --tags;"
        f"git switch --detach {commit};"
        "if ($LASTEXITCODE -ne 0) { throw 'git switch failed' };"
        f"New-Item -ItemType Directory -Force -Path '{release_dir}' | Out-Null;"
        f"$gate = Start-Process -FilePath 'powershell' -ArgumentList @({gate_args}) "
        "-WorkingDirectory $root -NoNewWindow -Wait -PassThru "
        f"-RedirectStandardOutput '{log_file}' -RedirectStandardError '{err_file}';"
        "if ($gate.ExitCode -ne 0) { "
        "Write-Output ('GATE-FAILED exit=' + $gate.ExitCode);"
        f"Get-Content -LiteralPath '{log_file}' -Tail 40;"
        f"if (Test-Path -LiteralPath '{err_file}') "
        f"{{ Get-Content -LiteralPath '{err_file}' -Tail 40 }};"
        "exit 1 };"
        "Write-Output 'GATE-DONE';"
        f"Get-Content -LiteralPath '{log_file}' -Tail 3"
    )
    # Windows OpenSSH runs the space-joined argv through cmd.exe, which splits
    # an unquoted payload at '&' — the gate invocation after 'git switch' never
    # reached PowerShell. -EncodedCommand (base64 of UTF-16LE) is immune to
    # remote-shell quoting entirely.
    encoded = base64.b64encode(command.encode("utf-16-le")).decode("ascii")
    run(
        [
            "ssh",
            WINDOWS_HOST,
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-EncodedCommand",
            encoded,
        ],
        timeout=3600,
    )


def remote_release_path(version: str, name: str) -> str:
    return f"{WINDOWS_HOST}:{WINDOWS_SCP_ROOT}/dist/{name}"


def copy_manifest(mode: str, version: str, destination: Path) -> dict[str, Any]:
    remote = (
        f"{WINDOWS_HOST}:{WINDOWS_SCP_ROOT}/.cache/release/"
        f"v{version}/{mode}-manifest.json"
    )
    run(["scp", "-q", remote, destination], timeout=120)
    return read_json(destination)


def verify_gate_manifest(
    manifest: dict[str, Any], mode: str, version: str, commit: str
) -> None:
    expected = {"schema": 1, "mode": mode, "version": version, "commit": commit}
    for key, value in expected.items():
        if manifest.get(key) != value:
            raise ReleaseError(f"{mode} manifest mismatch for {key}")
    if int(manifest.get("templates_verified") or 0) <= 0:
        raise ReleaseError(f"{mode} manifest did not verify templates")
    geoip = manifest.get("geoip") or {}
    expected_geoip = read_json(GEOIP_LOCK_PATH)
    if any(geoip.get(key) != expected_geoip.get(key) for key in ("version", "sha256", "size")):
        raise ReleaseError(f"{mode} manifest GeoIP does not match release lock")
    core = manifest.get("core") or {}
    for digest_key in ("lock_sha256", "manifest_sha256"):
        if not re.fullmatch(r"[0-9a-f]{64}", str(core.get(digest_key) or "")):
            raise ReleaseError(f"{mode} manifest contains an invalid core {digest_key}")
    core_sources = core.get("sources") or []
    if {str(item.get("id")) for item in core_sources} != {
        "xray-core",
        "sing-box-extended",
        "hysteria",
        "amnezia",
    }:
        raise ReleaseError(f"{mode} manifest core source set mismatch")
    for source in core_sources:
        approved_amnezia = source.get("id") == "amnezia" and source.get("repository") == "amnezia-vpn/amneziawg-go" and source.get("channel") == "official-tags"
        if source.get("id") == "amnezia" and not approved_amnezia:
            raise ReleaseError(f"{mode} manifest contains an unapproved Amnezia source")
        if not approved_amnezia and (source.get("channel") != "stable" or source.get("release_prerelease") is not False):
            raise ReleaseError(f"{mode} manifest contains a non-stable core source")
        if not re.fullmatch(r"[0-9a-f]{64}", str(source.get("archive_sha256") or "")):
            raise ReleaseError(f"{mode} manifest contains an invalid core archive digest")
        if int(source.get("asset_size") or 0) <= 0:
            raise ReleaseError(f"{mode} manifest contains an invalid core asset size")
    executable = manifest.get("executable") or {}
    if int(executable.get("size") or 0) <= 0 or not re.fullmatch(
        r"[0-9a-f]{64}", str(executable.get("sha256") or "")
    ):
        raise ReleaseError(f"{mode} manifest contains an invalid executable")


def collect_assets(version: str, commit: str) -> tuple[Path, dict[str, Any]]:
    destination = RELEASE_ROOT / f"v{version}"
    destination.mkdir(parents=True, exist_ok=True)
    manifest_path = destination / "stable-manifest.json"
    manifest = copy_manifest("stable", version, manifest_path)
    verify_gate_manifest(manifest, "stable", version, commit)
    assets = manifest.get("assets") or []
    expected_names = {name.format(version=version) for name in EXPECTED_ASSET_NAMES}
    if {str(item.get("name")) for item in assets} != expected_names:
        raise ReleaseError("stable manifest asset set mismatch")
    for item in assets:
        name = str(item["name"])
        local = destination / name
        run(["scp", "-q", remote_release_path(version, name), local], timeout=1200)
        if local.stat().st_size != int(item["size"]) or sha256(local) != item["sha256"]:
            raise ReleaseError(f"copied asset mismatch: {name}")
    checksum_name = f"ZapretKVN-v{version}-windows-x64.zip.sha256"
    zip_name = f"ZapretKVN-v{version}-windows-x64.zip"
    expected_zip = (destination / checksum_name).read_text(encoding="ascii").strip()
    if not re.fullmatch(r"[0-9a-f]{64}", expected_zip):
        raise ReleaseError("ZIP checksum file has an invalid format")
    if sha256(destination / zip_name) != expected_zip:
        raise ReleaseError("ZIP checksum mismatch after Windows transfer")
    return destination, manifest


@dataclass
class Forgejo:
    token: str

    @classmethod
    def load(cls) -> "Forgejo":
        mode = stat.S_IMODE(FORGEJO_TOKEN_PATH.stat().st_mode)
        if mode != 0o600:
            raise ReleaseError(f"Forgejo token mode must be 0600, got {mode:o}")
        return cls(FORGEJO_TOKEN_PATH.read_text(encoding="utf-8").strip())

    @property
    def api(self) -> str:
        return f"{FORGEJO_BASE}/api/v1/repos/{FORGEJO_REPO}"

    def request(
        self,
        method: str,
        url: str,
        payload: dict[str, Any] | None = None,
        *,
        allow_404: bool = False,
    ) -> dict[str, Any] | None:
        data = json.dumps(payload).encode() if payload is not None else None
        request = urllib.request.Request(
            url,
            data=data,
            headers={
                "Authorization": f"token {self.token}",
                "Content-Type": "application/json",
                "User-Agent": "ZapretKVN-Local-Release/1",
            },
            method=method,
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return json.load(response)
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", "replace")[:500]
            if allow_404 and exc.code == 404:
                return None
            raise ReleaseError(f"Forgejo HTTP {exc.code}: {body}") from None

    def release_by_tag(self, version: str) -> dict[str, Any] | None:
        return self.request(
            "GET", f"{self.api}/releases/tags/v{version}", allow_404=True
        )

    def create_draft(
        self, version: str, commit: str, changes: list[str]
    ) -> dict[str, Any]:
        result = self.request(
            "POST",
            f"{self.api}/releases",
            {
                "tag_name": f"v{version}",
                "target_commitish": commit,
                "name": f"Zapret KVN v{version}",
                "body": "\n".join(f"- {item}" for item in changes),
                "draft": True,
                "prerelease": False,
            },
        )
        assert result is not None
        return result

    def upload_asset(self, release_id: int, path: Path) -> dict[str, Any]:
        parsed = urllib.parse.urlsplit(FORGEJO_BASE)
        if parsed.scheme != "https":
            raise ReleaseError("Forgejo upload requires HTTPS")
        boundary = "----ZapretKVN" + uuid.uuid4().hex
        mime = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        prefix = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="attachment"; filename="{path.name}"\r\n'
            f"Content-Type: {mime}\r\n\r\n"
        ).encode()
        suffix = f"\r\n--{boundary}--\r\n".encode()
        endpoint = (
            f"{parsed.path}/api/v1/repos/{FORGEJO_REPO}/releases/{release_id}/assets"
            f"?name={urllib.parse.quote(path.name)}"
        )
        connection = http.client.HTTPSConnection(parsed.hostname, parsed.port, timeout=600)
        connection.putrequest("POST", endpoint)
        connection.putheader("Authorization", f"token {self.token}")
        connection.putheader("Content-Type", f"multipart/form-data; boundary={boundary}")
        connection.putheader(
            "Content-Length", str(len(prefix) + path.stat().st_size + len(suffix))
        )
        connection.endheaders()
        connection.send(prefix)
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                connection.send(chunk)
        connection.send(suffix)
        response = connection.getresponse()
        body = response.read()
        connection.close()
        if response.status not in {200, 201}:
            raise ReleaseError(
                f"Forgejo asset upload failed for {path.name}: HTTP {response.status}"
            )
        return json.loads(body)

    def download_hash(self, url: str) -> tuple[int, str]:
        request = urllib.request.Request(
            url,
            headers={
                "Authorization": f"token {self.token}",
                "User-Agent": "ZapretKVN-Local-Release/1",
            },
        )
        digest = hashlib.sha256()
        size = 0
        with urllib.request.urlopen(request, timeout=600) as response:
            while chunk := response.read(1024 * 1024):
                digest.update(chunk)
                size += len(chunk)
        return size, digest.hexdigest()

    def publish(self, release_id: int) -> dict[str, Any]:
        result = self.request(
            "PATCH",
            f"{self.api}/releases/{release_id}",
            {"draft": False, "prerelease": False},
        )
        assert result is not None
        return result

    def latest(self) -> dict[str, Any]:
        result = self.request("GET", f"{self.api}/releases/latest")
        assert result is not None
        return result


def ensure_tag(version: str, commit: str) -> None:
    tag = f"v{version}"
    existing = subprocess.run(
        ["git", "rev-parse", "-q", "--verify", f"refs/tags/{tag}^{{commit}}"],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )
    if existing.returncode == 0:
        if existing.stdout.strip() != commit:
            raise ReleaseError(f"existing {tag} points to another commit")
    else:
        run(["git", "tag", "-a", tag, commit, "-m", f"Zapret KVN {tag}"])
    remote_lines = output(
        [
            "git",
            "ls-remote",
            "--tags",
            "origin",
            f"refs/tags/{tag}",
            f"refs/tags/{tag}^{{}}",
        ]
    ).splitlines()
    if not remote_lines:
        run(["git", "push", "origin", tag])
        return
    peeled = [line.split()[0] for line in remote_lines if line.endswith("^{}")]
    targets = peeled or [line.split()[0] for line in remote_lines]
    if targets != [commit]:
        raise ReleaseError(f"remote {tag} points to another commit")


def verify_and_upload_assets(
    forgejo: Forgejo,
    release: dict[str, Any],
    directory: Path,
    manifest: dict[str, Any],
) -> dict[str, Any]:
    release_id = int(release["id"])
    expected = {item["name"]: item for item in manifest["assets"]}
    remote = {item["name"]: item for item in release.get("assets") or []}
    extras = set(remote) - set(expected)
    if extras:
        raise ReleaseError(f"Forgejo draft contains unexpected assets: {sorted(extras)}")
    for name, item in expected.items():
        local = directory / name
        asset = remote.get(name)
        if asset is None:
            log(f"uploading {name}")
            asset = forgejo.upload_asset(release_id, local)
            remote[name] = asset
        if int(asset.get("size") or 0) != int(item["size"]):
            raise ReleaseError(f"Forgejo size mismatch: {name}")
        size, digest = forgejo.download_hash(asset["browser_download_url"])
        if size != int(item["size"]) or digest != item["sha256"]:
            raise ReleaseError(f"Forgejo content mismatch: {name}")
        log(f"verified remote asset {name}")
    refreshed = forgejo.release_by_tag(str(release["tag_name"]).removeprefix("v"))
    if refreshed is None:
        raise ReleaseError("Forgejo draft disappeared")
    if {item["name"] for item in refreshed.get("assets") or []} != set(expected):
        raise ReleaseError("Forgejo remote asset set mismatch")
    return refreshed


def verify_published_release(
    forgejo: Forgejo,
    release: dict[str, Any],
    version: str,
    commit: str,
    manifest: dict[str, Any],
) -> None:
    expected_names = {item["name"] for item in manifest["assets"]}
    if release.get("tag_name") != f"v{version}":
        raise ReleaseError("published Forgejo tag mismatch")
    if release.get("draft") or release.get("prerelease"):
        raise ReleaseError("Forgejo release is not stable")
    if release.get("target_commitish") != commit:
        raise ReleaseError("Forgejo release commit mismatch")
    if {item["name"] for item in release.get("assets") or []} != expected_names:
        raise ReleaseError("published Forgejo asset set mismatch")
    if forgejo.latest().get("tag_name") != f"v{version}":
        raise ReleaseError("published release is not Latest")


def telegram_has_version(version: str) -> bool:
    if not PUBLISHER_STATE.is_file():
        return False
    state = read_json(PUBLISHER_STATE)
    return f"windows|v{version}|ZapretKVN-v{version}-windows-x64.exe|" in json.dumps(
        state.get("published", {}), ensure_ascii=False
    )


def publish_telegram(version: str, changes: list[str]) -> None:
    if telegram_has_version(version):
        log(f"Telegram already contains v{version}")
        return
    run([PUBLISHER_PYTHON, PUBLISHER_SYNC, "--sync-windows"], timeout=1200)
    if not PUBLISHER_COMMAND.is_file():
        raise ReleaseError(f"Telegram publisher command is missing: {PUBLISHER_COMMAND}")
    arguments: list[str | os.PathLike[str]] = [
        PUBLISHER_PYTHON,
        PUBLISHER_COMMAND,
        "windows",
        version,
    ]
    for item in changes:
        arguments.extend(("--change", item))
    run(arguments, timeout=1800)
    if not telegram_has_version(version):
        raise ReleaseError("Telegram publisher did not record the stable installer")


def preflight(version: str | None, changes: list[str], telegram: bool) -> str:
    latest = latest_stable_tag()
    version = validate_next_stable_version(latest, version)
    if current_app_version() != latest.removeprefix("v"):
        raise ReleaseError("APP_VERSION must match the latest stable before a fresh release")
    refresh_stable_core_lock(write=False)
    refresh_stable_geoip_lock(write=False)
    Forgejo.load()
    run(["ssh", WINDOWS_HOST, "powershell", "-NoProfile", "-Command", "$PSVersionTable.PSVersion.ToString()"], capture=True, timeout=30)
    if telegram:
        if not PUBLISHER_COMMAND.is_file():
            raise ReleaseError("ZapretGPT stable publisher helper is not installed")
        socket = Path("/home/codex-pve/zapretgpt/data/zapretgpt-admin.sock")
        if not socket.exists() or not stat.S_ISSOCK(socket.stat().st_mode):
            raise ReleaseError("ZapretGPT admin Unix socket is unavailable")
    log(
        json.dumps(
            {"status": "ready", "version": version, "telegram": telegram, "changes": changes},
            ensure_ascii=False,
        )
    )
    return version


def load_or_create_state(args: argparse.Namespace, changes: list[str]) -> dict[str, Any]:
    if STATE_PATH.is_file():
        state = read_json(STATE_PATH)
        if state.get("phase") == "complete":
            os.replace(STATE_PATH, LAST_RESULT_PATH)
            raise ReleaseError(
                "the previous release was already complete; run the command again to start the next patch"
            )
        else:
            if args.version and args.version != state.get("version"):
                raise ReleaseError("--version conflicts with the active release state")
            if changes and changes != state.get("changes"):
                raise ReleaseError("changelog conflicts with the active release state")
            log(f"resuming v{state['version']} from {state.get('phase', 'start')}")
            return state
    tag = latest_stable_tag()
    version = validate_next_stable_version(tag, args.version)
    if current_app_version() != tag.removeprefix("v"):
        raise ReleaseError(
            "APP_VERSION must match the latest stable before a fresh release"
        )
    if not changes:
        raise ReleaseError("at least one --change or --changes value is required")
    state = {
        "schema": 1,
        "phase": "",
        "version": version,
        "previous_tag": tag,
        "changes": changes,
        "telegram": not args.no_telegram,
    }
    atomic_json(STATE_PATH, state)
    return state


def execute(args: argparse.Namespace) -> dict[str, Any]:
    changes = normalize_changes(
        (args.change or []) + ([args.changes] if args.changes else []),
        allow_empty=not args.preflight,
    )
    # Refresh release facts before deriving a version or persisting resume state.
    # This also guarantees that a failed fresh invocation cannot leave a state
    # file behind merely because the worktree was dirty.
    require_clean_main()
    run(["git", "fetch", "origin", "main", "--tags"])
    if args.preflight:
        version = preflight(args.version, changes, not args.no_telegram)
        return {"status": "ready", "version": version}

    state = load_or_create_state(args, changes)
    version = state["version"]
    changes = list(state["changes"])
    telegram = bool(state["telegram"])
    forgejo = Forgejo.load()

    if not phase_done(state, "source_prepared"):
        if forgejo.release_by_tag(version) is not None:
            raise ReleaseError(f"Forgejo release v{version} already exists")
        if output(["git", "ls-remote", "--tags", "origin", f"refs/tags/v{version}"]):
            raise ReleaseError(f"remote tag v{version} already exists")
        if current_app_version() == version:
            require_clean_main()
            run(["git", "fetch", "origin", "main", "--tags"])
            commit = output(["git", "rev-parse", "HEAD"])
            if output(["git", "rev-parse", "origin/main"]) != commit:
                raise ReleaseError(
                    "APP_VERSION already matches the candidate but HEAD is not origin/main"
                )
            log(f"recovered already-pushed release source {commit}")
        else:
            commit = prepare_source(version)
        mark_phase(state, "source_prepared", commit=commit)
    elif not phase_done(state, "tag_pushed"):
        # A gate can fail because of the release source itself, and the only
        # way to fix that is a new commit.  Nothing immutable exists before the
        # tag, so re-pin to the pushed HEAD and replay the gates against it;
        # otherwise the release would be stuck rebuilding the broken commit,
        # with a fresh start blocked by the already-bumped APP_VERSION.
        require_clean_main()
        head = output(["git", "rev-parse", "HEAD"])
        if head != state["commit"]:
            if current_app_version() != version:
                raise ReleaseError(
                    "APP_VERSION no longer matches the active release version"
                )
            if output(["git", "rev-parse", "origin/main"]) != head:
                raise ReleaseError("push the source fix to origin/main before resuming")
            if output(["git", "ls-remote", "--tags", "origin", f"refs/tags/v{version}"]):
                raise ReleaseError(f"remote tag v{version} already exists")
            if forgejo.release_by_tag(version) is not None:
                raise ReleaseError(f"Forgejo release v{version} already exists")
            log(f"re-pinning release source to {head} after a source fix")
            mark_phase(state, "source_prepared", commit=head)
    commit = state["commit"]

    release_dir = RELEASE_ROOT / f"v{version}"
    release_dir.mkdir(parents=True, exist_ok=True)
    if not phase_done(state, "dev_verified"):
        powershell_bootstrap("dev", commit, version)
        manifest = copy_manifest("dev", version, release_dir / "dev-manifest.json")
        verify_gate_manifest(manifest, "dev", version, commit)
        mark_phase(state, "dev_verified")

    if not phase_done(state, "stable_verified"):
        if forgejo.release_by_tag(version) is not None:
            raise ReleaseError(f"Forgejo release v{version} appeared before stable build")
        powershell_bootstrap("stable", commit, version)
        mark_phase(state, "stable_verified")

    if not phase_done(state, "assets_verified"):
        release_dir, manifest = collect_assets(version, commit)
        mark_phase(state, "assets_verified", manifest=str(release_dir / "stable-manifest.json"))
    manifest = read_json(Path(state["manifest"]))
    verify_gate_manifest(manifest, "stable", version, commit)

    if not phase_done(state, "tag_pushed"):
        ensure_tag(version, commit)
        mark_phase(state, "tag_pushed")

    release = forgejo.release_by_tag(version)
    if not phase_done(state, "draft_created"):
        if release is None:
            release = forgejo.create_draft(version, commit, changes)
        if not release.get("draft") or release.get("prerelease"):
            raise ReleaseError("existing Forgejo release is not the expected draft")
        mark_phase(state, "draft_created", release_id=int(release["id"]))
    release = forgejo.release_by_tag(version)
    if release is None:
        raise ReleaseError("Forgejo release is missing")

    if not phase_done(state, "assets_uploaded"):
        release = verify_and_upload_assets(forgejo, release, release_dir, manifest)
        mark_phase(state, "assets_uploaded")

    if not phase_done(state, "release_published"):
        if release.get("draft"):
            release = forgejo.publish(int(release["id"]))
        verify_published_release(forgejo, release, version, commit, manifest)
        mark_phase(state, "release_published", release_url=release["html_url"])
    else:
        verify_published_release(forgejo, release, version, commit, manifest)

    if telegram and not phase_done(state, "telegram_published"):
        publish_telegram(version, changes)
        mark_phase(state, "telegram_published")
    elif not telegram and not phase_done(state, "telegram_published"):
        mark_phase(state, "telegram_published", telegram_skipped=True)

    run(["git", "fetch", "origin", "main", "--tags"])
    # Follow-up commits on main during the release (e.g. runner fixes) are
    # legitimate: the published artifacts are pinned to the release commit by
    # the immutable tag. Finalization only requires that main still contains
    # the release commit, is synced with origin, and the tree is clean.
    local_head = output(["git", "rev-parse", "HEAD"])
    if local_head != output(["git", "rev-parse", "origin/main"]):
        raise ReleaseError("local main and origin/main diverged during release")
    contains = subprocess.run(
        ["git", "merge-base", "--is-ancestor", commit, local_head], cwd=ROOT
    )
    if contains.returncode != 0:
        raise ReleaseError("main no longer contains the release commit")
    require_clean_main()
    mark_phase(state, "complete")
    os.replace(STATE_PATH, LAST_RESULT_PATH)
    result = {
        "status": "published",
        "version": version,
        "commit": commit,
        "release_url": state["release_url"],
        "telegram": telegram,
        "assets": [item["name"] for item in manifest["assets"]],
    }
    log(json.dumps(result, ensure_ascii=False))
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build, verify and publish one Zapret KVN Windows stable release"
    )
    parser.add_argument(
        "--version",
        help="exact next patch or immediate next minor .0; defaults to the next patch",
    )
    parser.add_argument(
        "--change",
        action="append",
        help="one user-facing changelog item; repeat 1-6 times",
    )
    parser.add_argument(
        "--changes",
        help="semicolon-separated changelog items (alternative to repeated --change)",
    )
    parser.add_argument(
        "--no-telegram",
        action="store_true",
        help="publish Forgejo stable but do not send the installer to Telegram",
    )
    parser.add_argument(
        "--preflight",
        action="store_true",
        help="validate the release environment without changing Git or external state",
    )
    return parser


def main() -> int:
    try:
        execute(build_parser().parse_args())
    except (ReleaseError, OSError, subprocess.SubprocessError) as exc:
        print(f"[release] ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
