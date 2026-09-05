"""
Build XrayFluent portable exe via PyInstaller.

Usage:  python build.py          — full build (clean + compile + pack zip)
        python build.py --no-zip — skip zip creation
        python build.py --clean  — only wipe previous build artefacts

Requires .venv created by setup.bat (or manually).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
import zipfile

ROOT = Path(__file__).resolve().parent
VENV_DIR = ROOT / ".venv"
VENV_PYTHON = VENV_DIR / "Scripts" / "python.exe"
VENV_PIP = VENV_DIR / "Scripts" / "pip.exe"

APP_NAME = "ZapretKVN"

DIST_DIR = ROOT / "dist"
BUILD_DIR = ROOT / "build"
APP_DIR = DIST_DIR / APP_NAME
ZIP_PATH = DIST_DIR / f"{APP_NAME}-portable.zip"

MANIFEST = ROOT / "uac_admin.manifest"
CORE_DIR = ROOT / "core"
ZAPRET_DIR = ROOT / "zapret"
DATA_TEMPLATES_DIR = ROOT / "data" / "templates"
ASSETS_DIR = ROOT / "assets"
APP_ICON = ASSETS_DIR / "app_icon.ico"
TEMPLATE_UPDATE_BUNDLE_NAME = "template-update"
CORE_LOCK_PATH = ROOT / "scripts" / "core-lock.windows-x64.json"
DOWNLOAD_CACHE = ROOT / ".cache" / "core-downloads"
ROUTING_SOURCE_ID = "runetfreedom-routing-data"
ROUTING_ARCHIVE_LIMIT_BYTES = 128 * 1024 * 1024
SINGBOX_RULE_SET_RELATIVE_PATHS = (
    Path("rule-set/geosite-ru-blocked.srs"),
    Path("rule-set/geoip-ru-blocked.srs"),
    Path("rule-set/geosite-category-ru.srs"),
    Path("rule-set/geoip-ru.srs"),
)

# A release build is a payload, not an installed application.  Only these
# directories are allowed to be copied from the source tree into the portable
# application directory.  Runtime state (``data/state.enc``, active configs,
# logs and generated runtime files) belongs to an installed copy and must
# never become part of a new release.
PAYLOAD_TOP_LEVEL_NAMES = frozenset(
    {"ZapretKVN.exe", "_internal", "assets", "core", "data", "zapret"}
)
PAYLOAD_DATA_NAMES = frozenset({"templates"})


def _print(msg: str) -> None:
    print(f"[build] {msg}", flush=True)


def _windows_path(path: Path) -> str:
    """Convert a repo path to a Windows path when running via WSL interop."""
    resolved = path.resolve()
    if os.name == "nt":
        return str(resolved)
    result = subprocess.run(
        ["wslpath", "-w", str(resolved)],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _run(cmd: list[str], **kwargs) -> None:
    _print(f"> {' '.join(cmd)}")
    subprocess.run(cmd, check=True, **kwargs)


def _remove_path_strict(path: Path) -> None:
    """Remove a build path and fail if Windows still has a file locked."""
    if not path.exists() and not path.is_symlink():
        return
    try:
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
        else:
            path.unlink()
    except PermissionError as exc:
        raise RuntimeError(
            f"Cannot remove build path because it is locked: {path}"
        ) from exc


def _copy_tree_strict(src: Path, dst: Path) -> None:
    """Copy a source tree into an empty destination without hiding failures."""
    if not src.is_dir():
        raise FileNotFoundError(f"Build source directory is missing: {src}")
    if dst.exists() or dst.is_symlink():
        raise RuntimeError(f"Build staging destination is not empty: {dst}")
    try:
        shutil.copytree(src, dst)
    except (PermissionError, shutil.Error) as exc:
        raise RuntimeError(
            f"Cannot stage build files because a source or destination is locked: {dst}"
        ) from exc


def assert_clean_payload(app_dir: Path = APP_DIR) -> None:
    """Reject runtime data or unexpected top-level files in a release payload."""
    if not app_dir.is_dir():
        raise RuntimeError(f"Build payload directory is missing: {app_dir}")

    unexpected = sorted(
        path.name for path in app_dir.iterdir() if path.name not in PAYLOAD_TOP_LEVEL_NAMES
    )
    if unexpected:
        raise RuntimeError(
            "Build payload contains unexpected top-level files: "
            + ", ".join(unexpected)
        )

    data_dir = app_dir / "data"
    if not data_dir.is_dir():
        raise RuntimeError(f"Build payload is missing data/templates: {data_dir}")
    unexpected_data = sorted(
        path.name for path in data_dir.iterdir() if path.name not in PAYLOAD_DATA_NAMES
    )
    if unexpected_data:
        raise RuntimeError(
            "Build payload contains runtime data under data/: "
            + ", ".join(unexpected_data)
        )
    if not (data_dir / "templates").is_dir():
        raise RuntimeError(f"Build payload is missing data/templates: {data_dir}")

    core_dir = app_dir / "core"
    missing_rule_sets = [
        relative.as_posix()
        for relative in SINGBOX_RULE_SET_RELATIVE_PATHS
        if not (core_dir / relative).is_file()
        or (core_dir / relative).stat().st_size <= 0
    ]
    if missing_rule_sets:
        raise RuntimeError(
            "Build payload is missing bundled sing-box rule-set files: "
            + ", ".join(missing_rule_sets)
        )


def stage_template_update_bundle(
    source_dir: Path = DATA_TEMPLATES_DIR,
    app_dir: Path = APP_DIR,
) -> Path:
    """Mirror versioned native JSON templates outside preserved data/."""
    destination = app_dir / "assets" / TEMPLATE_UPDATE_BUNDLE_NAME
    _remove_path_strict(destination)
    if source_dir.is_dir():
        _print(f"Staging template update bundle -> {destination}")
        _copy_tree_strict(source_dir, destination)
    return destination


def _routing_source(lock_path: Path) -> dict:
    try:
        payload = json.loads(lock_path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Cannot read routing lock {lock_path}: {exc}") from exc
    sources = payload.get("sources") if isinstance(payload, dict) else None
    matches = [
        source
        for source in sources or []
        if isinstance(source, dict) and source.get("id") == ROUTING_SOURCE_ID
    ]
    if len(matches) != 1:
        raise RuntimeError(f"Core lock must contain exactly one {ROUTING_SOURCE_ID} source")
    return matches[0]


def _download_locked_archive(source: dict, destination: Path) -> None:
    """Share the core-bundle cache; never trust a cached name without its hash."""
    name = str(source.get("archive") or "")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*\.zip", name):
        raise RuntimeError("Routing archive must have a plain ZIP filename")
    expected = str(source.get("sha256") or "").lower()
    if re.fullmatch(r"[0-9a-f]{64}", expected) is None:
        raise RuntimeError("Routing source has no valid SHA-256")
    url = str(source.get("url") or "")
    if not url.startswith("https://github.com/runetfreedom/russia-v2ray-rules-dat/archive/"):
        raise RuntimeError("Routing source URL is outside the approved repository")

    DOWNLOAD_CACHE.mkdir(parents=True, exist_ok=True)
    cached = DOWNLOAD_CACHE / name
    valid = False
    if cached.is_file() and 0 < cached.stat().st_size <= ROUTING_ARCHIVE_LIMIT_BYTES:
        with cached.open("rb") as handle:
            valid = hashlib.file_digest(handle, "sha256").hexdigest() == expected
    if valid:
        _print(f"Routing cache hit: {name}")
    else:
        # Each writer owns its temporary file. Only a complete, verified archive
        # becomes visible to subsequent dev/stable builds.
        with tempfile.NamedTemporaryFile(
            dir=DOWNLOAD_CACHE, prefix=f"{name}.", suffix=".partial", delete=False
        ) as handle:
            partial = Path(handle.name)
        try:
            _fetch_locked_archive(source, partial)
            partial.replace(cached)
        finally:
            partial.unlink(missing_ok=True)
    shutil.copyfile(cached, destination)
    # Also protect against another writer replacing this filename between the
    # cache check and the copy (for example after a lock update).
    with destination.open("rb") as handle:
        actual = hashlib.file_digest(handle, "sha256").hexdigest()
    if actual != expected:
        destination.unlink(missing_ok=True)
        raise RuntimeError("Routing archive SHA-256 changed while copying from cache")


def _fetch_locked_archive(source: dict, destination: Path) -> None:
    url = str(source.get("url") or "")
    expected_sha256 = str(source.get("sha256") or "").lower()
    if not url.startswith("https://github.com/runetfreedom/russia-v2ray-rules-dat/archive/"):
        raise RuntimeError("Routing source URL is outside the approved repository")
    if re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None:
        raise RuntimeError("Routing source has no valid SHA-256")

    request = Request(url, headers={"User-Agent": "ZapretKVN-build/1"})
    digest = hashlib.sha256()
    total = 0
    try:
        with urlopen(request, timeout=120) as response, destination.open("wb") as output:
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > ROUTING_ARCHIVE_LIMIT_BYTES:
                    raise RuntimeError("Routing archive exceeds the build safety limit")
                digest.update(chunk)
                output.write(chunk)
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        raise RuntimeError(f"Cannot download locked routing data: {exc}") from exc
    if total <= 0:
        raise RuntimeError("Locked routing archive is empty")
    actual_sha256 = digest.hexdigest()
    if actual_sha256 != expected_sha256:
        raise RuntimeError(
            "Routing archive SHA-256 mismatch: "
            f"expected {expected_sha256}, got {actual_sha256}"
        )


def stage_singbox_rule_sets(
    lock_path: Path = CORE_LOCK_PATH,
    core_dir: Path | None = None,
) -> Path:
    """Cache the locked snapshot, stage four SRS files, and clean extraction data."""

    source = _routing_source(lock_path)
    destination_root = (core_dir or (APP_DIR / "core")) / "rule-set"
    expected_targets = {relative.as_posix() for relative in SINGBOX_RULE_SET_RELATIVE_PATHS}
    mappings = [
        mapping
        for mapping in source.get("files") or []
        if isinstance(mapping, dict) and str(mapping.get("target") or "") in expected_targets
    ]
    if {str(mapping["target"]) for mapping in mappings} != expected_targets:
        raise RuntimeError("Routing lock does not map every required sing-box rule-set")

    with tempfile.TemporaryDirectory(prefix="zapret-kvn-routing-build-") as temp_name:
        temp_root = Path(temp_name)
        archive_path = temp_root / "routing.zip"
        staged_root = temp_root / "rule-set"
        staged_root.mkdir()
        _print(f"Preparing locked routing data {source.get('version', '')}")
        _download_locked_archive(source, archive_path)
        try:
            with zipfile.ZipFile(archive_path, "r") as archive:
                names = [name.replace("\\", "/") for name in archive.namelist()]
                for mapping in mappings:
                    pattern = re.compile(str(mapping["match"]))
                    matches = [name for name in names if pattern.search(name)]
                    if len(matches) != 1:
                        raise RuntimeError(
                            f"Expected one {mapping['match']} in routing archive, found {len(matches)}"
                        )
                    relative = Path(str(mapping["target"])).relative_to("rule-set")
                    payload = archive.read(matches[0])
                    if not payload:
                        raise RuntimeError(f"Routing archive contains an empty {relative.as_posix()}")
                    (staged_root / relative).write_bytes(payload)
        except (OSError, re.error, zipfile.BadZipFile) as exc:
            raise RuntimeError(f"Cannot stage sing-box rule-set files: {exc}") from exc

        _remove_path_strict(destination_root)
        _copy_tree_strict(staged_root, destination_root)

    return destination_root


# ------------------------------------------------------------------
def ensure_venv() -> None:
    if VENV_PYTHON.exists():
        _print(f"venv OK: {VENV_PYTHON}")
        return
    _print("Creating virtual environment ...")
    _run([sys.executable, "-m", "venv", str(VENV_DIR)])
    _run([str(VENV_PIP), "install", "--upgrade", "pip"])
    _run([str(VENV_PIP), "install", "-r", str(ROOT / "requirements.txt")])


def clean() -> None:
    # Both the old payload and PyInstaller's temporary output are disposable.
    # Removing the complete application directory is what prevents stale
    # runtime files, orphaned source files and locked old binaries from being
    # silently carried into the next archive.
    for path in (BUILD_DIR, APP_DIR, DIST_DIR / "_build_tmp"):
        if path.exists() or path.is_symlink():
            _print(f"Removing {path}")
            _remove_path_strict(path)


def build_exe() -> None:
    ensure_venv()

    # Build into a temporary directory so PyInstaller doesn't touch the live
    # APP_DIR while it is being assembled.  The destination was removed by
    # clean(); it must remain empty so copy failures cannot leave an older file
    # behind for packaging.
    temp_dist = DIST_DIR / "_build_tmp"
    _remove_path_strict(temp_dist)

    cmd = [
        str(VENV_PYTHON), "-m", "PyInstaller",
        _windows_path(ROOT / "main.py"),
        "--name", APP_NAME,
        "--noconfirm",
        "--console",
        "--onedir",
        "--uac-admin",
        "--manifest", _windows_path(MANIFEST),
        "--icon", _windows_path(APP_ICON),
        "--distpath", _windows_path(temp_dist),
        # win32comext is needed by qframelesswindow for Mica/DWM effects
        "--hidden-import", "win32comext",
        "--hidden-import", "win32comext.shell",
        "--hidden-import", "win32comext.shell.shellcon",
        # encodings.idna is needed by socket.getaddrinfo() for hostname resolution
        "--hidden-import", "encodings.idna",
        # Imported lazily by QR support and therefore must be explicit for PyInstaller.
        "--hidden-import", "zxingcpp",
        "--add-data", _windows_path(ROOT / "xray_fluent" / "application" / "runtime-errors.json")
        + ";xray_fluent/application",
    ]
    _run(cmd, cwd=str(ROOT))

    temp_app = temp_dist / APP_NAME
    _print(f"Staging fresh application payload -> {APP_DIR}")
    _copy_tree_strict(temp_app, APP_DIR)
    _remove_path_strict(temp_dist)

    # Every copied tree targets a new destination.  There is no merge fallback:
    # a locked file is a failed build, never permission to keep its old copy.
    dst_core = APP_DIR / "core"
    _print(f"Staging core -> {dst_core}")
    _copy_tree_strict(CORE_DIR, dst_core)
    stage_singbox_rule_sets(core_dir=dst_core)

    dst_zapret = APP_DIR / "zapret"
    _print(f"Staging zapret -> {dst_zapret}")
    _copy_tree_strict(ZAPRET_DIR, dst_zapret)

    # Ship only source-owned templates under data/. Active configs, encrypted
    # state, logs and runtime output are deliberately absent from a release.
    dst_templates = APP_DIR / "data" / "templates"
    _print(f"Staging templates -> {dst_templates}")
    dst_templates.parent.mkdir(parents=True, exist_ok=True)
    _copy_tree_strict(DATA_TEMPLATES_DIR, dst_templates)

    # Keep the high-resolution PNG available to Qt for the window, splash,
    # and tray while the multi-size ICO is embedded into the executable.
    dst_assets = APP_DIR / "assets"
    _print(f"Staging assets -> {dst_assets}")
    _copy_tree_strict(ASSETS_DIR, dst_assets)

    # app_updater.py preserves the installed data/ directory. Carry a second,
    # generated copy outside data/ so the updated executable can safely merge
    # shipped templates and untouched active configs on first launch.
    stage_template_update_bundle()

    assert_clean_payload()

    _print(f"Build complete: {APP_DIR / (APP_NAME + '.exe')}")


def pack_zip() -> None:
    if ZIP_PATH.exists():
        ZIP_PATH.unlink()
    _print(f"Creating {ZIP_PATH} ...")
    shutil.make_archive(str(ZIP_PATH.with_suffix("")), "zip", str(DIST_DIR), APP_NAME)
    _print(f"Portable archive ready: {ZIP_PATH}")


# ------------------------------------------------------------------
def main() -> int:
    parser = argparse.ArgumentParser(description="Build XrayFluent portable exe")
    parser.add_argument("--no-zip", action="store_true", help="skip zip creation")
    parser.add_argument("--clean", action="store_true", help="only clean build artefacts")
    args = parser.parse_args()

    os.chdir(ROOT)

    if args.clean:
        clean()
        _print("Done.")
        return 0

    clean()
    build_exe()

    if not args.no_zip:
        pack_zip()

    _print("All done!")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
