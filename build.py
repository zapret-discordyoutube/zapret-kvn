"""
Build XrayFluent portable exe via PyInstaller.

Usage:  python build.py          — full build (clean + compile + pack zip)
        python build.py --no-zip — skip zip creation
        python build.py --clean  — only wipe previous build artefacts

Requires .venv created by setup.bat (or manually).
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

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
