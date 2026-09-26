#!/usr/bin/env python3
"""Generate the sing-box JSON Schema that drives the structured routing GUI.

The schema comes from the pinned core itself: ``sing-box schema`` reflects the
Go option structs, so field names, value types, enums and tag references are
exactly what the bundled core accepts.  The GUI invents no schema of its own.

The extended fork adds a few custom JSON types that its schema generator does
not map (amnezia ranges, byte sizes, providers) and the command aborts on them.
This script builds the pinned module with the Windows release build tags and
applies one local generator tweak: a regular expression maps to a string and
any other unmapped custom type becomes an unconstrained node, with its path
recorded in ``loose-paths.txt``. Tests guarantee that no loosened path lies in
a section the GUI edits.

Requires Go and network access to the Go module proxy.  Run it after a
sing-box pin change in ``scripts/core-lock.windows-x64.json``::

    python3 scripts/generate_singbox_schema.py
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
LOCK_PATH = ROOT / "scripts" / "core-lock.windows-x64.json"
OUTPUT_DIR = ROOT / "assets" / "sing-box-schema"
SCHEMA_NAME = "schema.json"
LOOSE_NAME = "loose-paths.txt"
META_NAME = "meta.json"

_GENERATOR_ERROR = (
    '\t\treturn nil, E.New("unmapped custom JSON type ", valueType.String(), '
    '" at ", strings.Join(g.path, "."))'
)
_GENERATOR_LOOSE = (
    '\t\tif valueType.Name() == "Regexp" && strings.HasSuffix(valueType.PkgPath(), "badoption") {\n'
    "\t\t\treturn StringNode(), nil\n"
    "\t\t}\n"
    '\t\tprintln("LOOSE", strings.Join(g.path, "."), valueType.String())\n'
    "\t\treturn &Node{}, nil"
)


def _run(command: list[str], *, cwd: Path, env: dict[str, str] | None = None) -> str:
    result = subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True)
    if result.returncode != 0:
        raise SystemExit(f"{' '.join(command)} failed:\n{result.stdout}\n{result.stderr}")
    return result.stdout + result.stderr


def _module_dir(module: str, version: str, workdir: Path) -> Path:
    output = _run(["go", "mod", "download", "-json", f"{module}@{version}"], cwd=workdir)
    return Path(json.loads(output)["Dir"])


def generate() -> None:
    lock = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
    module = lock["singbox_build"]["module"]
    version = lock["singbox_build"]["version"]

    with tempfile.TemporaryDirectory(prefix="singbox-schema-") as temp:
        workdir = Path(temp)
        source = workdir / "src"
        shutil.copytree(_module_dir(module, version, workdir), source)
        for path in source.rglob("*"):
            path.chmod(path.stat().st_mode | 0o200)

        generator = source / "schema" / "generator.go"
        text = generator.read_text(encoding="utf-8")
        if _GENERATOR_ERROR not in text:
            raise SystemExit("sing-box schema generator changed; update generate_singbox_schema.py")
        generator.write_text(text.replace(_GENERATOR_ERROR, _GENERATOR_LOOSE, 1), encoding="utf-8")

        tags = (source / "release" / "DEFAULT_BUILD_TAGS_WINDOWS").read_text(encoding="utf-8").strip()
        env = dict(os.environ, GOFLAGS="-mod=mod", CGO_ENABLED="0")
        schema_path = workdir / SCHEMA_NAME
        output = _run(
            ["go", "run", "-tags", tags, "./cmd/sing-box", "schema", "-o", str(schema_path)],
            cwd=source,
            env=env,
        )
        loose = sorted(
            {line.split(" ", 1)[1].strip() for line in output.splitlines() if line.startswith("LOOSE ")}
        )
        schema = json.loads(schema_path.read_text(encoding="utf-8"))

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUTPUT_DIR / SCHEMA_NAME).write_text(
        json.dumps(schema, ensure_ascii=False, indent=1) + "\n", encoding="utf-8"
    )
    (OUTPUT_DIR / LOOSE_NAME).write_text("".join(f"{line}\n" for line in loose), encoding="utf-8")
    (OUTPUT_DIR / META_NAME).write_text(
        json.dumps({"module": module, "version": version, "build_tags": tags}, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"sing-box {version}: schema written, {len(loose)} loosened paths")


if __name__ == "__main__":
    try:
        generate()
    except KeyboardInterrupt:
        sys.exit(130)
