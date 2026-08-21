"""Minimal winws2 (zapret2) process manager — preset-based, no orchestrator."""

from __future__ import annotations

import ipaddress
import logging
import os
import shutil
import socket
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from PyQt6.QtCore import QObject, QProcess, QTimer, pyqtSignal

from .constants import BASE_DIR
from .models import ZapretTargetSettings
from .subprocess_utils import decode_output, kill_processes_by_path, sleep_with_events
from .zapret_blobs import blob_arguments, lua_init_arguments, unresolved_blob_names
from .zapret_target import (
    ResolvedZapretEndpoint,
    ZapretEndpointSpec,
    ZapretStrategyEntry,
    endpoint_spec_for_node,
    strategy_for_target,
    target_requires_zapret,
)

log = logging.getLogger(__name__)

ZAPRET_DIR = BASE_DIR / "zapret"
WINWS2_EXE = ZAPRET_DIR / "exe" / "winws2.exe"
WINWS_EXE = ZAPRET_DIR / "exe" / "winws.exe"
PRESETS_DIR = ZAPRET_DIR / "presets"

#: Preset applied when the user never picked one; falls back to any preset on disk.
DEFAULT_PRESET_NAME = "Default"

_IPSET_IP_PREFIX = "--ipset-ip="
_UDP_PROXY_TYPES = frozenset({"hysteria", "hysteria2", "tuic"})
_PROFILE_ARGUMENT_PREFIXES = (
    "--filter-",
    "--hostlist",
    "--import",
    "--in-range",
    "--ipset",
    "--lua-desync",
    "--name",
    "--out-range",
    "--payload",
    "--skip",
    "--template",
)

_CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0

# WinDivert/winws2 normally restarts quickly, but the process can spend a
# bounded amount of time releasing the previous driver handles before the new
# pass profile is actually active.  A proxy transition must not race that
# window forever or assume that the old process is already using the new IP
# list.
PROXY_PROTECTION_READY_TIMEOUT_MS = 5_000


@dataclass
class PresetInfo:
    name: str
    description: str
    created: str
    modified: str
    arg_count: int
    file_path: Path


class ZapretManager(QObject):
    """Start / stop winws2.exe with a preset file."""

    started = pyqtSignal()
    stopped = pyqtSignal()
    error = pyqtSignal(str)
    log_line = pyqtSignal(str)
    # Emitted only after the winws2 process carrying the requested pass profile
    # has reported QProcess.started.  The generation prevents a late signal
    # from an older restart from unblocking a newer transition.
    proxy_protection_ready = pyqtSignal(int)
    proxy_protection_failed = pyqtSignal(int, str)
    target_profile_ready = pyqtSignal(int)
    target_profile_failed = pyqtSignal(int, str)
    target_profile_changed = pyqtSignal(object)

    def __init__(self, parent: QObject | None = None):
        super().__init__(parent)
        self._process: QProcess | None = None
        self._current_preset: str = ""
        self._start_args: list[str] = []
        self._protected_proxy_ips: set[str] = set()
        self._proxy_resolution_cache: dict[str, set[str]] = {}
        self._target_settings = ZapretTargetSettings()
        self._resolved_target: ResolvedZapretEndpoint | None = None
        self._target_strategy: ZapretStrategyEntry | None = None
        self._pending_restart_preset = ""
        self._stop_expected = False
        self._proxy_protection_generation = 0
        self._proxy_protection_ready_generation = 0
        self._proxy_protection_pending_generation = 0
        self._health_timer = QTimer(self)
        self._health_timer.setInterval(3000)
        self._health_timer.timeout.connect(self._check_health)

    # ── public API ──────────────────────────────────────────────

    @property
    def running(self) -> bool:
        return self._process is not None and self._process.state() == QProcess.ProcessState.Running

    @property
    def proxy_protection_generation(self) -> int:
        """Generation of the currently requested protected UDP endpoint set."""

        return self._proxy_protection_generation

    def proxy_protection_is_ready(self, node: object | None = None) -> bool:
        """Whether a transition may use the current UDP pass configuration.

        A stopped Zapret manager is an intentional no-op: there is no WinDivert
        process to restart or wait for.  When a running manager is replacing
        its profile, however, readiness remains false until the new process
        emits ``started`` for the current generation.
        """

        if self._proxy_protection_pending_generation:
            return False
        if not self.running:
            return True
        if not self.proxy_protection_server(node):
            return True
        return self._proxy_protection_ready_generation == self._proxy_protection_generation

    @property
    def target_profile_generation(self) -> int:
        return self._proxy_protection_generation

    @property
    def resolved_target(self) -> ResolvedZapretEndpoint | None:
        return self._resolved_target

    @property
    def target_strategy(self) -> ZapretStrategyEntry | None:
        return self._target_strategy

    def set_target_settings(self, settings: ZapretTargetSettings) -> None:
        self._target_settings = settings

    def target_spec(self, node: object | None) -> ZapretEndpointSpec | None:
        return endpoint_spec_for_node(node)

    def target_requires_zapret(self, node: object | None) -> bool:
        return target_requires_zapret(self._target_settings, node)

    def target_profile_is_ready(self, node: object | None = None) -> bool:
        if self._proxy_protection_pending_generation:
            return False
        spec = self.target_spec(node)
        if spec is None:
            return True
        try:
            strategy = strategy_for_target(self._target_settings, spec)
        except ValueError:
            return False
        if strategy is None:
            return True
        if self._resolved_target is None or self._resolved_target.spec != spec:
            return False
        if self._target_strategy != strategy:
            return False
        if self.target_requires_zapret(node) and not self.running:
            return False
        if not self.running:
            return True
        return self._proxy_protection_ready_generation == self._proxy_protection_generation

    def start_with_target(self, preset_name: str) -> None:
        """Start winws2 and make QProcess.started the readiness proof."""
        if self._resolved_target is not None and self._target_strategy is not None:
            generation = self._proxy_protection_generation
            self._proxy_protection_ready_generation = generation - 1
            self._proxy_protection_pending_generation = generation
            self._arm_proxy_protection_timeout(generation)
        self.start(preset_name)

    @staticmethod
    def list_presets() -> list[str]:
        """Return sorted list of available preset names (without .txt)."""
        if not PRESETS_DIR.is_dir():
            return []
        return sorted(
            p.stem for p in PRESETS_DIR.iterdir()
            if p.suffix == ".txt" and not p.name.startswith("_")
        )

    @staticmethod
    def default_preset() -> str:
        """Preset to fall back on so a fresh install can still connect.

        A blank ``zapret_preset`` used to refuse the connection outright, which
        made a clean install unusable until the user discovered the Zapret page.
        """

        if ZapretManager.preset_path(DEFAULT_PRESET_NAME).is_file():
            return DEFAULT_PRESET_NAME
        available = ZapretManager.list_presets()
        return available[0] if available else ""

    @staticmethod
    def preset_path(name: str) -> Path:
        return PRESETS_DIR / f"{name}.txt"

    @staticmethod
    def _parse_preset_args(preset: Path) -> list[str]:
        """Read preset file and return list of arguments (skip comments/blanks)."""
        args: list[str] = []
        text = preset.read_text(encoding="utf-8", errors="replace")
        for line in text.splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                args.append(stripped)
        return args

    @staticmethod
    def _with_target_profile(
        args: list[str],
        target: ResolvedZapretEndpoint | None,
        strategy: ZapretStrategyEntry | None,
    ) -> list[str]:
        """Prepend one exact IP/transport/port profile without editing a preset."""
        if target is None or strategy is None or not target.ips:
            return list(args)

        normalized_ips = sorted(
            {str(ipaddress.ip_address(value)) for value in target.ips},
            key=lambda value: (ipaddress.ip_address(value).version, value),
        )
        first_profile_index = next(
            (
                index
                for index, argument in enumerate(args)
                if argument == "--new"
                or argument.startswith("--new=")
                or argument.startswith(_PROFILE_ARGUMENT_PREFIXES)
            ),
            len(args),
        )
        global_args = args[:first_profile_index]
        original_profiles = args[first_profile_index:]
        required_lua = (
            "--lua-init=@lua/zapret-lib.lua",
            "--lua-init=@lua/zapret-antidpi.lua",
        )
        for required in reversed(required_lua):
            filename = required.rsplit("/", 1)[-1]
            if not any(arg.startswith("--lua-init=") and filename in arg for arg in global_args):
                global_args.insert(0, required)
        # Extension lua files must load after the core ones they build upon.
        lua_tail = max(
            (index for index, arg in enumerate(global_args) if arg.startswith("--lua-init=")),
            default=-1,
        )
        for extension in reversed(lua_init_arguments(strategy.args)):
            filename = extension.rsplit("/", 1)[-1]
            if any(arg.startswith("--lua-init=") and filename in arg for arg in global_args):
                continue
            global_args.insert(lua_tail + 1, extension)
        for definition in blob_arguments(strategy.blob_dependencies):
            blob_name = definition.removeprefix("--blob=").split(":", 1)[0]
            if not any(arg.startswith(f"--blob={blob_name}:") for arg in global_args):
                global_args.append(definition)
        unresolved = unresolved_blob_names(strategy.blob_dependencies)
        if unresolved:
            log.warning(
                "Стратегия %s ссылается на неизвестные блобы: %s",
                strategy.strategy_id, ", ".join(unresolved),
            )

        transport = target.spec.transport
        capture_prefix = f"--wf-{transport}-out="
        capture_indexes = [
            index for index, argument in enumerate(global_args)
            if argument.startswith(capture_prefix)
        ]
        if capture_indexes:
            first = capture_indexes[0]
            existing_values = [
                global_args[index].removeprefix(capture_prefix)
                for index in capture_indexes
            ]
            if "*" in existing_values:
                global_args[first] = capture_prefix + "*"
            else:
                merged = list(dict.fromkeys(
                    [
                        token.strip()
                        for token in f"{','.join(existing_values)},{target.spec.port_filter}".split(",")
                        if token.strip()
                    ]
                ))
                global_args[first] = capture_prefix + ",".join(merged)
            for index in reversed(capture_indexes[1:]):
                global_args.pop(index)
        else:
            global_args.append(capture_prefix + target.spec.port_filter)
        target_profile = [
            "--name=ZapretKVN: выбранный сервер",
            f"--filter-{transport}={target.spec.port_filter}",
            _IPSET_IP_PREFIX + ",".join(normalized_ips),
            *strategy.args,
        ]
        separator = ["--new"] if original_profiles else []
        return [*global_args, *target_profile, *separator, *original_profiles]

    @staticmethod
    def _with_proxy_pass_profile(args: list[str], protected_ips: set[str]) -> list[str]:
        """Compatibility implementation for the former UDP-only protection API."""
        if not protected_ips:
            return list(args)
        normalized_ips = sorted(
            protected_ips,
            key=lambda value: (ipaddress.ip_address(value).version, value),
        )
        first_profile_index = next(
            (
                index
                for index, argument in enumerate(args)
                if argument == "--new"
                or argument.startswith("--new=")
                or argument.startswith(_PROFILE_ARGUMENT_PREFIXES)
            ),
            len(args),
        )
        global_args = args[:first_profile_index]
        original_profiles = args[first_profile_index:]
        required_lua = "--lua-init=@lua/zapret-lib.lua"
        if not any(
            arg.startswith("--lua-init=") and "zapret-lib.lua" in arg
            for arg in global_args
        ):
            global_args.insert(0, required_lua)
        pass_profile = [
            "--filter-udp=*",
            _IPSET_IP_PREFIX + ",".join(normalized_ips),
            "--lua-desync=pass",
        ]
        separator = ["--new"] if original_profiles else []
        return [*global_args, *pass_profile, *separator, *original_profiles]

    @staticmethod
    def _resolve_server_ips(server: str) -> set[str]:
        host = server.strip().strip("[]").rstrip(".")
        if not host:
            return set()
        try:
            return {str(ipaddress.ip_address(host))}
        except ValueError:
            pass

        resolved: set[str] = set()
        for info in socket.getaddrinfo(host, None, type=socket.SOCK_DGRAM):
            address = info[4][0]
            try:
                resolved.add(str(ipaddress.ip_address(address)))
            except ValueError:
                continue
        return resolved

    @classmethod
    def resolve_target(cls, spec: ZapretEndpointSpec) -> ResolvedZapretEndpoint:
        resolved: set[str] = set()
        for host in spec.hosts:
            resolved.update(cls._resolve_server_ips(host))
        if not resolved:
            raise OSError(f"не удалось определить IP: {', '.join(spec.hosts)}")
        normalized = tuple(sorted(
            resolved,
            key=lambda value: (ipaddress.ip_address(value).version, value),
        ))
        return ResolvedZapretEndpoint(spec, normalized)

    @staticmethod
    def proxy_protection_server(node: object | None) -> str:
        if node is None:
            return ""
        outbound = getattr(node, "outbound", {})
        proxy_type = str(outbound.get("type") or getattr(node, "scheme", "")).lower()
        if proxy_type not in _UDP_PROXY_TYPES:
            return ""
        return str(outbound.get("server") or getattr(node, "server", "")).strip()

    def cache_proxy_resolution(self, server: str, protected_ips: set[str]) -> None:
        if server:
            self._proxy_resolution_cache[server] = set(protected_ips)

    def apply_resolved_target(
        self,
        node: object | None,
        resolved: ResolvedZapretEndpoint | None,
    ) -> bool:
        """Install a freshly resolved selected-node profile in manager state."""
        spec = self.target_spec(node)
        if spec is None:
            self._set_target_profile(None, None)
            return True
        try:
            strategy = strategy_for_target(self._target_settings, spec)
        except ValueError as exc:
            self.log_line.emit(f"[zapret] {exc}")
            return False
        if strategy is None:
            self._set_target_profile(None, None)
            return True
        if resolved is None or resolved.spec != spec or not resolved.ips:
            return False
        self._set_target_profile(resolved, strategy)
        return True

    def clear_target_profile(self) -> None:
        self._set_target_profile(None, None)

    def apply_cached_proxy_node(self, node: object | None) -> bool:
        """Apply a prepared endpoint without DNS or other blocking work."""
        server = self.proxy_protection_server(node)
        if not server:
            self._set_protected_proxy_ips(set())
            return True
        protected_ips = self._proxy_resolution_cache.get(server)
        if protected_ips is None:
            return False
        self._set_protected_proxy_ips(protected_ips)
        return True

    def protect_proxy_node(self, node: object) -> set[str]:
        """Keep UDP proxy endpoints out of winws2 desynchronization profiles."""
        server = self.proxy_protection_server(node)
        if not server:
            self._set_protected_proxy_ips(set())
            return set()
        try:
            resolved = self._resolve_server_ips(server)
        except OSError as exc:
            log.warning("zapret could not resolve protected proxy endpoint %s: %s", server, exc)
            self.log_line.emit(f"[zapret] Не удалось определить IP сервера UDP-прокси: {server}")
            return set()
        self.cache_proxy_resolution(server, resolved)
        self._set_protected_proxy_ips(resolved)
        return resolved

    def _set_protected_proxy_ips(self, protected_ips: set[str]) -> None:
        if not protected_ips and self._resolved_target is None:
            self._protected_proxy_ips.clear()
            return
        if protected_ips:
            target = ResolvedZapretEndpoint(
                ZapretEndpointSpec("quic_proxy", "udp", ("compat",), ("1-65535",)),
                tuple(sorted(protected_ips)),
            )
            strategy = ZapretStrategyEntry("pass", "udp", "pass", ("--lua-desync=pass",))
        else:
            target = None
            strategy = None
        self._set_target_profile(target, strategy)

    def _set_target_profile(
        self,
        target: ResolvedZapretEndpoint | None,
        strategy: ZapretStrategyEntry | None,
    ) -> None:
        if target == self._resolved_target and strategy == self._target_strategy:
            return

        self._resolved_target = target
        self._target_strategy = strategy
        self._protected_proxy_ips = set(target.ips if target else ())
        self._proxy_protection_generation += 1
        generation = self._proxy_protection_generation
        self._proxy_protection_ready_generation = generation - 1
        if target and strategy:
            joined = ", ".join(target.ips)
            self.log_line.emit(
                f"[zapret] Профиль выбранного сервера: {target.spec.transport.upper()} "
                f"{target.spec.port_filter}; {strategy.name}; {joined}"
            )
        else:
            self.log_line.emit("[zapret] Профиль выбранного сервера отключён")
        self.target_profile_changed.emit(target)

        # If a previous restart has already killed the process, retain the
        # pending generation and let that restart's eventual start event prove
        # readiness.  Starting a second overlapping QProcess would make the
        # generation contract meaningless and can also race WinDivert handles.
        # ``_pending_restart_preset`` covers the stop/start handoff; the
        # pending generation also covers the short QProcess.Starting window
        # after start() has consumed that marker but before ``started`` fires.
        restart_in_flight = bool(
            self._pending_restart_preset
            or self._proxy_protection_pending_generation
        )
        if (self.running and self._current_preset) or restart_in_flight:
            self._proxy_protection_pending_generation = generation
            self._arm_proxy_protection_timeout(generation)
        else:
            # Zapret is not running.  There is no pass process whose readiness
            # could be awaited, so this is deliberately a ready/no-op state.
            self._proxy_protection_pending_generation = 0
            self._proxy_protection_ready_generation = generation
            self.proxy_protection_ready.emit(generation)
            self.target_profile_ready.emit(generation)

        if self.running and self._current_preset and not restart_in_flight:
            preset = self._current_preset
            self.log_line.emit("[zapret] Перезапуск с обновлённым профилем pass")
            self._restart_for_proxy_protection(preset)

    def _arm_proxy_protection_timeout(self, generation: int) -> None:
        QTimer.singleShot(
            PROXY_PROTECTION_READY_TIMEOUT_MS,
            lambda generation=generation: self._on_proxy_protection_timeout(generation),
        )

    def _on_proxy_protection_timeout(self, generation: int) -> None:
        if generation != self._proxy_protection_pending_generation:
            return
        self._proxy_protection_pending_generation = 0
        self.log_line.emit(
            "[zapret] Не удалось подтвердить перезапуск UDP-профиля pass "
            f"за {PROXY_PROTECTION_READY_TIMEOUT_MS} мс"
        )
        self.proxy_protection_failed.emit(generation, "timeout")
        self.target_profile_failed.emit(generation, "timeout")

    def _fail_pending_proxy_protection(self, reason: str) -> None:
        generation = self._proxy_protection_pending_generation
        if not generation:
            return
        self._proxy_protection_pending_generation = 0
        self.proxy_protection_failed.emit(generation, reason)
        self.target_profile_failed.emit(generation, reason)

    def _restart_for_proxy_protection(self, preset: str) -> None:
        """Restart winws2 through QProcess signals instead of waitForFinished()."""
        self._pending_restart_preset = preset
        process = self._process
        if process is None or process.state() == QProcess.ProcessState.NotRunning:
            QTimer.singleShot(0, lambda preset=preset: self.start(preset))
            return
        self._health_timer.stop()
        self._stop_expected = True
        process.kill()

    @staticmethod
    def _parse_metadata(text: str) -> dict[str, str]:
        """Extract metadata from comment headers."""
        meta: dict[str, str] = {}
        for line in text.splitlines()[:15]:  # only check first 15 lines
            stripped = line.strip()
            if not stripped.startswith("#"):
                if stripped:  # non-empty non-comment = end of headers
                    break
                continue
            for key in ("Preset", "Description", "Created", "Modified", "BuiltinVersion"):
                prefix = f"# {key}:"
                if stripped.startswith(prefix):
                    meta[key] = stripped[len(prefix):].strip()
                    break
        return meta

    @staticmethod
    def list_preset_infos() -> list[PresetInfo]:
        """Return list of PresetInfo for all presets, sorted by name."""
        if not PRESETS_DIR.is_dir():
            return []
        result = []
        for p in sorted(PRESETS_DIR.iterdir()):
            if p.suffix != ".txt" or p.name.startswith("_"):
                continue
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                # This runs on the window-initialization path; one unreadable
                # file must not take the whole page down with it.
                log.warning("Не удалось прочитать пресет %s: %s", p.name, exc)
                continue
            meta = ZapretManager._parse_metadata(text)
            arg_count = sum(1 for line in text.splitlines()
                           if line.strip() and not line.strip().startswith("#"))
            result.append(PresetInfo(
                name=p.stem,
                description=meta.get("Description", ""),
                created=meta.get("Created", ""),
                modified=meta.get("Modified", ""),
                arg_count=arg_count,
                file_path=p,
            ))
        return result

    @staticmethod
    def read_preset(name: str) -> str:
        """Return full text content of a preset file."""
        path = PRESETS_DIR / f"{name}.txt"
        if not path.is_file():
            return ""
        return path.read_text(encoding="utf-8", errors="replace")

    @staticmethod
    def save_preset(name: str, content: str, description: str = "") -> PresetInfo:
        """Write preset file with updated metadata headers."""
        path = PRESETS_DIR / f"{name}.txt"
        PRESETS_DIR.mkdir(parents=True, exist_ok=True)

        # Preserve original Created date if file exists
        created = ""
        if path.is_file():
            old_text = path.read_text(encoding="utf-8", errors="replace")
            old_meta = ZapretManager._parse_metadata(old_text)
            created = old_meta.get("Created", "")

        now = datetime.now().isoformat(timespec="seconds")
        if not created:
            created = now

        # Strip existing metadata headers from content
        lines = content.splitlines()
        body_lines = []
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("# Preset:") or stripped.startswith("# Description:") \
               or stripped.startswith("# Created:") or stripped.startswith("# Modified:"):
                continue
            body_lines.append(line)

        # Remove leading blank lines from body
        while body_lines and not body_lines[0].strip():
            body_lines.pop(0)

        header = f"# Preset: {name}\n# Description: {description}\n# Created: {created}\n# Modified: {now}\n\n"
        full_text = header + "\n".join(body_lines) + "\n"
        path.write_text(full_text, encoding="utf-8")

        arg_count = sum(1 for l in body_lines if l.strip() and not l.strip().startswith("#"))
        return PresetInfo(name=name, description=description, created=created,
                         modified=now, arg_count=arg_count, file_path=path)

    @staticmethod
    def rename_preset(old_name: str, new_name: str) -> PresetInfo | None:
        """Rename preset file. Returns new PresetInfo or None on failure."""
        old_path = PRESETS_DIR / f"{old_name}.txt"
        new_path = PRESETS_DIR / f"{new_name}.txt"
        if not old_path.is_file() or new_path.exists():
            return None

        # Update # Preset: header inside the file
        text = old_path.read_text(encoding="utf-8", errors="replace")
        text = text.replace(f"# Preset: {old_name}", f"# Preset: {new_name}", 1)
        new_path.write_text(text, encoding="utf-8")
        old_path.unlink()

        meta = ZapretManager._parse_metadata(text)
        arg_count = sum(1 for l in text.splitlines() if l.strip() and not l.strip().startswith("#"))
        return PresetInfo(name=new_name, description=meta.get("Description", ""),
                         created=meta.get("Created", ""), modified=meta.get("Modified", ""),
                         arg_count=arg_count, file_path=new_path)

    @staticmethod
    def delete_preset(name: str) -> bool:
        """Delete preset file. Returns True if deleted."""
        path = PRESETS_DIR / f"{name}.txt"
        if path.is_file():
            path.unlink()
            return True
        return False

    @staticmethod
    def import_preset(source_path: Path) -> PresetInfo | None:
        """Import a preset file from external path. Handles name conflicts."""
        if not source_path.is_file():
            return None
        PRESETS_DIR.mkdir(parents=True, exist_ok=True)

        base_name = source_path.stem
        target = PRESETS_DIR / f"{base_name}.txt"
        counter = 1
        while target.exists():
            target = PRESETS_DIR / f"{base_name} ({counter}).txt"
            counter += 1

        shutil.copy2(source_path, target)

        # Read and return info
        text = target.read_text(encoding="utf-8", errors="replace")
        meta = ZapretManager._parse_metadata(text)
        arg_count = sum(1 for l in text.splitlines() if l.strip() and not l.strip().startswith("#"))
        return PresetInfo(name=target.stem, description=meta.get("Description", ""),
                         created=meta.get("Created", ""), modified=meta.get("Modified", ""),
                         arg_count=arg_count, file_path=target)

    def start(self, preset_name: str) -> None:
        # A pending-restart marker only protects the gap before this launch.
        # Clear it once QProcess.start() is being attempted so a crash of the
        # replacement process cannot recursively schedule an unbounded restart.
        self._pending_restart_preset = ""
        if self._process is not None and self._process.state() != QProcess.ProcessState.NotRunning:
            self.stop(preserve_pending=True)

        killed = self._kill_orphaned()
        for name in killed:
            self.log_line.emit(f"[zapret] Завершён сторонний процесс: {name}")

        exe = WINWS2_EXE
        if not exe.exists():
            self.error.emit(f"winws2.exe не найден: {exe}")
            self._fail_pending_proxy_protection("missing_executable")
            return

        preset = self.preset_path(preset_name)
        if not preset.exists():
            self.error.emit(f"Пресет не найден: {preset}")
            self._fail_pending_proxy_protection("missing_preset")
            return

        # Parse preset and pass args directly (winws2 @file can't handle spaces in path)
        args = self._with_target_profile(
            self._parse_preset_args(preset),
            self._resolved_target,
            self._target_strategy,
        )
        if not args:
            self.error.emit(f"Пресет пустой: {preset_name}")
            self._fail_pending_proxy_protection("empty_preset")
            return

        self._current_preset = preset_name
        self._start_args = args

        self._process = QProcess(self)
        self._process.setProgram(str(exe))
        self._process.setArguments(args)
        self._process.setWorkingDirectory(str(ZAPRET_DIR))
        self._process.readyReadStandardOutput.connect(self._on_stdout)
        self._process.readyReadStandardError.connect(self._on_stderr)
        self._process.started.connect(self._on_started)
        self._process.errorOccurred.connect(self._on_process_error)
        self._process.finished.connect(self._on_finished)

        log.info("zapret start: %s [%s] (%d args)", exe.name, preset_name, len(args))
        self.log_line.emit(f"[zapret] Запуск: {preset_name} ({len(args)} аргументов)")
        self._process.start()

    def _on_started(self) -> None:
        self._health_timer.start()
        generation = self._proxy_protection_pending_generation
        if generation:
            self._proxy_protection_pending_generation = 0
            self._proxy_protection_ready_generation = generation
            self.proxy_protection_ready.emit(generation)
            self.target_profile_ready.emit(generation)
        self.started.emit()

    def _on_process_error(self, process_error: QProcess.ProcessError) -> None:
        if process_error != QProcess.ProcessError.FailedToStart:
            return
        self.error.emit(f"Не удалось запустить winws2.exe: {process_error.name}")
        process = self._process
        if process is not None and process.state() == QProcess.ProcessState.NotRunning:
            self._health_timer.stop()
            self._process = None
            self._current_preset = ""
            self._start_args = []
            self._fail_pending_proxy_protection("start_failed")
            self.stopped.emit()

    def stop(self, *, preserve_pending: bool = False) -> None:
        """Stop winws2; a manual stop fails any readiness waiter.

        ``preserve_pending`` is used only by :meth:`start` while replacing an
        already running process.  In that narrow case the next ``started``
        signal remains the readiness proof for the same generation.
        """
        self._pending_restart_preset = ""
        self._health_timer.stop()
        process = self._process
        if process is None:
            if not preserve_pending:
                self._fail_pending_proxy_protection("stopped")
            return

        if process.state() != QProcess.ProcessState.NotRunning:
            log.info("zapret stop")
            self._stop_expected = True
            process.kill()
            process.waitForFinished(5000)

        if self._process is process:
            self._process = None
            self._current_preset = ""
            self._start_args = []
            self._stop_expected = False
            self.stopped.emit()
        if not preserve_pending:
            self._fail_pending_proxy_protection("stopped")

    # ── internals ───────────────────────────────────────────────

    @staticmethod
    def _kill_orphaned() -> list[str]:
        """Kill any orphaned winws.exe / winws2.exe processes."""
        killed: list[str] = []
        if os.name != "nt":
            return killed
        for exe_name, exe_path in (("winws2.exe", WINWS2_EXE), ("winws.exe", WINWS_EXE)):
            try:
                if kill_processes_by_path(exe_name, exe_path, timeout=5):
                    killed.append(exe_name)
            except Exception:
                pass
        if killed:
            # Let the WinDivert driver release its handles without freezing the
            # GUI: pump Qt events every 100ms instead of a blind time.sleep(1).
            sleep_with_events(1.0, step_sec=0.1)
        return killed

    @staticmethod
    def _exit_code_hint(code: int) -> str:
        """Return a human-readable hint for common winws2 exit codes."""
        hints = {
            1: "общая ошибка (другой экземпляр / не удалось открыть WinDivert)",
            2: "ошибка аргументов командной строки",
            3: "не удалось загрузить WinDivert драйвер (нужны права администратора)",
        }
        return hints.get(code, "")

    def _drain_output(self) -> list[str]:
        """Read any remaining stdout/stderr from the process."""
        lines: list[str] = []
        if self._process is None:
            return lines
        for reader in (self._process.readAllStandardOutput,
                       self._process.readAllStandardError):
            data = reader().data()
            if data:
                for line in decode_output(bytes(data)).splitlines():
                    stripped = line.strip()
                    if stripped:
                        lines.append(stripped)
        return lines

    def _on_stdout(self) -> None:
        if self._process is None:
            return
        data = self._process.readAllStandardOutput().data()
        for line in decode_output(bytes(data)).splitlines():
            if line.strip():
                self.log_line.emit(f"[zapret] {line.strip()}")

    def _on_stderr(self) -> None:
        if self._process is None:
            return
        data = self._process.readAllStandardError().data()
        for line in decode_output(bytes(data)).splitlines():
            if line.strip():
                self.log_line.emit(f"[zapret] {line.strip()}")

    def _on_finished(self, exit_code: int, exit_status: QProcess.ExitStatus) -> None:
        if self._process is None:
            return
        self._health_timer.stop()
        expected = self._stop_expected
        pending_restart = self._pending_restart_preset

        # Drain any buffered output before dropping the process reference
        remaining = self._drain_output()
        for line in remaining:
            self.log_line.emit(f"[zapret] {line}")

        preset = self._current_preset or "?"
        log.info("zapret finished: code=%d status=%s preset=%s", exit_code, exit_status.name, preset)

        if not expected and (exit_code != 0 or exit_status == QProcess.ExitStatus.CrashExit):
            # Подробности в лог
            hint = self._exit_code_hint(exit_code)
            if hint:
                self.log_line.emit(f"[zapret] Код {exit_code}: {hint}")
            self.log_line.emit(f"[zapret] Пресет: {preset}")
            if self._start_args:
                preview = " ".join(self._start_args[:6])
                if len(self._start_args) > 6:
                    preview += f" ... (+{len(self._start_args) - 6} аргументов)"
                self.log_line.emit(f"[zapret] Команда: winws2.exe {preview}")
            if not remaining:
                self.log_line.emit("[zapret] Процесс не вывел ничего в stdout/stderr")

            # Краткое сообщение для InfoBar и status_label
            short = f"winws2 завершился с кодом {exit_code}"
            if hint:
                short += f" — {hint}"
            self.error.emit(short)

        self._process = None
        self._current_preset = ""
        self._start_args = []
        self._stop_expected = False
        self._pending_restart_preset = ""
        self.stopped.emit()
        if pending_restart:
            # Keep the generation pending while the replacement process is
            # being created.  _on_started is the only readiness proof.
            self._pending_restart_preset = pending_restart
            QTimer.singleShot(0, lambda preset=pending_restart: self.start(preset))

    def _check_health(self) -> None:
        if not self.running:
            self._health_timer.stop()
            self.stopped.emit()
