"""winws2 command line: a preset plus, optionally, one rule for the VPN server.

Pure functions, no Qt and no I/O besides the preset read by the caller — so the
exact argument order can be tested directly.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass

from .blobs import blob_arguments, lua_init_arguments, unresolved_blob_names
from .endpoint import ResolvedEndpoint
from .strategies import Strategy

log = logging.getLogger(__name__)

SERVER_PROFILE_NAME = "--name=ZapretKVN: выбранный сервер"
_CORE_LUA = (
    "--lua-init=@lua/zapret-lib.lua",
    "--lua-init=@lua/zapret-antidpi.lua",
)
# The first argument with one of these prefixes opens winws2's profile list;
# everything before it is global (lua, blobs, capture filters).
_PROFILE_PREFIXES = (
    "--filter-", "--hostlist", "--import", "--in-range", "--ipset",
    "--lua-desync", "--name", "--out-range", "--payload", "--skip", "--template",
)


@dataclass(frozen=True, slots=True)
class ServerRule:
    """What winws2 does with the packets of one resolved VPN server."""

    target: ResolvedEndpoint
    strategy: Strategy

    def describe(self) -> str:
        endpoint = self.target.endpoint
        return (
            f"{endpoint.transport.upper()} {endpoint.port_filter}; "
            f"{self.strategy.name}; {', '.join(self.target.ips)}"
        )


def _loads_lua(global_args: list[str], init: str) -> bool:
    filename = init.rsplit("/", 1)[-1]
    return any(arg.startswith("--lua-init=") and filename in arg for arg in global_args)


def _merge_capture_filter(global_args: list[str], transport: str, ports: str) -> None:
    """One ``--wf-<transport>-out=`` covering the preset's ports and the server's."""

    prefix = f"--wf-{transport}-out="
    indexes = [index for index, arg in enumerate(global_args) if arg.startswith(prefix)]
    if not indexes:
        global_args.append(prefix + ports)
        return
    values = [global_args[index].removeprefix(prefix) for index in indexes]
    if "*" in values:
        merged = "*"
    else:
        tokens = f"{','.join(values)},{ports}".split(",")
        merged = ",".join(dict.fromkeys(token.strip() for token in tokens if token.strip()))
    global_args[indexes[0]] = prefix + merged
    for index in reversed(indexes[1:]):
        global_args.pop(index)


def build_arguments(preset_args: list[str], rule: ServerRule | None) -> list[str]:
    """Preset arguments with the server rule as the very first profile.

    winws2 applies the first matching profile, so the server's exact
    IP/transport/port rule placed first wins over any broad preset profile.
    The preset list itself is never modified.
    """

    if rule is None or not rule.target.ips:
        return list(preset_args)
    strategy = rule.strategy
    endpoint = rule.target.endpoint

    first_profile = next(
        (
            index for index, arg in enumerate(preset_args)
            if arg == "--new" or arg.startswith("--new=") or arg.startswith(_PROFILE_PREFIXES)
        ),
        len(preset_args),
    )
    global_args = preset_args[:first_profile]
    profiles = preset_args[first_profile:]

    for init in reversed(_CORE_LUA):
        if not _loads_lua(global_args, init):
            global_args.insert(0, init)
    # Extension lua builds on the core API, so it loads after the last lua-init.
    lua_tail = max(
        (index for index, arg in enumerate(global_args) if arg.startswith("--lua-init=")),
        default=-1,
    )
    for init in reversed(lua_init_arguments(strategy.args)):
        if not _loads_lua(global_args, init):
            global_args.insert(lua_tail + 1, init)
    for definition in blob_arguments(strategy.blob_dependencies):
        name = definition.removeprefix("--blob=").split(":", 1)[0]
        if not any(arg.startswith(f"--blob={name}:") for arg in global_args):
            global_args.append(definition)
    unresolved = unresolved_blob_names(strategy.blob_dependencies)
    if unresolved:
        log.warning(
            "Стратегия %s ссылается на неизвестные блобы: %s",
            strategy.strategy_id, ", ".join(unresolved),
        )

    _merge_capture_filter(global_args, endpoint.transport, endpoint.port_filter)
    ips = sorted(
        {str(ipaddress.ip_address(value)) for value in rule.target.ips},
        key=lambda value: (ipaddress.ip_address(value).version, value),
    )
    server_profile = [
        SERVER_PROFILE_NAME,
        f"--filter-{endpoint.transport}={endpoint.port_filter}",
        "--ipset-ip=" + ",".join(ips),
        *strategy.args,
    ]
    separator = ["--new"] if profiles else []
    return [*global_args, *server_profile, *separator, *profiles]
