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
POOL_PROFILE_NAME = "--name=ZapretKVN: серверы набора"
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


def _sorted_ips(values) -> list[str]:
    return sorted(
        {str(ipaddress.ip_address(value)) for value in values},
        key=lambda value: (ipaddress.ip_address(value).version, value),
    )


def _merged_ports(endpoints) -> str:
    tokens = dict.fromkeys(port for endpoint in endpoints for port in endpoint.ports)
    return ",".join(sorted(tokens, key=lambda item: int(item.split("-", 1)[0])))


def build_arguments(
    preset_args: list[str],
    rule: ServerRule | None,
    pool: tuple[ServerRule, ...] = (),
) -> list[str]:
    """Preset arguments with the server rule as the very first profile.

    winws2 applies the first matching profile, so the server's exact
    IP/transport/port rule placed first wins over any broad preset profile.
    The preset list itself is never modified.

    ``pool`` — the other servers of the running pool.  Their rules follow
    the selected server's profile, one profile per transport and strategy
    (IPs and ports merged), so switching to any of them needs no winws2
    restart and therefore no tunnel stop.
    """

    if rule is None or not rule.target.ips:
        return list(preset_args)
    # Profile groups: (transport, strategy) -> rules.  The selected server's
    # group goes first and keeps its name; its own exact rule is always in it.
    groups: dict[tuple[str, Strategy], list[ServerRule]] = {}
    for item in (rule, *pool):
        if item is None or not item.target.ips:
            continue
        key = (item.target.endpoint.transport, item.strategy)
        groups.setdefault(key, []).append(item)

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

    server_profiles: list[str] = []
    for index, ((transport, strategy), members) in enumerate(groups.items()):
        # Extension lua builds on the core API, so it loads after the last lua-init.
        lua_tail = max(
            (position for position, arg in enumerate(global_args) if arg.startswith("--lua-init=")),
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

        ports = _merged_ports(member.target.endpoint for member in members)
        _merge_capture_filter(global_args, transport, ports)
        if server_profiles:
            server_profiles.append("--new")
        server_profiles.extend([
            SERVER_PROFILE_NAME if index == 0 else POOL_PROFILE_NAME,
            f"--filter-{transport}={ports}",
            "--ipset-ip=" + ",".join(_sorted_ips(ip for member in members for ip in member.target.ips)),
            *strategy.args,
        ])
    separator = ["--new"] if profiles else []
    return [*global_args, *server_profiles, *separator, *profiles]
