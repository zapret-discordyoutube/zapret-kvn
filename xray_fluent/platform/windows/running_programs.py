"""Running programs grouped by the folder they are installed in (for the «Игры» helper of the routing rules).

A game is many processes (the client, the launcher, the updater, crash reporters...) and they live in one install folder.
One rule on that folder covers all of them, so the user picks FOLDERS, never processes. ``install_root`` decides which folder
is "the install" of a program; ``group_programs`` is pure, ``running_program_paths`` reads the list from Windows.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import os
from typing import Iterable

#: Folders whose children are separate installs: ``C:\Program Files (x86)\World of Warcraft``.
_INSTALL_PARENTS = frozenset({"program files", "program files (x86)", "programdata", "games", "game", "игры", "apps"})
#: Not games: the system itself and the user's profile plumbing.
_SKIP_ROOTS = frozenset({"windows", "$recycle.bin", "system volume information"})


@dataclass(frozen=True, slots=True)
class ProgramGroup:
    root: str       # the install folder with a trailing backslash: ``C:\Program Files (x86)\World of Warcraft\``
    name: str       # its last folder: ``World of Warcraft``
    processes: int  # how many running programs live under it


def install_root(path: str) -> str | None:
    """The install folder of a program (with a trailing backslash), or None for system paths and bare names."""
    parts = [part for part in str(path or "").replace("/", "\\").split("\\") if part]
    if len(parts) < 3 or len(parts[0]) != 2 or parts[0][1] != ":":
        return None
    folders = parts[1:-1]  # without the drive and the file name
    if not folders or folders[0].lower() in _SKIP_ROOTS:
        return None
    lowered = [part.lower() for part in folders]
    if "steamapps" in lowered:
        at = lowered.index("steamapps")
        # Steam: ...\steamapps\common\<Game>\...: the game folder, not Steam itself
        if at + 2 < len(folders) and lowered[at + 1] == "common":
            return "\\".join(parts[: 1 + at + 3]) + "\\"
    if lowered[0] == "users":
        # C:\Users\<name>\AppData\Local|Roaming\<Vendor>\...: the vendor folder
        if len(folders) >= 5 and lowered[2] == "appdata" and lowered[3] in ("local", "roaming"):
            if lowered[4] == "microsoft":
                return None
            return "\\".join(parts[:6]) + "\\"
        return None
    depth = 2 if lowered[0] in _INSTALL_PARENTS else 1
    if len(folders) < depth:
        return None
    return "\\".join(parts[: 1 + depth]) + "\\"


def group_programs(paths: Iterable[str]) -> list[ProgramGroup]:
    """Programs counted per install folder, the busiest first (a game with a launcher tops the list)."""
    counts: Counter[str] = Counter()
    spelling: dict[str, str] = {}  # Windows paths ignore the case: one folder, the first spelling shown
    for path in paths:
        root = install_root(path)
        if root:
            key = root.casefold()
            counts[key] += 1
            spelling.setdefault(key, root)
    groups = [
        ProgramGroup(spelling[key], spelling[key].rstrip("\\").rsplit("\\", 1)[-1], count)
        for key, count in counts.items()
    ]
    return sorted(groups, key=lambda group: (-group.processes, group.name.casefold()))


def _image_path(kernel32, pid: int, buffer) -> str | None:
    import ctypes
    from ctypes import wintypes

    handle = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
    if not handle:
        return None
    try:
        size = wintypes.DWORD(len(buffer))
        if kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
            return buffer.value
        return None
    finally:
        kernel32.CloseHandle(handle)


def established_connections() -> list[tuple[str, str]]:
    """(program image path, remote address) of every ESTABLISHED TCP connection, IPv4 and IPv6 (Windows only)."""
    if os.name != "nt":
        return []
    import ctypes
    import socket
    from ctypes import wintypes

    iphlpapi, kernel32 = ctypes.WinDLL("iphlpapi"), ctypes.WinDLL("kernel32", use_last_error=True)
    established = 5  # MIB_TCP_STATE_ESTAB
    owner_pid_all = 5  # TCP_TABLE_OWNER_PID_ALL
    buffer = ctypes.create_unicode_buffer(1024)
    paths: dict[int, str | None] = {}
    result: list[tuple[str, str]] = []

    def path_of(pid: int) -> str | None:
        if pid not in paths:
            paths[pid] = _image_path(kernel32, pid, buffer)
        return paths[pid]

    for family in (socket.AF_INET, socket.AF_INET6):
        size = wintypes.DWORD(0)
        iphlpapi.GetExtendedTcpTable(None, ctypes.byref(size), False, family, owner_pid_all, 0)
        raw = (ctypes.c_ubyte * max(size.value, 4))()
        if iphlpapi.GetExtendedTcpTable(raw, ctypes.byref(size), False, family, owner_pid_all, 0) != 0:
            continue
        count = int.from_bytes(bytes(raw[0:4]), "little")
        # MIB_TCPROW_OWNER_PID: state, laddr, lport, raddr, rport, pid (6 x DWORD); MIB_TCP6ROW_OWNER_PID: laddr[16], lscope,
        # lport, raddr[16], rscope, rport, state, pid (16+4+4+16+4+4+4+4 = 56 bytes)
        width = 24 if family == socket.AF_INET else 56
        for index in range(count):
            row = bytes(raw[4 + index * width: 4 + (index + 1) * width])
            if len(row) < width:
                break
            if family == socket.AF_INET:
                state, remote, pid = (int.from_bytes(row[0:4], "little"), row[12:16], int.from_bytes(row[20:24], "little"))
            else:
                state, remote, pid = (int.from_bytes(row[48:52], "little"), row[24:40], int.from_bytes(row[52:56], "little"))
            if state != established or not pid:
                continue
            path = path_of(pid)
            if path:
                result.append((path, socket.inet_ntop(family, remote)))
    return result


def running_program_paths() -> list[str]:
    """Full paths of the programs running now (Windows only; empty elsewhere). Blocking, for a worker or a short call."""
    if os.name != "nt":
        return []
    import ctypes
    from ctypes import wintypes

    psapi, kernel32 = ctypes.WinDLL("psapi"), ctypes.WinDLL("kernel32", use_last_error=True)
    ids = (wintypes.DWORD * 4096)()
    needed = wintypes.DWORD()
    if not psapi.EnumProcesses(ids, ctypes.sizeof(ids), ctypes.byref(needed)):
        return []
    paths: list[str] = []
    buffer = ctypes.create_unicode_buffer(1024)
    for index in range(needed.value // ctypes.sizeof(wintypes.DWORD)):
        path = _image_path(kernel32, ids[index], buffer)
        if path:
            paths.append(path)
    return paths
