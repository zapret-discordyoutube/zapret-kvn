"""Read existing Windows DNS cache entries. Never resolve or refresh a name."""
from __future__ import annotations

import json
import os
import sys
from subprocess import TimeoutExpired
from ipaddress import ip_address
from pathlib import Path

from .subprocess_utils import CREATE_NO_WINDOW, run_text, result_output_text

# No hostnames interpolated, no remote CIM session and no resolving cmdlet.
_CACHE_COMMAND = (
    "$ErrorActionPreference='Stop'; "
    "Get-DnsClientCache | Select-Object Entry,Name,RecordName,RecordType,Type,Status,TimeToLive,Data "
    "| ConvertTo-Json -Compress"
)


def host_key(host: str) -> str:
    try:
        return host.strip().rstrip('.').encode('idna').decode('ascii').lower()
    except (UnicodeError, ValueError):
        return ''


def cached_addresses(records) -> dict[str, tuple[str, ...]]:
    """Follow CNAME chains only inside this snapshot; omit expired/negative records."""
    if isinstance(records, dict):
        records = [records]
    if not isinstance(records, list):
        return {}
    ips, aliases = {}, {}
    for record in records:
        if not isinstance(record, dict):
            continue
        try:
            if int(record.get('TimeToLive') or 0) <= 0:
                continue
        except (TypeError, ValueError):
            continue
        if str(record.get('Status', '')).lower() not in {'0', 'success'}:
            continue
        kind = str(record.get('RecordType') or record.get('Type') or '').upper()
        data = str(record.get('Data') or '').strip()
        names = {host_key(str(record.get(key) or '')) for key in ('Entry', 'Name', 'RecordName')}
        names.discard('')
        if kind in {'1', '28', 'A', 'AAAA'}:
            try:
                address = ip_address(data)
            except ValueError:
                continue
            if address.is_global:
                for name in names:
                    ips.setdefault(name, set()).add(str(address))
        elif kind in {'5', 'CNAME'}:
            for name in names:
                aliases.setdefault(name, set()).add(host_key(data))

    def collect(name, seen):
        if name in seen or len(seen) > 32:
            return set()
        found = set(ips.get(name, ()))
        for target in aliases.get(name, ()):
            found.update(collect(target, seen | {name}))
        return found
    return {name: tuple(sorted(collect(name, set()))) for name in ips.keys() | aliases.keys()}


def read_dns_cache() -> dict[str, tuple[str, ...]]:
    if sys.platform != 'win32':
        return {}
    executable = Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32' / 'WindowsPowerShell' / 'v1.0' / 'powershell.exe'
    try:
        result = run_text([str(executable), '-NoLogo', '-NoProfile', '-NonInteractive', '-Command', _CACHE_COMMAND], timeout=5, creationflags=CREATE_NO_WINDOW)
        if result.returncode:
            return {}
        return cached_addresses(json.loads(result_output_text(result)))
    except (OSError, ValueError, TimeoutExpired):
        return {}
