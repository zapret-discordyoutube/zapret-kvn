""""Подбор": the freeze verdict, candidate choice, run plan and ranking (same as Android
`masking/tester`). Pure: the worker runs each step through the connected tunnel and hands
the sampled numbers of the tunnel's OUTER connection here.

FROZEN = bytes stop >= 8 s at the same offset on two transfers AND a control transfer carried
>= 64 KB (net4people #490, pwnnex/ByeByeVPN). FIN/RST is inconclusive; a target < 64 KB
cannot show the freeze. Must not expose servers: one target, sequential, jittered pauses,
no fan-out, never a UDP probe of the VPN server.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from enum import Enum

from .model import Core, ServerShape
from .presets import Preset, all_presets

STALL_MS = 8_000
MIN_TARGET_BYTES = 64 * 1024
SAME_OFFSET_BYTES = 4 * 1024
SAME_OFFSET_SHARE = 0.25
PAUSE_MS = (1_500, 4_000)
TRANSFERS_PER_CANDIDATE = 2


class End(str, Enum):
    COMPLETED = "completed"
    RESET = "reset"
    TIMEOUT = "timeout"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class Transfer:
    samples: tuple[tuple[int, int], ...]  # (at_ms, bytes)
    end: End
    target_bytes: int | None

    @property
    def total_bytes(self) -> int:
        return max((value for _, value in self.samples), default=0)

    @property
    def duration_ms(self) -> int:
        return self.samples[-1][0] - self.samples[0][0] if len(self.samples) >= 2 else 0


@dataclass(frozen=True, slots=True)
class Verdict:
    kind: str  # pass | frozen | inconclusive | not_applicable
    bytes_per_second: int = 0
    offset_bytes: int = 0
    reason: str = ""


def longest_stall(transfer: Transfer) -> tuple[int, int] | None:
    """(offset bytes, stall ms) of the longest pause."""
    if not transfer.samples:
        return None
    best: tuple[int, int] | None = None
    since_at, since_bytes = transfer.samples[0]
    for at, value in transfer.samples[1:]:
        if value > since_bytes:
            since_at, since_bytes = at, value
            continue
        length = at - since_at
        if best is None or length > best[1]:
            best = (since_bytes, length)
    return best


def same_offset(a: int, b: int) -> bool:
    return abs(a - b) <= max(SAME_OFFSET_BYTES, int(max(a, b) * SAME_OFFSET_SHARE))


def verdict(transfers: list[Transfer], control_bytes: int) -> Verdict:
    if not transfers:
        return Verdict("inconclusive", reason="нет данных")
    if all((t.target_bytes if t.target_bytes is not None else MIN_TARGET_BYTES) < MIN_TARGET_BYTES for t in transfers):
        return Verdict("not_applicable")
    stalls = []
    for transfer in transfers:
        stall = longest_stall(transfer)
        if stall and stall[1] >= STALL_MS and transfer.end is not End.COMPLETED:
            stalls.append(stall)
    if len(stalls) >= 2:
        first, second = sorted(stalls)[:2]
        if same_offset(first[0], second[0]):
            if control_bytes < MIN_TARGET_BYTES:
                return Verdict("inconclusive", reason="контрольная загрузка тоже не прошла")
            return Verdict("frozen", offset_bytes=(first[0] + second[0]) // 2)
    completed = [t for t in transfers if t.end is End.COMPLETED and t.total_bytes >= MIN_TARGET_BYTES]
    if completed:
        rate = max(t.total_bytes * 1000 // t.duration_ms if t.duration_ms > 0 else 0 for t in completed)
        return Verdict("pass", bytes_per_second=rate)
    if any(t.end is End.RESET for t in transfers):
        return Verdict("inconclusive", reason="соединение сброшено (FIN/RST), это не заморозка")
    return Verdict("inconclusive", reason="загрузка не завершилась")


def candidates(shape: ServerShape, presets: list[Preset] | None = None) -> list[Preset]:
    def fits(preset: Preset) -> bool:
        masking = preset.masking
        if shape.core is Core.AMNEZIA:
            return masking.wireguard is not None
        if shape.core is Core.XRAY and masking.xray is not None:
            if masking.xray.xmux is not None:
                return shape.is_xhttp
            if masking.xray.mux is not None:
                return not shape.is_multiplexed_transport
            return masking.xray.fragment is not None and shape.is_tcp_stream
        if shape.core is Core.SINGBOX:
            return masking.singbox is not None and shape.security == "tls"
        return False

    chosen = [preset for preset in (presets if presets is not None else all_presets()) if fits(preset)]
    return sorted(chosen, key=lambda preset: preset.group)


@dataclass(frozen=True, slots=True)
class Step:
    preset: Preset
    transfer: int
    pause_before_ms: int


def plan(chosen: list[Preset], rng: random.Random | None = None) -> list[Step]:
    rng = rng or random.Random()
    return [
        Step(preset, transfer, rng.randint(*PAUSE_MS))
        for preset in chosen
        for transfer in range(1, TRANSFERS_PER_CANDIDATE + 1)
    ]


_ORDER = {"pass": 0, "inconclusive": 1, "not_applicable": 2, "frozen": 3}


def reason(result: Verdict) -> str:
    if result.kind == "pass":
        return f"прошло без заморозки, {result.bytes_per_second // 1024} КБ/с"
    if result.kind == "frozen":
        return f"заморозка на {result.offset_bytes // 1024} КБ"
    if result.kind == "inconclusive":
        return f"не ясно: {result.reason}"
    return "проверка слишком мала, чтобы увидеть заморозку"


def rank(results: list[tuple[Preset, Verdict]]) -> list[tuple[Preset, Verdict, str]]:
    ordered = sorted(results, key=lambda item: (_ORDER[item[1].kind], -item[1].bytes_per_second, -item[1].offset_bytes))
    return [(preset, result, reason(result)) for preset, result in ordered]
