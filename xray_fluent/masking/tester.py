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

from .model import OFF, Core, Masking, MaskingOverride, OverrideKind, ServerShape
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


TRANSFER_BYTES = 256 * 1024  # twice the 64 KB the freeze needs to show


@dataclass(frozen=True, slots=True)
class Candidate:
    """What one candidate sets as the server's own choice while measured (and when kept)."""

    id: str
    title: str
    override: MaskingOverride

    @classmethod
    def of(cls, preset: Preset) -> Candidate:
        return cls(preset.id, preset.title, MaskingOverride(OverrideKind.CUSTOM, preset.masking))


# Measured first: the comparison point; a working run proves the network itself is fine.
BASELINE = Candidate("baseline", "Без маскировки", OFF)


def _fits(masking: Masking, shape: ServerShape) -> bool:
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


def candidates(shape: ServerShape, current: Masking | None = None, presets: list[Preset] | None = None) -> list[Candidate]:
    """The baseline, the server's ``current`` set when it is no preset, then the fitting presets,
    strongest group first. Empty when nothing can act (Hysteria2: obfs is part of the link)."""
    fitting = sorted(
        (preset for preset in (presets if presets is not None else all_presets()) if _fits(preset.masking, shape)),
        key=lambda preset: preset.group,
    )
    if not fitting:
        return []
    chosen = [BASELINE]
    if current is not None and not current.is_empty and all(preset.masking != current for preset in fitting):
        chosen.append(Candidate("current", "Сейчас", MaskingOverride(OverrideKind.CUSTOM, current)))
    return chosen + [Candidate.of(preset) for preset in fitting]


@dataclass(frozen=True, slots=True)
class Step:
    candidate: Candidate
    transfer: int
    pause_before_ms: int


def plan(chosen: list[Candidate], rng: random.Random | None = None) -> list[Step]:
    rng = rng or random.Random()
    return [
        Step(candidate, transfer, rng.randint(*PAUSE_MS))
        for candidate in chosen
        for transfer in range(1, TRANSFERS_PER_CANDIDATE + 1)
    ]


@dataclass(frozen=True, slots=True)
class Measurement:
    """What the runner hands back for one candidate; ``connected`` False: the tunnel did not come up."""

    candidate: Candidate
    transfers: tuple[Transfer, ...]
    first_byte_ms: int | None = None
    connected: bool = True


@dataclass(frozen=True, slots=True)
class Ranked:
    candidate: Candidate
    verdict: Verdict
    reason: str
    first_byte_ms: int | None = None


_ORDER = {"pass": 0, "inconclusive": 1, "not_applicable": 2, "frozen": 3}


def reason(result: Verdict) -> str:
    if result.kind == "pass":
        return f"прошло без заморозки, {result.bytes_per_second // 1024} КБ/с"
    if result.kind == "frozen":
        return f"заморозка на {result.offset_bytes // 1024} КБ"
    if result.kind == "inconclusive":
        return f"не ясно: {result.reason}"
    return "проверка слишком мала, чтобы увидеть заморозку"


def rank(results: list[tuple[Candidate, Verdict, int | None]]) -> list[Ranked]:
    """Best first: passed (fastest first), then inconclusive, then frozen (later freeze first)."""
    ordered = sorted(results, key=lambda item: (_ORDER[item[1].kind], -item[1].bytes_per_second, -item[1].offset_bytes))
    return [Ranked(candidate, result, reason(result), first_byte) for candidate, result, first_byte in ordered]


def judge(measurements: list[Measurement]) -> list[Ranked]:
    """Verdicts of a whole run, best first. The control is the run itself: the most bytes any
    transfer carried through the same tunnel to the same target."""
    control = max((t.total_bytes for m in measurements for t in m.transfers), default=0)
    results = []
    for measurement in measurements:
        if not measurement.connected:
            result = Verdict("inconclusive", reason="туннель не поднялся с этими настройками")
        else:
            result = verdict(list(measurement.transfers), control)
        results.append((measurement.candidate, result, measurement.first_byte_ms))
    return rank(results)
