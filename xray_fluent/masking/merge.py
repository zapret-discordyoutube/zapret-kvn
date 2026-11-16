"""The one decision "which masking does this server get" (same as Android `MaskingMerge`).

Master switch off or override OFF: nothing. CUSTOM: each section present replaces the global
one (even disabled), absent sections fall back to global. A section that does not fit the
server's native core, or has a validation error, is dropped with a note.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import singbox as singbox_rules
from . import wireguard as wireguard_rules
from . import xray as xray_rules
from .model import NONE, Core, Masking, MaskingSettings, OverrideKind, ServerShape, errors


@dataclass(frozen=True, slots=True)
class Effective:
    masking: Masking
    notes: list[str] = field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        return self.masking.is_empty


def effective(settings: MaskingSettings, server_key: str | None, shape: ServerShape) -> Effective:
    if not settings.enabled:
        return Effective(NONE)
    override = settings.override_for(server_key)
    if override.kind is OverrideKind.OFF:
        return Effective(NONE, ["Маскировка выключена для этого сервера."])
    chosen = settings.global_masking
    if override.kind is OverrideKind.CUSTOM:
        custom = override.masking
        chosen = Masking(
            wireguard=custom.wireguard if custom.wireguard is not None else chosen.wireguard,
            xray=custom.xray if custom.xray is not None else chosen.xray,
            singbox=custom.singbox if custom.singbox is not None else chosen.singbox,
        )
    notes: list[str] = []
    wireguard = chosen.wireguard if chosen.wireguard is not None and chosen.wireguard.enabled else None
    if wireguard is not None:
        if shape.core is not Core.AMNEZIA:
            wireguard = None
        elif errors(wireguard_rules.validate(wireguard)):
            notes.append("WireGuard-маскировка пропущена: в ней ошибка.")
            wireguard = None
    xray = chosen.xray if chosen.xray is not None and chosen.xray.enabled else None
    if xray is not None:
        if shape.core is not Core.XRAY:
            xray = None
        elif errors(xray_rules.validate(xray)):
            notes.append("Настройки Xray пропущены: в них ошибка.")
            xray = None
    singbox = chosen.singbox if chosen.singbox is not None and chosen.singbox.enabled else None
    if singbox is not None:
        if not singbox_rules.applies(shape):
            singbox = None
        elif errors(singbox_rules.validate(singbox)):
            notes.append("Фрагментация TLS пропущена: в ней ошибка.")
            singbox = None
    if shape.core is Core.HYSTERIA and not chosen.is_empty:
        notes.append("Для Hysteria2 маскировка задаётся в самой ссылке (obfs salamander).")
    return Effective(Masking(wireguard=wireguard, xray=xray, singbox=singbox), notes)
