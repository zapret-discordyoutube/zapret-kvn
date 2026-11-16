"""What the Windows "Маскировка" controls show and write: preset choices for the global set
and for one server. Pure, so the Qt page and the node menu stay dumb views.

A global section the user tuned beyond the presets (through «Свои значения») reads as
CUSTOM and is kept as is until the user picks another choice for that section.
"""

from __future__ import annotations

from dataclasses import replace

from . import presets
from .model import (
    INHERIT,
    OFF,
    Masking,
    MaskingOverride,
    MaskingSettings,
    MuxCool,
    OverrideKind,
    XRAY_PROTOCOLS,
    SingboxFragment,
    XrayFragment,
    XrayShaping,
)

NONE_ID = "off"
CUSTOM_ID = "custom"

WIREGUARD_CHOICES: list[tuple[str, str]] = [
    (NONE_ID, "Выключена"),
    ("wg-dns", "Плановый DNS"),
    ("wg-more-junk", "Больше мусора"),
    ("wg-junk-only", "Только junk"),
]
XMUX_CHOICES: list[tuple[str, str]] = [
    (NONE_ID, "Выключено"),
    ("xmux-default", "Как в ядре"),
    ("xmux-rotate", "Частая смена"),
    ("xmux-few", "Мало соединений"),
]
DESYNC_CHOICES: list[tuple[str, str]] = [
    (NONE_ID, "Выключены"),
    ("desync-fake", "Обманка"),
    ("desync-disorder", "Беспорядок пакетов"),
]
CUSTOM_TITLE = "Свои значения"


def _preset(preset_id: str) -> presets.Preset | None:
    return next((preset for preset in presets.all_presets() if preset.id == preset_id), None)


def wireguard_choice(masking: Masking) -> str:
    section = masking.wireguard
    if section is None or not section.enabled:
        return NONE_ID
    for preset_id, _ in WIREGUARD_CHOICES[1:]:
        preset = _preset(preset_id)
        if preset is not None and preset.masking.wireguard == section:
            return preset_id
    return CUSTOM_ID


def xmux_choice(masking: Masking) -> str:
    xmux = masking.xray.xmux if masking.xray is not None and masking.xray.enabled else None
    if xmux is None:
        return NONE_ID
    for preset_id, _ in XMUX_CHOICES[1:]:
        preset = _preset(preset_id)
        if preset is not None and preset.masking.xray is not None and preset.masking.xray.xmux == xmux:
            return preset_id
    return CUSTOM_ID


def desync_choice(masking: Masking) -> str:
    desync = masking.xray.desync if masking.xray is not None and masking.xray.enabled else None
    if desync is None or not desync.enabled:
        return NONE_ID
    for preset_id, _ in DESYNC_CHOICES[1:]:
        preset = _preset(preset_id)
        if preset is not None and preset.masking.xray is not None and preset.masking.xray.desync == desync:
            return preset_id
    return CUSTOM_ID


def mux_on(masking: Masking) -> bool:
    xray = masking.xray
    return bool(xray and xray.enabled and xray.mux and xray.mux.enabled)


def xray_fragment_on(masking: Masking) -> bool:
    xray = masking.xray
    return bool(xray and xray.enabled and xray.fragment and xray.fragment.enabled)


def singbox_fragment_on(masking: Masking) -> bool:
    return bool(masking.singbox and masking.singbox.enabled)


def compose_global(
    current: Masking, *, wireguard: str, mux: bool, xmux: str, xray_fragment: bool, singbox_fragment: bool,
    desync: str = CUSTOM_ID,
) -> Masking:
    """The global set after the controls changed; CUSTOM keeps the current section."""
    if wireguard == CUSTOM_ID:
        wg_section = current.wireguard
    elif wireguard == NONE_ID:
        wg_section = None
    else:
        preset = _preset(wireguard)
        wg_section = preset.masking.wireguard if preset is not None else None

    current_xray = current.xray if current.xray is not None and current.xray.enabled else XrayShaping()
    if xmux == CUSTOM_ID:
        xmux_section = current_xray.xmux
    elif xmux == NONE_ID:
        xmux_section = None
    else:
        preset = _preset(xmux)
        xmux_section = preset.masking.xray.xmux if preset is not None and preset.masking.xray else None
    mux_section = (current_xray.mux if current_xray.mux is not None and current_xray.mux.enabled else MuxCool()) if mux else None
    fragment_section = (
        current_xray.fragment if current_xray.fragment is not None and current_xray.fragment.enabled else XrayFragment()
    ) if xray_fragment else None
    if desync == CUSTOM_ID:
        desync_section = current_xray.desync
    elif desync == NONE_ID:
        desync_section = None
    else:
        preset = _preset(desync)
        desync_section = preset.masking.xray.desync if preset is not None and preset.masking.xray else None
    xray = XrayShaping(mux=mux_section, xmux=xmux_section, fragment=fragment_section, desync=desync_section)
    if xray.mux is None and xray.xmux is None and xray.fragment is None and xray.desync is None:
        xray = None

    singbox = (current.singbox if current.singbox is not None and current.singbox.enabled else SingboxFragment()) if singbox_fragment else None
    return Masking(wireguard=wg_section, xray=xray, singbox=singbox)


def server_choices(protocol: str) -> list[tuple[str, str]]:
    """(choice id, title) for one server: inherit, off, then the presets that fit its protocol."""
    protocol = protocol.lower()
    result = [("inherit", "Как в общих"), ("off", "Выключить")]
    for preset in presets.all_presets():
        masking = preset.masking
        fits = (
            (protocol in {"wireguard", "awg"} and masking.wireguard is not None)
            or (protocol in XRAY_PROTOCOLS and masking.xray is not None)
            or (protocol not in {"wireguard", "awg", "hy2", "hysteria2"} | XRAY_PROTOCOLS and masking.singbox is not None)
        )
        if fits:
            result.append((preset.id, preset.title))
    return result


def with_override(settings: MaskingSettings, node_ids: set[str], choice_id: str) -> MaskingSettings:
    overrides = dict(settings.overrides)
    for node_id in node_ids:
        if choice_id == "inherit":
            overrides.pop(node_id, None)
        elif choice_id == "off":
            overrides[node_id] = OFF
        else:
            preset = _preset(choice_id)
            if preset is None:
                raise ValueError(f"unknown masking choice: {choice_id}")
            overrides[node_id] = MaskingOverride(OverrideKind.CUSTOM, preset.masking)
    return replace(settings, overrides=overrides)


def override_label(override: MaskingOverride) -> str:
    if override.kind is OverrideKind.INHERIT:
        return "Как в общих"
    if override.kind is OverrideKind.OFF:
        return "Выключена"
    match = next((preset for preset in presets.all_presets() if preset.masking == override.masking), None)
    return match.title if match is not None else "Своя"


__all__ = [
    "CUSTOM_ID", "CUSTOM_TITLE", "DESYNC_CHOICES", "INHERIT", "NONE_ID", "WIREGUARD_CHOICES", "XMUX_CHOICES",
    "compose_global", "desync_choice", "mux_on", "override_label", "server_choices", "singbox_fragment_on",
    "wireguard_choice", "with_override", "xmux_choice", "xray_fragment_on",
]
