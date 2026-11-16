"""Named starting points, identical to Android `MaskingPresets`. Every number stays editable;
the tester tries several of them on the user's own network. Group order = expected benefit."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

from .model import Desync, Masking, MuxCool, SingboxFragment, Span, WireGuardMasking, XrayFragment, XrayShaping, Xmux
from .wireguard import DNS_DOMAINS, dns_chain


class Group(IntEnum):
    WIREGUARD = 0
    XRAY = 1
    EXPERIMENT = 2


@dataclass(frozen=True, slots=True)
class Preset:
    id: str
    group: Group
    title: str
    note: str
    masking: Masking


def wireguard_dns(domain: str = DNS_DOMAINS[0]) -> Preset:
    chain = dns_chain(domain)
    if chain is None:
        raise ValueError("preset domain must be valid")
    return Preset(
        "wg-dns", Group.WIREGUARD, "Плановый DNS",
        f"Перед рукопожатием уходит пакет, похожий на DNS-запрос к {domain}, и немного мусора. "
        "Работает и с обычным WireGuard-сервером.",
        Masking(wireguard=WireGuardMasking(jc=3, jmin=10, jmax=30, signatures={"i1": chain})),
    )


WIREGUARD_MORE_JUNK = Preset(
    "wg-more-junk", Group.WIREGUARD, "Больше мусора",
    "Больше мусорных пакетов разного размера перед рукопожатием. Каждый меньше MTU, чтобы не дробиться.",
    Masking(wireguard=WireGuardMasking(jc=6, jmin=40, jmax=80)),
)
WIREGUARD_JUNK_ONLY = Preset(
    "wg-junk-only", Group.WIREGUARD, "Только junk",
    "Только мусорные пакеты, без сигнатурного I1: для сетей, где пакет под DNS отбрасывают.",
    Masking(wireguard=WireGuardMasking(jc=3, jmin=10, jmax=30)),
)
XRAY_MUX = Preset(
    "xray-mux", Group.XRAY, "Mux (VLESS по TCP)",
    "Много запросов идут в нескольких долгих соединениях: меньше рукопожатий подряд. "
    "QUIC в mux отклоняется, приложения перейдут на TCP.",
    Masking(xray=XrayShaping(mux=MuxCool())),
)
XMUX_CORE_DEFAULT = Preset(
    "xmux-default", Group.XRAY, "XHTTP: как в ядре",
    "Значения самого Xray: 3 соединения, смена после 600-900 запросов или 30-50 минут.",
    Masking(xray=XrayShaping(xmux=Xmux())),
)
XMUX_ROTATE = Preset(
    "xmux-rotate", Group.XRAY, "XHTTP: частая смена",
    "Соединения живут недолго и несут мало данных: против заморозки соединения после ~16-30 КБ.",
    Masking(xray=XrayShaping(xmux=Xmux(
        max_concurrency=Span(16, 32), c_max_reuse_times=Span(8, 16),
        h_max_request_times=Span(60, 120), h_max_reusable_secs=Span(60, 120),
    ))),
)
XMUX_FEW = Preset(
    "xmux-few", Group.XRAY, "XHTTP: мало соединений",
    "Два долгих соединения: меньше рукопожатий подряд, но каждое несёт больше данных.",
    Masking(xray=XrayShaping(xmux=Xmux(max_connections=Span.of(2), h_max_reusable_secs=Span(1800, 3000)))),
)
XRAY_FRAGMENT = Preset(
    "xray-fragment", Group.EXPERIMENT, "Фрагментация TLS (Xray)",
    "Эксперимент. Первый пакет TLS режется на куски с паузами. Помогает против блокировки по имени "
    "сайта, но не против заморозки соединения.",
    Masking(xray=XrayShaping(fragment=XrayFragment())),
)
SINGBOX_FRAGMENT = Preset(
    "singbox-fragment", Group.EXPERIMENT, "Фрагментация TLS (Trojan, VMess)",
    "Эксперимент. То же для протоколов sing-box. На REALITY не действует.",
    Masking(singbox=SingboxFragment()),
)


def desync_fake(ttl: int) -> Preset:
    """Android's decoy presets differ by TTL; kept for the shared ids and the tests."""
    return Preset(
        f"desync-fake-{ttl}", Group.EXPERIMENT, f"Обманка, TTL {ttl}",
        "Эксперимент. Перед настоящим первым пакетом уходит пакет-обманка с другим именем сайта.",
        Masking(xray=XrayShaping(desync=Desync(method="fake", fake_ttl=ttl))),
    )


#: Windows decoy: sing-box `tls_spoof` over WinDivert. The decoy carries a wrong TCP sequence
#: number, so the server drops it whatever the TTL: one preset instead of Android's two.
DESYNC_FAKE = Preset(
    "desync-fake", Group.EXPERIMENT, "Обманка",
    "Эксперимент. Перед настоящим первым пакетом уходит пакет-обманка с другим именем сайта и "
    "неверным номером TCP: его видит фильтр, а сервер отбрасывает. Нужен драйвер WinDivert, "
    "на это время Zapret не трогает пакеты этого сервера.",
    Masking(xray=XrayShaping(desync=Desync(method="fake"))),
)

DESYNC_DISORDER = Preset(
    "desync-disorder", Group.EXPERIMENT, "Беспорядок пакетов",
    "Эксперимент. Начало первого пакета, с частью имени сайта, отправляется так, что теряется по пути, "
    "и уходит повторно после остального: фильтр видит куски не по порядку.",
    Masking(xray=XrayShaping(desync=Desync(method="disorder"))),
)

#: The Windows engine: sing-box `tls_spoof` (WinDivert) and core patch kvn-desync.patch.
DESYNC_ENGINE_AVAILABLE = True


def desync_presets() -> list[Preset]:
    return [DESYNC_FAKE, DESYNC_DISORDER]


def all_presets() -> list[Preset]:
    return [
        wireguard_dns(), WIREGUARD_MORE_JUNK, WIREGUARD_JUNK_ONLY,
        XRAY_MUX, XMUX_CORE_DEFAULT, XMUX_ROTATE, XMUX_FEW,
        XRAY_FRAGMENT, *(desync_presets() if DESYNC_ENGINE_AVAILABLE else []), SINGBOX_FRAGMENT,
    ]
