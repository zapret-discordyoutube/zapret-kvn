"""What each built-in service slot matches on Windows.

The same services as on Android (android/app/.../slots/*Slot.kt): the names and the Telegram ranges are shared, the
apps are Windows process names. A browser tab is caught by its names, which is the main Windows case.
"""

from __future__ import annotations

from dataclasses import dataclass

YOUTUBE = "youtube"
AI = "ai"
TELEGRAM = "telegram"


@dataclass(frozen=True, slots=True)
class SlotSpec:
    id: str
    title: str
    domain_suffixes: tuple[str, ...]
    process_names: tuple[str, ...] = ()
    ip_cidrs: tuple[str, ...] = ()


# Same list as the template's always-proxy YouTube rule and Android's ForcedProxyDomains.
YOUTUBE_DOMAINS = (
    "googlevideo.com",
    "youtube.com",
    "youtu.be",
    "ytimg.com",
    "ggpht.com",
    "youtube-nocookie.com",
    "youtubei.googleapis.com",
)

AI_DOMAINS = (
    "openai.com",
    "chatgpt.com",
    "oaistatic.com",
    "oaiusercontent.com",
    "anthropic.com",
    "claude.ai",
    "gemini.google.com",
    "generativelanguage.googleapis.com",
    "perplexity.ai",
    "deepseek.com",
    "x.ai",
    "grok.com",
    "copilot.microsoft.com",
)

AI_PROCESSES = ("ChatGPT.exe", "Claude.exe", "claude.exe", "Perplexity.exe")

TELEGRAM_DOMAINS = ("telegram.org", "t.me", "telegram.me", "telesco.pe", "tdesktop.com", "telegra.ph")

# Telegram Desktop and its forks (ZaStoGram Desktop also ships as Telegram.exe).
TELEGRAM_PROCESSES = ("Telegram.exe", "AyuGram.exe", "64Gram.exe", "Kotatogram.exe", "Unigram.exe")

# Datacentre ranges: a client nobody listed is still caught by where it connects. IPv4 only, like the templates
# (dns strategy ipv4_only).
TELEGRAM_CIDRS = (
    "91.108.4.0/22",
    "91.108.8.0/22",
    "91.108.12.0/22",
    "91.108.16.0/22",
    "91.108.20.0/22",
    "91.108.56.0/22",
    "149.154.160.0/20",
    "185.76.151.0/24",
)

# Order is the routing order (first match wins), as on Android: AI, YouTube, Telegram.
BUILT_IN: tuple[SlotSpec, ...] = (
    SlotSpec(AI, "ИИ-приложения", AI_DOMAINS, AI_PROCESSES),
    SlotSpec(YOUTUBE, "YouTube", YOUTUBE_DOMAINS),
    SlotSpec(TELEGRAM, "Telegram", TELEGRAM_DOMAINS, TELEGRAM_PROCESSES, TELEGRAM_CIDRS),
)

BY_ID = {spec.id: spec for spec in BUILT_IN}
