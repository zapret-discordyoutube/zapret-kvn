"""Ссылки страницы «О нас». Других мест, где они записаны, в приложении нет.

Модуль без Qt: его читают тесты и его можно импортировать где угодно.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class AboutUsLink:
    title: str
    subtitle: str
    url: str


# Рекламная метка deep-link бота: источник kvnwin + место about.
# Метка не менялась при переезде ссылок на страницу «О нас»: её ждёт статистика бота.
BOT_ABOUT_URL = "https://t.me/zapretvpns_bot?start=kvnwin_about"

# Зеркало-переадресатор: вики и Git открываются через него, пока основные домены закрыты.
MIRROR_URL = (
    "https://script.google.com/macros/s/"
    "AKfycbzcEPk67WW6fYC0vPVm397QyDFHd4m-SrfKDBnfvG8jAD-n_HXVv8AqQnEHZ6A42oIh/exec"
)

#: Главный VPN-бот, где покупают подписку: стоит над всем остальным.
BOT = AboutUsLink("Zapret VPN bot", "Главный VPN-бот: здесь можно купить подписку", BOT_ABOUT_URL)

CHANNELS: tuple[AboutUsLink, ...] = (
    AboutUsLink("Zapret KVN", "Telegram-канал", "https://t.me/bypassblock"),
    AboutUsLink("VPN Discord YouTube", "Telegram-сообщество", "https://t.me/vpndiscordyooutube"),
    AboutUsLink("RuNet VPN YouTube Discord", "Telegram-канал", "https://t.me/runetvpnyoutubediscord"),
    AboutUsLink("Zastogram", "Telegram-канал", "https://t.me/zastogram"),
)

#: Главные ресурсы проекта и запасные списки адресов на случай блокировки основных.
RESOURCES: tuple[AboutUsLink, ...] = (
    AboutUsLink("Вики", "Инструкции и ответы на вопросы", f"{MIRROR_URL}?s=wiki"),
    AboutUsLink("Git", "Исходный код и релизы", f"{MIRROR_URL}?s=git"),
    AboutUsLink(
        "Резервный список адресов",
        "Документ Google",
        "https://docs.google.com/document/d/1v1TeRSBpXEJpy6qxNa3tVkyhgtoM_rj_T-jwphhfvYI/",
    ),
    AboutUsLink(
        "Ещё один резервный список",
        "GitHub Gist",
        "https://gist.github.com/fuckyourkn/ecb9b6a03f53bddcdd47023ebc12d4f9",
    ),
)

ALL: tuple[AboutUsLink, ...] = (BOT, *CHANNELS, *RESOURCES)
