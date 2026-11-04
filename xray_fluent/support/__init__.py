"""Обращение в поддержку: готовый архив журналов и страница на открытом зеркале.

Раньше человек присылал «что нашёл»: скриншот, кусок журнала, иногда ссылку
подписки. Модуль собирает одно и то же каждый раз — редактированный архив
(``diagnostics`` + журналы установки и запуска, версия, система) — и открывает
страницу обращений на том имени нашего сайта, которое сейчас открывается
(общее ядро ``zapret_update.mirrors``, то же, что у проверки обновлений).
"""

from .bundle import SupportBundle, append_support_files, redact_support_text
from .site import SUPPORT_PATH, support_url

__all__ = ["SUPPORT_PATH", "SupportBundle", "append_support_files", "redact_support_text", "support_url"]
