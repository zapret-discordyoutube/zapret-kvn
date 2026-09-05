"""Display explicit provider flags without relying on Windows emoji fonts."""
from functools import lru_cache
import re

from .geoip import normalize_country

_FLAGS = re.compile('[\U0001f1e6-\U0001f1ff]{2}')


@lru_cache(maxsize=32768)
def name_country(name: str) -> str:
    match = _FLAGS.search(name or '')
    if not match:
        return ''
    return normalize_country(''.join(chr(ord(char) - 0x1F1E6 + ord('A')) for char in match.group()))


@lru_cache(maxsize=32768)
def display_name(name: str) -> str:
    return _FLAGS.sub('', name or '').strip() or 'Без имени'


def node_country(node) -> str:
    return normalize_country(node.country_override) or name_country(node.name) or normalize_country(node.country_code)
