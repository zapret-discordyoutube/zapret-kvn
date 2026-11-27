"""The stock NaiveProxy client (klzgrad/naiveproxy) as the native core of ``naive+https`` keys.

Naive is Chromium's network stack: it runs as its own helper process (``core/naive.exe``) that listens on a loopback
SOCKS5 port with random credentials, and the sing-box front dials that port, exactly like the Hysteria2 and Xray helpers.
"""

from .key import NaiveKey, NaiveKeyError, helper_config, parse_naive_key

__all__ = ["NaiveKey", "NaiveKeyError", "helper_config", "parse_naive_key"]
