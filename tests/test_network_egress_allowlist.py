"""Сетевые вызовы приложения — только в известных местах.

Требование незаметности (шлюз проверок, ``xray_fluent/network/probe_gate.py``):
приложение само не стучится ни к серверам, ни к сторонним сайтам, кроме мест,
которые прошли разбор. Новый ``create_connection``/``getaddrinfo``/``urlopen``
в другом модуле роняет этот тест: сначала реши, через какое правило шлюза идёт
новая проверка (текущий сервер — по сигналу, кандидат — в замене, по кнопке —
по одному), потом добавь модуль сюда с причиной.
"""

from __future__ import annotations

import ast
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1] / "xray_fluent"

PRIMITIVES = {
    "create_connection", "getaddrinfo", "gethostbyname", "gethostbyname_ex",
    "urlopen", "build_opener", "OpenerDirector", "HTTPSConnection", "HTTPConnection",
    "socket",  # только вызов socket.socket(...)
}

# модуль → разрешённые примитивы. Причина — в комментарии.
ALLOWED: dict[str, set[str]] = {
    # Локальные порты: свободен ли порт на 127.0.0.1 перед запуском ядра.
    "application/connection_service.py": {"socket"},
    "application/controller.py": {"socket"},
    "application/port_allocator.py": {"socket"},
    "engines/singbox/runtime_planner.py": {"socket"},
    # API ядра на 127.0.0.1 (clash/selector), готовность локальных портов;
    # подтверждение обрыва — один запрос через локальный прокси ядра (внутри
    # туннеля) и только по сигналу «запросы без ответа».
    "diagnostics/live_metrics_worker.py": {"urlopen", "build_opener"},
    "platform/windows/process_traffic_collector.py": {"urlopen"},
    "engines/singbox/selector_api.py": {"build_opener"},
    "engines/sidecar/readiness.py": {"create_connection"},
    "network/proxy_readiness.py": {"create_connection"},
    # Проверки через локальный SOCKS ядра — внутри туннеля.
    "engines/socks_probe.py": {"create_connection"},
    # «Проверить сайт»: домен вводит пользователь, по нажатию.
    "application/route_check.py": {"getaddrinfo"},
    # Адрес выбранного сервера: DoH, системный резолвер — только если DoH не ответил.
    "network/bootstrap_dns.py": {"HTTPSConnection", "getaddrinfo"},
    # Подписка: https напрямую или через туннель; http:// — только через туннель.
    "importer/subscription_http.py": {"build_opener"},
    # Обновления приложения и ядер — наш сервер обновлений и GitHub, HTTPS.
    "network/http_utils.py": {"build_opener", "urlopen"},
    "updates/app_updater.py": {"build_opener"},
    "updates/release_watch.py": {"urlopen"},
    "updates/update_checker.py": {"urlopen"},
    "engines/singbox/core_updater.py": {"urlopen"},
    "engines/xray/core_updater.py": {"urlopen"},
    # Смена сети: UDP connect без отправки пакетов (выбор интерфейса).
    "network/network_monitor.py": {"socket"},
    # Проверки серверов — правила шлюза: пинг по кнопке по одному с паузой,
    # скорость по кнопке с паузой и кандидат умной замены в бюджете шлюза.
    "network/ping_worker.py": {"create_connection"},
    "network/speed_test_worker.py": {"build_opener", "create_connection", "socket"},
    "network/connectivity_test.py": {"build_opener"},
}


def _calls(path: Path) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Attribute):
            name = func.attr
            if name == "socket" and not (isinstance(func.value, ast.Name) and func.value.id == "socket"):
                continue
        elif isinstance(func, ast.Name):
            name = func.id
            if name == "socket":
                continue
        else:
            continue
        if name in PRIMITIVES:
            found.add(name)
    return found


class NetworkEgressAllowlistTest(unittest.TestCase):
    def test_network_primitives_only_in_reviewed_modules(self) -> None:
        unexpected: list[str] = []
        for path in sorted(ROOT.rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            module = path.relative_to(ROOT).as_posix()
            extra = _calls(path) - ALLOWED.get(module, set())
            if extra:
                unexpected.append(f"{module}: {sorted(extra)}")
        self.assertEqual(unexpected, [], "сетевой вызов вне разобранных мест — см. docstring теста")

    def test_allowlist_has_no_stale_entries(self) -> None:
        stale = [module for module in ALLOWED if not (ROOT / module).is_file() or not _calls(ROOT / module)]
        self.assertEqual(stale, [])


if __name__ == "__main__":
    unittest.main()
