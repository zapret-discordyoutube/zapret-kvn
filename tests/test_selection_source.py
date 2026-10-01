"""Источник смены выбранного сервера: каждая смена называет себя в логе.

Инцидент 28.09.2026: сервер сменился, а в логе был только ``[core-switch]``
без причины — явное действие (кнопка «Следующий», трей, таблица) было
неотличимо от сбоя.  Инвариант держится статически (AST по ``xray_fluent``),
а не только проверкой на рантайме: обязательный ``source=`` падает TypeError
лишь на выполненной строке, а лямбды трея/главной тесты не вызывают.
"""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
import unittest

from xray_fluent.application import node_service
from xray_fluent.application.selection_source import SelectionSource
from xray_fluent.diagnostics.runtime_logging import node_ref
from xray_fluent.profiles.models import Node


PACKAGE = Path(__file__).resolve().parents[1] / "xray_fluent"

# Функции, которым разрешено присваивать ``.selected_node_id``.  Для каждой
# указано, кто пишет ``[select]``: сама функция (проверяется ниже) или вызывающий.
SELECTION_WRITERS: dict[tuple[str, str], str] = {
    ("application/node_service.py", "set_selected_node"): "self",
    ("application/node_service.py", "import_nodes_from_text"): "self",
    ("application/node_service.py", "remove_nodes"): "self",
    ("application/controller.py", "AppController._apply_subscription_update"): "self",
    # Чистые функции над AppState: лог пишет AppController вокруг вызова.
    ("application/subscription_service.py", "reconcile_subscription"): "caller",
    ("application/subscription_service.py", "remove_subscription"): "caller",
    ("application/subscription_service.py", "hide_subscription_node"): "caller",
    # Фиксация pending-выбора, уже записанного в лог при запросе
    # (set_selected_node для Amnezia, начало восстановления Hysteria).
    ("application/controller.py", "AppController._commit_pending_transport_selection"): "pending",
}

# Команды смены сервера: каждый вызов обязан передать source=.
SWITCH_COMMANDS = {"set_selected_node", "set_selected_node_operation", "switch_next_node"}


def _modules():
    for path in sorted(PACKAGE.rglob("*.py")):
        yield path.relative_to(PACKAGE).as_posix(), ast.parse(path.read_text(encoding="utf-8"))


class _Scoped(ast.NodeVisitor):
    def __init__(self) -> None:
        self.stack: list[str] = []

    def _scoped(self, node) -> None:
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()

    visit_FunctionDef = visit_AsyncFunctionDef = visit_ClassDef = _scoped

    @property
    def qualname(self) -> str:
        return ".".join(self.stack)


def _is_controller_switch_call(call: ast.Call) -> str | None:
    """Имя команды смены сервера или None.

    У страниц UI есть одноимённый метод отображения
    (``dashboard_page.set_selected_node(node)``) — это не смена сервера, поэтому
    атрибутный вызов учитывается только у контроллера (``controller``/``self``
    внутри application).
    """

    func = call.func
    if isinstance(func, ast.Name) and func.id in SWITCH_COMMANDS:
        return func.id
    if isinstance(func, ast.Attribute) and func.attr in SWITCH_COMMANDS:
        receiver = func.value
        name = receiver.attr if isinstance(receiver, ast.Attribute) else getattr(receiver, "id", "")
        if name in {"controller", "self"}:
            return func.attr
    return None


class SelectionInvariantTests(unittest.TestCase):
    def test_every_switch_command_names_its_source(self) -> None:
        missing: list[str] = []
        seen = 0
        for rel, tree in _modules():
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                name = _is_controller_switch_call(node)
                if name is None:
                    continue
                if rel.startswith("ui/") and isinstance(node.func, ast.Attribute):
                    receiver = node.func.value
                    if not (isinstance(receiver, ast.Attribute) and receiver.attr == "controller"):
                        continue  # метод отображения страницы, не команда
                seen += 1
                if not any(keyword.arg == "source" for keyword in node.keywords):
                    missing.append(f"{rel}:{node.lineno} {name}(...)")
        self.assertGreater(seen, 5, "AST-поиск команд смены сервера ничего не нашёл")
        self.assertEqual(missing, [], "вызов без source=: смена сервера без записи в логе")

    def test_selected_node_id_is_written_only_by_known_functions(self) -> None:
        found: dict[tuple[str, str], list[ast.AST]] = {}
        functions: dict[tuple[str, str], ast.AST] = {}

        for rel, tree in _modules():
            visitor = _Scoped()

            def record(target, rel=rel, visitor=visitor) -> None:
                if isinstance(target, ast.Attribute) and target.attr == "selected_node_id":
                    found.setdefault((rel, visitor.qualname), []).append(target)

            def visit_assign(node, visitor=visitor, record=record):
                for target in node.targets:
                    record(target)
                visitor.generic_visit(node)

            def visit_single(node, visitor=visitor, record=record):
                record(node.target)
                visitor.generic_visit(node)

            def visit_function(node, rel=rel, visitor=visitor):
                visitor.stack.append(node.name)
                functions[(rel, visitor.qualname)] = node
                visitor.generic_visit(node)
                visitor.stack.pop()

            visitor.visit_Assign = visit_assign
            visitor.visit_AugAssign = visit_single
            visitor.visit_AnnAssign = visit_single
            visitor.visit_FunctionDef = visit_function
            visitor.visit_AsyncFunctionDef = visit_function
            visitor.visit(tree)

        unexpected = sorted(f"{rel} {qualname}" for rel, qualname in set(found) - set(SELECTION_WRITERS))
        self.assertEqual(unexpected, [], "новое место смены selected_node_id: пропустите его через "
                         "set_selected_node(source=...) или log_selection_change")
        stale = sorted(f"{rel} {qualname}" for rel, qualname in set(SELECTION_WRITERS) - set(found))
        self.assertEqual(stale, [], "устаревшая запись в SELECTION_WRITERS")

        for key, who in SELECTION_WRITERS.items():
            if who != "self":
                continue
            calls = {
                getattr(node.func, "id", getattr(node.func, "attr", ""))
                for node in ast.walk(functions[key])
                if isinstance(node, ast.Call)
            }
            self.assertIn("log_selection_change", calls, f"{key}: смена без [select] в логе")

    def test_subscription_writers_are_logged_by_the_controller(self) -> None:
        controller = (PACKAGE / "application" / "controller.py").read_text(encoding="utf-8")
        tree = ast.parse(controller)
        callers: dict[str, set[str]] = {}
        for cls in (node for node in tree.body if isinstance(node, ast.ClassDef)):
            for method in (node for node in cls.body if isinstance(node, ast.FunctionDef)):
                names = {
                    getattr(call.func, "id", getattr(call.func, "attr", ""))
                    for call in ast.walk(method)
                    if isinstance(call, ast.Call)
                }
                callers[method.name] = names
        for operation in (
            "reconcile_subscription",
            "remove_subscription_operation",
            "hide_subscription_node_operation",
        ):
            users = [name for name, calls in callers.items() if operation in calls]
            self.assertTrue(users, operation)
            for user in users:
                self.assertIn("log_selection_change", callers[user], f"{user} вызывает {operation} без [select]")


def _controller(selected: str = "a"):
    logs: list[str] = []
    resets: list[dict] = []
    controller = SimpleNamespace(
        state=SimpleNamespace(
            nodes=[Node(id="a", name="Tiraru", scheme="vless"), Node(id="b", name="Titiru", scheme="hysteria2")],
            selected_node_id=selected,
        ),
        _active_session=None,
        _pending_transport_node_id=None,
        connected=False,
        _desired_connected=False,
        selected_node=None,
        selection_changed=SimpleNamespace(emit=lambda node: None),
        schedule_save=lambda: None,
        _reset_auto_switch_state=lambda **kwargs: resets.append(kwargs),
        _log=logs.append,
    )
    return controller, logs, resets


class SelectionLogTests(unittest.TestCase):
    def test_switch_logs_source_and_node_refs(self) -> None:
        controller, logs, _ = _controller()
        node_service.set_selected_node(controller, "b", source=SelectionSource.TRAY_NEXT)
        self.assertEqual(controller.state.selected_node_id, "b")
        self.assertEqual(
            logs,
            [
                "[select] source=tray-next (трей → «Следующий сервер»): "
                f"«Tiraru» node_ref={node_ref('a')} → «Titiru» node_ref={node_ref('b')}"
            ],
        )

    def test_reselecting_current_server_is_silent(self) -> None:
        controller, logs, _ = _controller()
        node_service.set_selected_node(controller, "a", source=SelectionSource.DASHBOARD_NEXT)
        self.assertEqual(logs, [])

    def test_manual_source_resets_auto_switch_and_automatic_does_not(self) -> None:
        manual, _, manual_resets = _controller()
        node_service.set_selected_node(manual, "b", source=SelectionSource.NODES_DOUBLE_CLICK)
        self.assertTrue(manual._auto_switch_manual_hold)
        self.assertEqual(manual_resets, [{"reset_cooldown": True, "reset_cycle": True}])

        auto, logs, auto_resets = _controller()
        node_service.set_selected_node(auto, "b", source=SelectionSource.AUTO_SWITCH)
        self.assertFalse(hasattr(auto, "_auto_switch_manual_hold"))
        self.assertEqual(auto_resets, [])
        self.assertTrue(logs[0].startswith("[select] source=auto-switch "))

    def test_removed_selected_server_keeps_its_name_in_the_log(self) -> None:
        controller, logs, _ = _controller()
        controller.nodes_changed = SimpleNamespace(emit=lambda nodes: None)
        controller.save = lambda: None
        node_service.remove_nodes(controller, {"a"})
        self.assertEqual(controller.state.selected_node_id, "b")
        self.assertEqual(
            logs,
            [
                "[select] source=node-removed (выбранный сервер удалён): "
                f"«Tiraru» node_ref={node_ref('a')} → «Titiru» node_ref={node_ref('b')}"
            ],
        )

    def test_every_source_has_unique_code(self) -> None:
        codes = [source.code for source in SelectionSource]
        self.assertEqual(len(codes), len(set(codes)))
        self.assertTrue(all(source.label for source in SelectionSource))


if __name__ == "__main__":
    unittest.main()
