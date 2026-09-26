"""Helpers for unit tests of step-based transitions (not a test module).

Operations are generators that yield :class:`TransitionStep` objects. Tests
that replace managers with ``Mock`` objects need two things:

- ``steps_via(method)`` — a generator-function twin of a (mocked) synchronous
  method: calling it records the call on the original mock and returns its
  ``return_value``/``side_effect`` result without yielding. ``bridge(obj,
  "start", "stop")`` installs ``obj.start_steps``/``obj.stop_steps`` twins, so
  existing assertions on ``obj.start``/``obj.stop`` keep working.
- ``drive(generator)`` — a deterministic synchronous driver: sleeps are
  recorded instead of waited, worker callables run inline, anything that is
  not a ``TransitionStep`` fails fast (a ``Mock`` must never be iterated).
"""

from __future__ import annotations

from typing import Any, Callable

from xray_fluent.application.async_steps import RunInWorkerStep, SleepStep, TransitionStep


def drive(
    generator: Any,
    *,
    sleeps: list[int] | None = None,
    on_sleep: Callable[[float], None] | None = None,
    max_steps: int = 10_000,
) -> Any:
    if not hasattr(generator, "send") or not hasattr(generator, "throw") or type(generator).__name__ != "generator":
        raise TypeError(f"drive() needs a generator, got {type(generator)!r}")
    value: Any = None
    error: BaseException | None = None
    for _ in range(max_steps):
        try:
            step = generator.throw(error) if error is not None else generator.send(value)
        except StopIteration as stop:
            return stop.value
        if not isinstance(step, TransitionStep):
            generator.close()
            raise TypeError(f"generator yielded {type(step)!r}, expected TransitionStep")
        value, error = None, None
        try:
            if isinstance(step, SleepStep):
                if sleeps is not None:
                    sleeps.append(step.ms)
                if on_sleep is not None:
                    on_sleep(step.ms / 1000.0)
            elif isinstance(step, RunInWorkerStep):
                value = step._fn()
            else:
                value = step.run_blocking()
        except BaseException as exc:  # noqa: BLE001 — delivered via generator.throw
            error = exc
    generator.close()
    raise RuntimeError(f"drive() exceeded {max_steps} steps")


def steps_via(method: Callable[..., Any]) -> Callable[..., Any]:
    def steps(*args: Any, **kwargs: Any):
        return method(*args, **kwargs)
        yield  # pragma: no cover — keeps the generator form

    return steps


def bridge(obj: Any, *names: str) -> Any:
    for name in names:
        setattr(obj, f"{name}_steps", steps_via(getattr(obj, name)))
    return obj


def bridge_controller(controller: Any) -> Any:
    """Install step twins for the controller-level helpers used by operations."""
    for name in (
        "_start_amnezia_manager",
        "_apply_core_outbound_tag",
        "_start_singbox_runtime_plan",
        "_rollback_singbox_front",
        "_prepare_amnezia_replacement",
        "_prepare_hysteria_replacement",
        "_commit_hysteria_replacement",
        "_stop_active_connection_processes",
        "_handle_unexpected_disconnect",
        "_disconnect_current",
        "_apply_proxy_runtime_change",
    ):
        setattr(controller, f"{name}_steps", steps_via(getattr(controller, name)))
    controller._proxy_steps = steps_via(
        lambda method, *args, **kwargs: getattr(controller.proxy, method)(*args, **kwargs)
    )
    controller._proxy_nowait = lambda method, *args, **kwargs: getattr(controller.proxy, method)(*args, **kwargs)
    for manager_name in ("singbox", "xray", "hysteria", "amnezia"):
        manager = getattr(controller, manager_name, None)
        if manager is None:
            continue
        try:
            bridge(manager, "start", "stop")
        except AttributeError:
            pass
    return controller
