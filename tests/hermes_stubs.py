"""Minimal stand-ins for the three Hermes seams the plugin touches.

The real hermes-agent pins heavy exact dependencies and is not a viable test
dependency; these stubs replicate the documented contracts:

  - ``FakeRegistry``  — tools.registry semantics (dispatch catches exceptions
    into ``{"error": ...}`` JSON, passes surprise kwargs, supports deregister)
  - ``FakeContext``   — hermes_cli.plugins.PluginContext registration surface
  - dispatching hooks with extra kwargs (Hermes always injects
    ``telemetry_schema_version``)
"""
from __future__ import annotations

import json
from typing import Any, Callable


class FakeRegistry:
    def __init__(self) -> None:
        self.tools: dict[str, dict] = {}

    def register(
        self,
        *,
        name: str,
        toolset: str,
        schema: dict,
        handler: Callable,
        override: bool = False,
        **extra: Any,
    ) -> None:
        if name in self.tools and not override:
            raise ValueError(f"tool {name} already registered")
        self.tools[name] = {
            "toolset": toolset,
            "schema": schema,
            "handler": handler,
            **extra,
        }

    def deregister(self, name: str) -> None:
        self.tools.pop(name, None)

    def dispatch(self, name: str, args: dict, **kwargs: Any) -> str:
        entry = self.tools.get(name)
        if entry is None:
            return json.dumps({"error": f"Unknown tool: {name}"})
        try:
            result = entry["handler"](args, **kwargs)
            return result if isinstance(result, str) else json.dumps(result)
        except Exception as exc:  # noqa: BLE001 — mirrors Hermes dispatch
            return json.dumps({"error": str(exc)})


class FakeContext:
    """Captures everything a plugin registers, like PluginContext does."""

    def __init__(self, registry: FakeRegistry | None = None) -> None:
        self.registry = registry or FakeRegistry()
        self.hooks: dict[str, list[Callable]] = {}
        self.commands: dict[str, dict] = {}
        self.cli_commands: dict[str, dict] = {}

    def register_tool(
        self,
        name: str,
        toolset: str,
        schema: dict,
        handler: Callable,
        check_fn: Callable | None = None,
        override: bool = False,
        **extra: Any,
    ) -> None:
        self.registry.register(
            name=name,
            toolset=toolset,
            schema=schema,
            handler=handler,
            override=override,
            check_fn=check_fn,
            **extra,
        )

    def register_hook(self, hook_name: str, callback: Callable) -> None:
        self.hooks.setdefault(hook_name, []).append(callback)

    def register_command(
        self, name: str, handler: Callable, description: str = "", args_hint: str = ""
    ) -> None:
        self.commands[name] = {
            "handler": handler,
            "description": description,
            "args_hint": args_hint,
        }

    def register_cli_command(
        self, name: str, help: str = "", setup_fn: Callable | None = None,
        handler_fn: Callable | None = None,
    ) -> None:
        self.cli_commands[name] = {"help": help, "setup_fn": setup_fn, "handler_fn": handler_fn}

    def invoke_hook(self, hook_name: str, **kwargs: Any) -> list:
        """Hermes always injects extra kwargs; mirror that here."""
        kwargs.setdefault("telemetry_schema_version", 3)
        results = []
        for callback in self.hooks.get(hook_name, []):
            results.append(callback(**kwargs))
        return results
