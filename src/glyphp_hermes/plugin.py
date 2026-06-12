"""Plugin wiring: GlyphRuntime + Hermes registration.

``register(ctx)`` is the only function Hermes calls. Every callable handed to
Hermes passes through :func:`_safe_callable`, which structurally guarantees
the ``(args=None, **kwargs)`` contract — Hermes injects extras like
``parent_agent`` and ``telemetry_schema_version`` and a future kwarg must
never produce a TypeError.
"""
from __future__ import annotations

import functools
import logging
import threading
from typing import Any, Callable, Optional

from . import _hermes
from .bridge import ServerBridge, SyncReport, ToolBinding, card_to_schema
from .config import GlyphConfig

logger = logging.getLogger("glyphp_hermes.plugin")


def _safe_callable(fn: Callable[..., object]) -> Callable[..., object]:
    """Normalize any plugin callable to tolerate arbitrary extra kwargs."""

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> object:
        return fn(*args, **kwargs)

    # The wrapped fn itself must already accept **kwargs; this assert keeps us
    # honest at registration time instead of at dispatch time.
    import inspect

    sig = inspect.signature(fn)
    has_var_kw = any(
        p.kind is inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values()
    )
    if not has_var_kw:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> object:  # noqa: F811 — intentional rebind
            accepted = {
                k: v
                for k, v in kwargs.items()
                if k in sig.parameters
            }
            return fn(*args, **accepted)

    return wrapper


class GlyphRuntime:
    """All bridges + the reconciliation loop. One instance per process."""

    def __init__(self, config: Optional[GlyphConfig] = None) -> None:
        self.config = config or GlyphConfig.load()
        self.bridges: dict[str, ServerBridge] = {}
        self.registered_tools: set[str] = set()
        self._lock = threading.Lock()
        self.confirmer = _hermes.request_user_confirmation

    # ---- lifecycle -----------------------------------------------------------

    def build_bridges(self) -> None:
        for server_cfg in self.config.servers:
            if server_cfg.alias in self.bridges:
                continue
            try:
                self.bridges[server_cfg.alias] = ServerBridge.from_config(
                    server_cfg, self.confirmer
                )
            except Exception:  # noqa: BLE001 — one bad server must not kill the rest
                logger.exception("could not build bridge for %s", server_cfg.alias)

    def sync_all(self) -> list[SyncReport]:
        reports = []
        for bridge in self.bridges.values():
            try:
                reports.append(bridge.sync())
            except Exception as exc:  # noqa: BLE001
                logger.exception("sync failed for %s", bridge.cfg.alias)
                reports.append(
                    SyncReport(ok=False, alias=bridge.cfg.alias, error=str(exc))
                )
        return reports

    def all_bindings(self) -> dict[str, tuple[ServerBridge, ToolBinding]]:
        out: dict[str, tuple[ServerBridge, ToolBinding]] = {}
        for bridge in self.bridges.values():
            for tool_name, binding in bridge.bindings.items():
                out[tool_name] = (bridge, binding)
        return out

    def find_bridge_for_tool(self, tool_name: str) -> Optional[ServerBridge]:
        for bridge in self.bridges.values():
            if tool_name in bridge.bindings:
                return bridge
        return None

    # ---- initial registration (through PluginContext) -------------------------

    def register_tools(self, ctx: Any) -> int:
        count = 0
        for tool_name, (bridge, binding) in self.all_bindings().items():
            schema = card_to_schema(tool_name, binding.alias, binding.card)
            try:
                ctx.register_tool(
                    name=tool_name,
                    toolset=f"glyph-{binding.alias}",
                    schema=schema,
                    handler=_safe_callable(bridge.make_handler(tool_name)),
                    description=schema["description"],
                    emoji="🔏",
                )
                self.registered_tools.add(tool_name)
                count += 1
            except Exception:  # noqa: BLE001 — a name clash must not abort the rest
                logger.exception("could not register %s", tool_name)
        return count

    # ---- live reconciliation (resync; same pattern as Hermes' MCP refresh) ----

    def reconcile(self) -> dict[str, Any]:
        """Re-sync every bridge and reconcile the live registry:
        register new tools, re-register changed ones, deregister removed ones.
        Handlers look bindings up at dispatch time, so updated/blocked states
        apply even without re-registration; the registry diff below keeps the
        *tool list* the model sees in step with the servers.
        """
        with self._lock:
            self.sync_all()
            current = set(self.all_bindings().keys())
            added = current - self.registered_tools
            removed = self.registered_tools - current

            results: dict[str, Any] = {
                "added": [],
                "removed": [],
                "kept": len(current & self.registered_tools),
            }
            for tool_name in sorted(added):
                bridge, binding = self.all_bindings()[tool_name]
                ok = _hermes.register_tool_dynamic(
                    name=tool_name,
                    toolset=f"glyph-{binding.alias}",
                    schema=card_to_schema(tool_name, binding.alias, binding.card),
                    handler=_safe_callable(bridge.make_handler(tool_name)),
                    description=binding.card.get("intent", ""),
                )
                if ok:
                    self.registered_tools.add(tool_name)
                    results["added"].append(tool_name)
            for tool_name in sorted(removed):
                if _hermes.deregister_tool(tool_name):
                    self.registered_tools.discard(tool_name)
                    results["removed"].append(tool_name)
            return results

    # ---- hooks -----------------------------------------------------------------

    def on_session_start(self, **_kwargs: Any) -> None:
        try:
            self.reconcile()
        except Exception:  # noqa: BLE001 — hooks must never raise into Hermes
            logger.exception("glyph resync on session start failed")

    def close(self) -> None:
        for bridge in self.bridges.values():
            bridge.close()


_runtime: Optional[GlyphRuntime] = None


def get_runtime() -> Optional[GlyphRuntime]:
    return _runtime


def reset_runtime() -> None:
    global _runtime
    if _runtime is not None:
        _runtime.close()
    _runtime = None


def register(ctx: Any) -> None:
    """Hermes plugin entry point."""
    global _runtime
    from . import cli, commands

    try:
        config = GlyphConfig.load()
    except Exception:  # noqa: BLE001 — a broken config must not break Hermes startup
        logger.exception("glyph.yaml could not be loaded; commands-only mode")
        config = GlyphConfig()

    _runtime = GlyphRuntime(config)
    runtime = _runtime

    # Slash command + CLI are always available (even with zero servers).
    try:
        ctx.register_command(
            "glyph",
            handler=_safe_callable(commands.make_handler(runtime)),
            description="Glyph Protocol trust & audit (status, sync, trust, revoke, diff, audit)",
            args_hint="status|sync|trust <tool>|revoke <tool> [reason]|diff <tool>|audit [n]",
        )
    except Exception:  # noqa: BLE001
        logger.exception("could not register /glyph command")

    try:
        ctx.register_cli_command(
            "glyph",
            help="Manage Glyph Protocol servers (add, sync, trust, audit, call)",
            setup_fn=cli.setup,
            handler_fn=_safe_callable(cli.handle),
        )
    except Exception:  # noqa: BLE001
        logger.exception("could not register hermes glyph CLI command")

    try:
        ctx.register_hook("on_session_start", _safe_callable(runtime.on_session_start))
        ctx.register_hook(
            "post_approval_response", _safe_callable(_hermes.on_post_approval_response)
        )
    except Exception:  # noqa: BLE001
        logger.exception("could not register glyph hooks")

    if not config.servers:
        logger.info("glyph: no servers configured — run 'hermes glyph add <alias> <url>'")
        return

    runtime.build_bridges()
    runtime.sync_all()
    registered = runtime.register_tools(ctx)
    logger.info(
        "glyph: %d tools registered from %d server(s)", registered, len(runtime.bridges)
    )
