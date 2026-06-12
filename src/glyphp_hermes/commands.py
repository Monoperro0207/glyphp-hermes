"""/glyph slash command — trust & audit operations from inside a session.

Handlers return plain strings (gateway-safe) and never raise.
"""
from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, Callable

from . import _hermes

if TYPE_CHECKING:
    from .bridge import ServerBridge, ToolBinding
    from .plugin import GlyphRuntime

USAGE = (
    "usage: /glyph status | sync | trust <tool> | revoke <tool> [reason] | "
    "diff <tool> | audit [n]"
)


def make_handler(runtime: "GlyphRuntime") -> Callable[..., str]:
    def handler(args: str = "", **_kwargs: Any) -> str:
        try:
            return _dispatch(runtime, (args or "").strip())
        except Exception as exc:  # noqa: BLE001 — slash commands never raise
            return f"glyph command failed: {exc}"

    return handler


def _dispatch(runtime: "GlyphRuntime", args: str) -> str:
    parts = args.split()
    if not parts:
        return USAGE
    cmd, rest = parts[0], parts[1:]

    if cmd == "status":
        return _status(runtime)
    if cmd == "sync":
        return _sync(runtime)
    if cmd == "trust" and rest:
        return _trust(runtime, rest[0])
    if cmd == "revoke" and rest:
        return _revoke(runtime, rest[0], " ".join(rest[1:]))
    if cmd == "diff" and rest:
        return _diff(runtime, rest[0])
    if cmd == "audit":
        n = int(rest[0]) if rest and rest[0].isdigit() else 10
        return _audit(runtime, n)
    return USAGE


def _status(runtime: "GlyphRuntime") -> str:
    if not runtime.bridges:
        caps = _hermes.capability_report()
        return (
            "No Glyph servers configured. Add one with: hermes glyph add <alias> <url>\n"
            f"capabilities: {json.dumps(caps)}"
        )
    lines = ["tool | alias | risk | state | reason"]
    for tool_name, (bridge, binding) in sorted(runtime.all_bindings().items()):
        state = binding.blocked_code or "callable"
        tier = (binding.card.get("cost") or {}).get("riskTier", "?")
        reason = binding.blocked_reason[:60] if binding.blocked_reason else ""
        lines.append(f"{tool_name} | {binding.alias} | {tier} | {state} | {reason}")
    caps = _hermes.capability_report()
    degraded = [k for k, v in caps.items() if k != "missing" and v is False]
    if degraded:
        lines.append(f"degraded capabilities: {', '.join(degraded)}")
    return "\n".join(lines)


def _sync(runtime: "GlyphRuntime") -> str:
    results = runtime.reconcile()
    reports = [b.last_report.summary() for b in runtime.bridges.values() if b.last_report]
    extra = []
    if results.get("added"):
        extra.append(f"added: {', '.join(results['added'])}")
    if results.get("removed"):
        extra.append(f"removed: {', '.join(results['removed'])}")
    return "\n".join(reports + extra) if (reports or extra) else "no servers configured"


def _trust(runtime: "GlyphRuntime", tool_name: str) -> str:
    bridge = runtime.find_bridge_for_tool(tool_name)
    if bridge is None:
        return f"unknown tool {tool_name!r} — run /glyph status to list tools"
    binding = bridge.bindings[tool_name]
    diff_text = _render_pending_diff(bridge, binding)
    result = bridge.trust_tool(tool_name)
    return (diff_text + "\n" + result) if diff_text else result


def _revoke(runtime: "GlyphRuntime", tool_name: str, reason: str) -> str:
    bridge = runtime.find_bridge_for_tool(tool_name)
    if bridge is None:
        return f"unknown tool {tool_name!r}"
    return bridge.revoke_tool(tool_name, reason)


def _diff(runtime: "GlyphRuntime", tool_name: str) -> str:
    bridge = runtime.find_bridge_for_tool(tool_name)
    if bridge is None:
        return f"unknown tool {tool_name!r}"
    binding = bridge.bindings[tool_name]
    rendered = _render_pending_diff(bridge, binding)
    if rendered:
        return rendered
    if binding.decision.diff:
        return _render_diff(binding.decision.diff)
    return f"{tool_name}: no pending changes (state: {binding.blocked_code or 'callable'})"


def _render_pending_diff(bridge: "ServerBridge", binding: "ToolBinding") -> str:
    pending = bridge.trust.pending().get(binding.glyph_name)
    if not pending:
        return ""
    return f"pending change for {binding.tool_name}:\n" + _render_diff(pending["diff"])


def _render_diff(diff: dict) -> str:
    lines = []
    for change in diff.get("changes", []):
        before = json.dumps(change.get("before"), ensure_ascii=False)
        after = json.dumps(change.get("after"), ensure_ascii=False)
        lines.append(
            f"  [{change['severity']:8}] {change['field']}: {before[:80]} -> {after[:80]}"
        )
    flags = []
    if diff.get("idChanged"):
        flags.append("id changed")
    if diff.get("keyChanged"):
        flags.append("SIGNING KEY CHANGED")
    if diff.get("requiresApproval"):
        flags.append("requires approval")
    if flags:
        lines.append("  (" + ", ".join(flags) + ")")
    return "\n".join(lines) if lines else "  (no field changes)"


def _audit(runtime: "GlyphRuntime", n: int) -> str:
    lines = []
    for bridge in runtime.bridges.values():
        for entry in bridge.audit.tail(n):
            verdict = "ok " if entry.get("verified") else "BAD"
            lines.append(
                f"{entry.get('ts', '?')} [{verdict}] {entry.get('toolName')} "
                f"callId={entry.get('callId', '?')}"
            )
    if not lines:
        return "audit log is empty"
    return "\n".join(lines[-n:])
