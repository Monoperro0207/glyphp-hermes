"""The ONLY module that imports hermes-agent internals.

Every Hermes symbol is resolved by feature-detection into :class:`HermesCaps`,
so an upstream rename degrades the affected feature **fail-closed** (and
visibly, via ``capability_report()`` surfaced in ``/glyph status``) instead of
crashing or silently auto-approving.

Confirmation outcomes returned by :func:`request_user_confirmation`:

  - ``approved`` / ``denied``  — interactive decision (CLI prompt or blocking
    gateway decision; one-shot by construction, nothing persisted)
  - ``pending``  — gateway fallback path: the approval request was queued for
    the user; the model should retry the same call after they approve. The
    grant recorded by the ``post_approval_response`` hook is **one-shot**:
    consumed atomically on the retry, so an identical later call re-asks.
  - ``timeout``  — the user never responded
  - ``unavailable`` — no approval channel in this context (cron, missing
    upstream API, outside Hermes): fail closed.
"""
from __future__ import annotations

import logging
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

logger = logging.getLogger("glyphp_hermes.hermes")


def _env_enabled(name: str) -> bool:
    return (os.environ.get(name) or "").strip().lower() in {"1", "true", "yes", "on"}


# ---------------------------------------------------------------------------
# Capability detection
# ---------------------------------------------------------------------------


@dataclass
class HermesCaps:
    """Feature-detected handles into hermes-agent. ``None`` = unavailable."""

    prompt_dangerous_approval: Optional[Callable] = None
    is_gateway_context: Optional[Callable[[], bool]] = None
    get_session_key: Optional[Callable] = None
    await_gateway_decision: Optional[Callable] = None  # private upstream; tier 1
    gateway_notify_cbs: Optional[dict] = None  # private upstream; tier 1
    submit_pending: Optional[Callable] = None  # public; tier 2
    registry_register: Optional[Callable] = None
    registry_deregister: Optional[Callable] = None
    available: bool = False
    missing: list[str] = field(default_factory=list)

    @property
    def gateway_tier1(self) -> bool:
        return self.await_gateway_decision is not None and self.gateway_notify_cbs is not None

    @property
    def gateway_tier2(self) -> bool:
        return self.submit_pending is not None and self.get_session_key is not None


_caps: Optional[HermesCaps] = None
_caps_lock = threading.Lock()


def detect_caps(force: bool = False) -> HermesCaps:
    global _caps
    with _caps_lock:
        if _caps is not None and not force:
            return _caps
        caps = HermesCaps()
        try:
            import tools.approval as approval

            caps.available = True
            for attr, target in (
                ("prompt_dangerous_approval", "prompt_dangerous_approval"),
                ("_is_gateway_approval_context", "is_gateway_context"),
                ("get_current_session_key", "get_session_key"),
                ("_await_gateway_decision", "await_gateway_decision"),
                ("_gateway_notify_cbs", "gateway_notify_cbs"),
                ("submit_pending", "submit_pending"),
            ):
                value = getattr(approval, attr, None)
                if value is None:
                    caps.missing.append(f"tools.approval.{attr}")
                else:
                    setattr(caps, target, value)
        except ImportError:
            caps.missing.append("tools.approval (not inside a Hermes process)")

        try:
            from tools.registry import registry

            caps.registry_register = getattr(registry, "register", None)
            caps.registry_deregister = getattr(registry, "deregister", None)
            for name, value in (
                ("tools.registry.registry.register", caps.registry_register),
                ("tools.registry.registry.deregister", caps.registry_deregister),
            ):
                if value is None:
                    caps.missing.append(name)
        except ImportError:
            caps.missing.append("tools.registry")

        _caps = caps
        if caps.missing:
            logger.info("glyph plugin degraded capabilities: %s", ", ".join(caps.missing))
        return caps


def capability_report() -> dict:
    caps = detect_caps()
    return {
        "hermes": caps.available,
        "cli_approval": caps.prompt_dangerous_approval is not None,
        "gateway_tier1": caps.gateway_tier1,
        "gateway_tier2": caps.gateway_tier2,
        "dynamic_registry": caps.registry_register is not None
        and caps.registry_deregister is not None,
        "missing": list(caps.missing),
    }


def hermes_home() -> Path:
    try:
        from hermes_constants import get_hermes_home  # type: ignore[import-not-found]

        return Path(get_hermes_home())
    except (ImportError, Exception):  # noqa: BLE001 — any failure falls back to env
        return Path(os.environ.get("HERMES_HOME", "~/.hermes")).expanduser()


# ---------------------------------------------------------------------------
# One-shot grant store (gateway tier 2)
# ---------------------------------------------------------------------------


class OneShotGrantStore:
    """Plugin-owned approvals: granted once, consumed exactly once.

    Deliberately NOT Hermes' session-scoped ``approve_session`` set — a glyph
    confirmation must never silently cover a later identical call.
    """

    def __init__(self, ttl_seconds: float = 300.0) -> None:
        self.ttl_seconds = ttl_seconds
        self._grants: dict[str, float] = {}
        self._lock = threading.Lock()

    def grant(self, approval_key: str) -> None:
        with self._lock:
            self._grants[approval_key] = time.time() + self.ttl_seconds

    def consume(self, approval_key: str) -> bool:
        with self._lock:
            expires = self._grants.pop(approval_key, None)
        return expires is not None and time.time() < expires

    def pending_count(self) -> int:
        with self._lock:
            now = time.time()
            self._grants = {k: v for k, v in self._grants.items() if v > now}
            return len(self._grants)


grants = OneShotGrantStore()


def on_post_approval_response(**kwargs: Any) -> None:
    """``post_approval_response`` hook: record one-shot grants for our keys."""
    keys = kwargs.get("pattern_keys") or [kwargs.get("pattern_key")]
    choice = kwargs.get("choice")
    if choice not in {"once", "session", "always", "approve", "approved", "yes"}:
        return
    for key in keys:
        if isinstance(key, str) and key.startswith("glyph:"):
            grants.grant(key)


# ---------------------------------------------------------------------------
# Confirmation seam
# ---------------------------------------------------------------------------


def request_user_confirmation(summary: str, description: str, approval_key: str) -> str:
    caps = detect_caps()

    # A grant from a previous gateway approval round-trip: consume it (one-shot).
    if grants.consume(approval_key):
        return "approved"

    in_gateway = False
    if caps.is_gateway_context is not None:
        try:
            in_gateway = bool(caps.is_gateway_context())
        except Exception:  # noqa: BLE001 — context detection must never break the gate
            in_gateway = False

    if in_gateway:
        return _gateway_confirmation(caps, summary, description, approval_key)

    if _env_enabled("HERMES_CRON_SESSION"):
        return "unavailable"  # nobody present to approve; fail closed

    if _env_enabled("HERMES_INTERACTIVE") and caps.prompt_dangerous_approval is not None:
        try:
            choice = caps.prompt_dangerous_approval(
                summary, description, allow_permanent=False
            )
        except Exception:  # noqa: BLE001 — a broken prompt must fail closed
            logger.exception("CLI approval prompt failed")
            return "unavailable"
        # Never honor 'always' semantics for glyph confirmations: each
        # danger-tier call is its own decision.
        return "approved" if choice in {"once", "session"} else "denied"

    return "unavailable"


def _gateway_confirmation(
    caps: HermesCaps, summary: str, description: str, approval_key: str
) -> str:
    session_key = "default"
    if caps.get_session_key is not None:
        try:
            session_key = caps.get_session_key()
        except Exception:  # noqa: BLE001
            pass

    approval_data = {
        "command": summary,
        "description": description,
        "pattern_key": approval_key,
        "pattern_keys": [approval_key],
    }

    # Tier 1: blocking decision bound to THIS call (what Hermes' own terminal
    # guard does). One-shot by construction.
    notify_cbs = caps.gateway_notify_cbs
    await_decision = caps.await_gateway_decision
    if caps.gateway_tier1 and notify_cbs is not None and await_decision is not None:
        notify_cb = notify_cbs.get(session_key)
        if notify_cb is not None:
            try:
                outcome = await_decision(
                    session_key, notify_cb, approval_data, surface="glyph"
                )
            except Exception:  # noqa: BLE001 — fall through to tier 2
                logger.exception("gateway blocking approval failed; falling back")
            else:
                if not outcome.get("resolved"):
                    return "timeout"
                choice = outcome.get("choice")
                return "approved" if choice in {"once", "session", "always"} else "denied"

    # Tier 2: queue the request and return; the post_approval_response hook
    # records a one-shot grant and the model retries.
    submit = caps.submit_pending
    if caps.gateway_tier2 and submit is not None:
        try:
            submit(session_key, approval_data)
            return "pending"
        except Exception:  # noqa: BLE001
            logger.exception("submit_pending failed")

    return "unavailable"


# ---------------------------------------------------------------------------
# Dynamic registry reconciliation (same pattern as Hermes' MCP refresh)
# ---------------------------------------------------------------------------


def register_tool_dynamic(
    *,
    name: str,
    toolset: str,
    schema: dict,
    handler: Callable,
    description: str = "",
) -> bool:
    caps = detect_caps()
    if caps.registry_register is None:
        return False
    try:
        caps.registry_register(
            name=name,
            toolset=toolset,
            schema=schema,
            handler=handler,
            description=description,
            emoji="🔏",
            override=True,
        )
        return True
    except Exception:  # noqa: BLE001 — registry rejection must not kill a resync
        logger.exception("dynamic register of %s failed", name)
        return False


def deregister_tool(name: str) -> bool:
    caps = detect_caps()
    if caps.registry_deregister is None:
        return False
    try:
        caps.registry_deregister(name)
        return True
    except Exception:  # noqa: BLE001
        logger.exception("deregister of %s failed", name)
        return False
