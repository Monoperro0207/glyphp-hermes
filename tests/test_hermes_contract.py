"""R4 upstream contract: assert the exact hermes-agent symbols this plugin uses.

Skipped unless hermes-agent is importable (CI runs these in the dedicated
`hermes-contract` workflow against a fresh clone of hermes-agent@main; locally
you can run them from inside a Hermes checkout/venv).

If any assertion here fails, upstream drifted: fix glyphp_hermes/_hermes.py
(the capability seams) before users hit it.
"""
from __future__ import annotations

import importlib.util
import inspect

import pytest

HERMES_AVAILABLE = (
    importlib.util.find_spec("tools") is not None
    and importlib.util.find_spec("hermes_cli") is not None
)

pytestmark = [
    pytest.mark.hermes_upstream,
    pytest.mark.skipif(not HERMES_AVAILABLE, reason="hermes-agent not importable"),
]


def test_plugin_context_register_tool_signature():
    from hermes_cli.plugins import PluginContext

    params = inspect.signature(PluginContext.register_tool).parameters
    for required in ("name", "toolset", "schema", "handler", "description", "emoji", "override"):
        assert required in params, f"PluginContext.register_tool lost param {required!r}"


def test_plugin_context_other_registrars():
    from hermes_cli.plugins import PluginContext

    for method in ("register_hook", "register_command", "register_cli_command"):
        assert hasattr(PluginContext, method)
    params = inspect.signature(PluginContext.register_command).parameters
    for required in ("name", "handler", "description", "args_hint"):
        assert required in params


def test_valid_hooks_include_ours():
    from hermes_cli.plugins import VALID_HOOKS

    assert "on_session_start" in VALID_HOOKS
    assert "post_approval_response" in VALID_HOOKS


def test_registry_register_and_deregister():
    from tools.registry import registry

    assert callable(getattr(registry, "register", None))
    assert callable(getattr(registry, "deregister", None))
    params = inspect.signature(registry.register).parameters
    for required in ("name", "toolset", "schema", "handler", "override"):
        assert required in params


def test_approval_symbols():
    import tools.approval as approval

    assert callable(getattr(approval, "prompt_dangerous_approval", None))
    params = inspect.signature(approval.prompt_dangerous_approval).parameters
    assert "allow_permanent" in params

    assert callable(getattr(approval, "submit_pending", None))
    assert callable(getattr(approval, "resolve_gateway_approval", None))
    assert callable(getattr(approval, "get_current_session_key", None))
    assert callable(getattr(approval, "_is_gateway_approval_context", None))


def test_tier1_private_symbols_still_exist():
    """Tier 1 uses private upstream symbols by design (with tier-2 fallback);
    this test tells us the moment they move."""
    import tools.approval as approval

    assert callable(getattr(approval, "_await_gateway_decision", None))
    assert isinstance(getattr(approval, "_gateway_notify_cbs", None), dict)
    params = inspect.signature(approval._await_gateway_decision).parameters
    for required in ("session_key", "notify_cb", "approval_data"):
        assert required in params


def test_capability_detection_full_on_real_hermes():
    from glyphp_hermes import _hermes

    caps = _hermes.detect_caps(force=True)
    assert caps.available
    assert caps.gateway_tier2, f"missing: {caps.missing}"
    assert caps.registry_register and caps.registry_deregister
