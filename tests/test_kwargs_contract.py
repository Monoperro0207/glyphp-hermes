"""R1 contract: EVERY callable the plugin registers tolerates surprise kwargs.

Hermes injects extras (`parent_agent`, `telemetry_schema_version`, and
whatever future versions add); none of our handlers/hooks/commands may raise
TypeError for them.
"""
from __future__ import annotations

import json

import pytest

import glyphp_hermes
from glyphp_hermes import plugin
from glyphp_hermes.config import GlyphConfig, ServerConfig, TofuPolicy

from .hermes_stubs import FakeContext

SURPRISE_KWARGS = {
    "parent_agent": object(),
    "telemetry_schema_version": 3,
    "task_id": "t-1",
    "some_future_kwarg": {"nested": True},
}


@pytest.fixture(autouse=True)
def fresh_runtime():
    yield
    plugin.reset_runtime()


@pytest.fixture()
def ctx(server):
    cfg = GlyphConfig()
    cfg.add_server(
        ServerConfig(
            alias="demo", url=server.url, tofu=TofuPolicy(enabled=True, max_risk_tier="caution")
        )
    )
    cfg.save()
    context = FakeContext()
    glyphp_hermes.register(context)
    return context


def test_every_tool_handler_tolerates_surprise_kwargs(ctx):
    assert ctx.registry.tools, "no tools registered"
    for name, entry in ctx.registry.tools.items():
        result = entry["handler"]({}, **SURPRISE_KWARGS)
        parsed = json.loads(result)
        # No TypeError surfaced as a dispatch error string.
        assert "TypeError" not in result, f"{name} choked on surprise kwargs"
        assert isinstance(parsed, dict)


def test_every_hook_tolerates_surprise_kwargs(ctx):
    assert ctx.hooks, "no hooks registered"
    for hook_name, callbacks in ctx.hooks.items():
        for callback in callbacks:
            callback(**SURPRISE_KWARGS)  # must not raise


def test_slash_command_tolerates_surprise_kwargs(ctx):
    handler = ctx.commands["glyph"]["handler"]
    out = handler("status", **SURPRISE_KWARGS)
    assert isinstance(out, str)


def test_cli_handler_tolerates_surprise_kwargs(ctx):
    import argparse

    handler = ctx.cli_commands["glyph"]["handler_fn"]
    args = argparse.Namespace(glyph_cmd="list")
    code = handler(args, **SURPRISE_KWARGS)
    assert code == 0
