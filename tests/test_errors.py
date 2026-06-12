"""Wire-error mapping on the handler path: never raises, always uniform JSON."""
from __future__ import annotations

import json

import pytest


@pytest.mark.parametrize(
    "code,status",
    [
        ("VALIDATION_FAILED", 400),
        ("RATE_LIMITED", 429),
        ("HANDLER_TIMEOUT", 504),
        ("HANDLER_ERROR", 502),
        ("UNAUTHORIZED", 401),
        ("INSUFFICIENT_SCOPE", 403),
    ],
)
def test_protocol_errors_mapped(bridge, server, code, status):
    server.set_error("echo", code, status)
    try:
        out = json.loads(bridge.make_handler("glyph_demo_echo")({}))
        assert out["ok"] is False
        assert out["error"]["code"] == code
    finally:
        server.clear_error("echo")


def test_transport_error_mapped(bridge, server):
    handler = bridge.make_handler("glyph_demo_echo")
    server.stop()
    out = json.loads(handler({}))
    assert out["error"]["code"] == "SERVER_UNREACHABLE"


def test_stale_binding_after_clear(bridge):
    handler = bridge.make_handler("glyph_demo_echo")
    bridge.bindings.clear()
    out = json.loads(handler({}))
    assert out["error"]["code"] == "NOT_FOUND"
    assert "sync" in out["error"]["message"]


def test_handler_accepts_surprise_kwargs(bridge):
    """Hermes dispatch passes extras like parent_agent — handlers must tolerate them."""
    handler = bridge.make_handler("glyph_demo_echo")
    out = json.loads(
        handler({"x": 1}, parent_agent=object(), telemetry_schema_version=3, future_kwarg="?")
    )
    assert out["ok"] is True
