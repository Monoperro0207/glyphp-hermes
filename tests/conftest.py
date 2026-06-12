"""Shared fixtures: isolated HERMES_HOME, fake server, bridge factory."""
from __future__ import annotations

import pytest

from glyph_protocol import MemoryPinStore

from glyphp_hermes.audit import ReceiptAuditLog
from glyphp_hermes.bridge import ServerBridge
from glyphp_hermes.config import (
    AttestationPolicy,
    ReceiptPolicy,
    ServerConfig,
    TofuPolicy,
)
from glyphp_hermes.trust import TrustManager

from .fake_server import FakeGlyphServer, default_glyphs


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes-home"))
    return tmp_path


@pytest.fixture()
def server():
    with FakeGlyphServer(default_glyphs()) as srv:
        yield srv


class ScriptedConfirmer:
    """Confirmer seam with a scripted outcome sequence and a call log."""

    def __init__(self, outcomes: list[str] | None = None):
        self.outcomes = list(outcomes or [])
        self.calls: list[dict] = []

    def __call__(self, summary: str, description: str, approval_key: str) -> str:
        self.calls.append(
            {"summary": summary, "description": description, "approval_key": approval_key}
        )
        if self.outcomes:
            return self.outcomes.pop(0)
        return "approved"


@pytest.fixture()
def confirmer():
    return ScriptedConfirmer()


def make_bridge(
    server,
    tmp_path,
    confirmer,
    *,
    tofu: TofuPolicy | None = None,
    receipts: ReceiptPolicy | None = None,
    attestation: AttestationPolicy | None = None,
    auto_repin_review: bool = True,
) -> ServerBridge:
    cfg = ServerConfig(
        alias="demo",
        url=server.url,
        tofu=tofu or TofuPolicy(enabled=True, max_risk_tier="caution"),
        receipts=receipts or ReceiptPolicy(),
        attestation=attestation or AttestationPolicy(),
        auto_repin_review=auto_repin_review,
        timeout_seconds=5.0,
    )
    trust = TrustManager(
        cfg.alias,
        MemoryPinStore(),
        cfg.tofu,
        auto_repin_review=cfg.auto_repin_review,
        pending_path=tmp_path / "pending.json",
    )
    return ServerBridge(
        cfg,
        trust=trust,
        audit=ReceiptAuditLog(tmp_path / "audit.jsonl"),
        confirmer=confirmer,
    )


@pytest.fixture()
def bridge(server, tmp_path, confirmer):
    b = make_bridge(server, tmp_path, confirmer)
    b.sync()
    yield b
    b.close()
