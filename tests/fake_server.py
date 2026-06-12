"""In-process fake Glyph server for hermetic tests.

Implements the wire contract the plugin depends on (handshake, lexicon, card
fetch, prepare/confirm, call with sealed envelope) over a real loopback HTTP
socket, with genuinely signed ed25519 cards and receipts — so the *real*
``glyph_protocol`` SDK client and verifiers run unmodified against it.

Mutation knobs let tests exercise the failure space:
  - ``tamper_card(name, **overrides)``  → legitimate re-issue (re-id, re-sign)
  - ``corrupt_signature(name)``         → invalid card signature
  - ``tamper_receipts(True)``           → receipts signed then corrupted
  - ``set_error(name, code, status)``   → forced protocol error on /call
  - ``rotate_key()``                    → new signing key (key-swap scenarios)
"""
from __future__ import annotations

import json
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Optional
from urllib.parse import urlparse

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from glyph_protocol import canonical_hash

from .cardlab import build_card, hex_pub, now_iso, sign

CONFIRMATION_TTL_SECONDS = 120.0


class FakeGlyph:
    def __init__(
        self,
        name: str,
        *,
        intent: str = "",
        risk_tier: str = "safe",
        requires_confirmation: bool = False,
        side_effects: bool = False,
        input_schema: Optional[dict] = None,
        output_schema: Optional[dict] = None,
        attestation: Optional[dict] = None,
        handler: Optional[Callable[[dict], Any]] = None,
    ) -> None:
        self.name = name
        self.intent = intent or f"Fake glyph {name}"
        self.risk_tier = risk_tier
        self.requires_confirmation = requires_confirmation
        self.side_effects = side_effects
        self.input_schema = input_schema or {"type": "object"}
        self.output_schema = output_schema or {"type": "object"}
        self.attestation = attestation
        self.handler = handler or (lambda inp: {"echo": inp})


class FakeGlyphServer:
    def __init__(self, glyphs: list[FakeGlyph]) -> None:
        self._key = Ed25519PrivateKey.generate()
        self.glyphs: dict[str, FakeGlyph] = {g.name: g for g in glyphs}
        self.cards: dict[str, dict] = {}
        self._confirmations: dict[str, dict] = {}
        self._receipt_tamper = False
        self._forced_errors: dict[str, tuple[str, int]] = {}
        self.requests: list[tuple[str, str]] = []  # (method, path) log
        self._httpd: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._rebuild_cards()

    # ---- lifecycle ----------------------------------------------------------

    def start(self) -> "FakeGlyphServer":
        handler = _make_handler(self)
        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None

    def __enter__(self) -> "FakeGlyphServer":
        return self.start()

    def __exit__(self, *_: Any) -> None:
        self.stop()

    @property
    def url(self) -> str:
        assert self._httpd, "server not started"
        host, port = self._httpd.server_address[:2]
        return f"http://{host}:{port}"

    @property
    def public_key(self) -> str:
        return hex_pub(self._key)

    # ---- mutation knobs ------------------------------------------------------

    def _rebuild_cards(self) -> None:
        for glyph in self.glyphs.values():
            self.cards[glyph.name] = build_card(
                self._key,
                name=glyph.name,
                intent=glyph.intent,
                risk_tier=glyph.risk_tier,
                requires_confirmation=glyph.requires_confirmation,
                side_effects=glyph.side_effects,
                input_schema=glyph.input_schema,
                output_schema=glyph.output_schema,
                attestation=glyph.attestation,
            )

    def tamper_card(self, name: str, **glyph_overrides: Any) -> dict:
        """Legitimately re-issue one card with changed fields (re-id + re-sign)."""
        glyph = self.glyphs[name]
        for key, value in glyph_overrides.items():
            setattr(glyph, key, value)
        self._rebuild_cards()
        return self.cards[name]

    def corrupt_signature(self, name: str) -> None:
        self.cards[name] = {**self.cards[name], "signature": "00" * 64}

    def tamper_receipts(self, enabled: bool = True) -> None:
        self._receipt_tamper = enabled

    def set_error(self, name: str, code: str, status: int) -> None:
        self._forced_errors[name] = (code, status)

    def clear_error(self, name: str) -> None:
        self._forced_errors.pop(name, None)

    def rotate_key(self) -> None:
        self._key = Ed25519PrivateKey.generate()
        self._rebuild_cards()

    def add_glyph(self, glyph: FakeGlyph) -> None:
        self.glyphs[glyph.name] = glyph
        self._rebuild_cards()

    def remove_glyph(self, name: str) -> None:
        self.glyphs.pop(name, None)
        self.cards.pop(name, None)

    def expire_confirmations(self) -> None:
        for entry in self._confirmations.values():
            entry["expiresAt"] = time.time() - 1

    # ---- request handling (called from the HTTP handler) ---------------------

    def handle(self, method: str, path: str, body: Optional[dict]) -> tuple[int, dict | list]:
        self.requests.append((method, path))
        parsed = urlparse(path)
        parts = [p for p in parsed.path.split("/") if p]

        if method == "GET" and parts == ["health"]:
            return 200, {"ok": True, "version": "fake", "protocolVersion": "1.0"}

        if method == "POST" and parts == ["handshake"]:
            return 200, {
                "protocolVersion": "1.0",
                "sessionId": str(uuid.uuid4()),
                "lexicon": self._lexicon(),
                "cardDepth": (body or {}).get("preferredCardDepth", "standard"),
                "serverVersion": "fake",
            }

        if method == "GET" and parts == ["lexicon"]:
            return 200, self._lexicon()

        if method == "GET" and parts == ["keys"]:
            return 404, _err("NOT_FOUND", "no key registry")

        if len(parts) == 2 and parts[0] == "glyphs" and method == "GET":
            card = self.cards.get(parts[1])
            if not card:
                return 404, _err("NOT_FOUND", f"unknown glyph {parts[1]}")
            return 200, card

        if len(parts) == 3 and parts[0] == "glyphs":
            name = parts[1]
            if name not in self.cards:
                return 404, _err("NOT_FOUND", f"unknown glyph {name}")
            if parts[2] == "prepare" and method == "POST":
                return self._prepare(name, body or {})
            if parts[2] == "call" and method == "POST":
                return self._call(name, body or {})

        return 404, _err("NOT_FOUND", path)

    def _lexicon(self) -> list[dict]:
        return [
            {
                "name": g.name,
                "intent": g.intent,
                "riskTier": g.risk_tier,
                "requiresConfirmation": g.requires_confirmation,
            }
            for g in self.glyphs.values()
        ]

    def _prepare(self, name: str, body: dict) -> tuple[int, dict]:
        card = self.cards[name]
        input_value = body.get("input", {})
        token = str(uuid.uuid4())
        self._confirmations[token] = {
            "glyphName": name,
            "inputHash": canonical_hash(input_value),
            "expiresAt": time.time() + CONFIRMATION_TTL_SECONDS,
        }
        return 200, {
            "confirmationToken": token,
            "glyphId": card["id"],
            "name": name,
            "cost": card["cost"],
            "input": input_value,
            "expiresAt": now_iso(),
        }

    def _call(self, name: str, body: dict) -> tuple[int, dict]:
        glyph = self.glyphs[name]
        card = self.cards[name]
        input_value = body.get("input", {})

        forced = self._forced_errors.get(name)
        if forced:
            code, status = forced
            return status, _err(code, f"forced {code} for tests")

        if glyph.requires_confirmation:
            token = body.get("confirmationToken")
            if not token:
                return 403, _err(
                    "CONFIRMATION_REQUIRED",
                    "This glyph requires confirmation",
                    {"glyph": name, "cost": card["cost"]},
                )
            pending = self._confirmations.pop(token, None)  # single-use
            if not pending:
                return 403, _err(
                    "INVALID_CONFIRMATION", "Unknown or already-consumed confirmation token"
                )
            valid = (
                time.time() < pending["expiresAt"]
                and pending["glyphName"] == name
                and pending["inputHash"] == canonical_hash(input_value)
            )
            if not valid:
                return 403, _err(
                    "INVALID_CONFIRMATION", "Expired or mismatched confirmation token"
                )

        try:
            payload = glyph.handler(input_value)
        except Exception as exc:  # noqa: BLE001 — handler errors are wire errors
            return 502, _err("HANDLER_ERROR", str(exc))

        inspection = {"modified": False, "findings": []}
        receipt_base: dict[str, Any] = {
            "receiptVersion": "0.3",
            "callId": str(uuid.uuid4()),
            "glyphId": card["id"],
            "glyphName": name,
            "inputHash": canonical_hash(input_value),
            "outputHash": canonical_hash(payload),
            "inspectionHash": canonical_hash(inspection),
            "riskTier": glyph.risk_tier,
            "provider": card["provider"],
            "latencyMs": 1,
            "timestamp": now_iso(),
            "serverPublicKey": self.public_key,
        }
        if body.get("callId"):
            receipt_base["clientCallId"] = body["callId"]
        signature = sign(self._key, canonical_hash(receipt_base))
        if self._receipt_tamper:
            # Flip the last byte: structurally plausible, cryptographically wrong.
            signature = signature[:-2] + ("00" if signature[-2:] != "00" else "ff")
        receipt = {**receipt_base, "signature": signature}
        return 200, {"payload": payload, "receipt": receipt, "inspection": inspection}


def _err(code: str, message: str, details: Optional[dict] = None) -> dict:
    error: dict[str, Any] = {"code": code, "message": message}
    if details:
        error["details"] = details
    return {"error": error}


def _make_handler(server: FakeGlyphServer):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:  # silence test output
            pass

        def _respond(self) -> None:
            body: Optional[dict] = None
            length = int(self.headers.get("content-length") or 0)
            if length:
                try:
                    body = json.loads(self.rfile.read(length))
                except json.JSONDecodeError:
                    self._send(400, _err("MALFORMED_JSON", "body is not JSON"))
                    return
            status, payload = server.handle(self.command, self.path, body)
            self._send(status, payload)

        def _send(self, status: int, payload: dict | list) -> None:
            data = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self) -> None:  # noqa: N802 — http.server API
            self._respond()

        def do_POST(self) -> None:  # noqa: N802
            self._respond()

    return Handler


def default_glyphs() -> list[FakeGlyph]:
    """The standard 3-glyph corpus used across the test suite."""
    notes: list[dict] = []

    def add_note(inp: dict) -> dict:
        notes.append({"id": len(notes) + 1, "text": inp.get("text", "")})
        return {"added": notes[-1]}

    def delete_note(inp: dict) -> dict:
        target = inp.get("id")
        kept = [n for n in notes if n["id"] != target]
        deleted = len(kept) < len(notes)
        notes[:] = kept
        return {"deleted": deleted}

    return [
        FakeGlyph("echo", intent="Echoes its input", risk_tier="safe"),
        FakeGlyph(
            "notes.add",
            intent="Append a note",
            risk_tier="caution",
            side_effects=True,
            input_schema={
                "type": "object",
                "properties": {"text": {"type": "string"}},
                "required": ["text"],
            },
            handler=add_note,
        ),
        FakeGlyph(
            "notes.delete",
            intent="Delete a note permanently",
            risk_tier="danger",
            requires_confirmation=True,
            side_effects=True,
            input_schema={
                "type": "object",
                "properties": {"id": {"type": "integer"}},
                "required": ["id"],
            },
            handler=delete_note,
        ),
    ]
