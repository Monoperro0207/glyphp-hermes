"""Uniform tool-facing error envelopes and Glyph wire-error parsing.

Hermes tools return strings to the model; every failure path in this plugin
returns the same JSON shape so the model can react predictably:

    {"ok": false, "error": {"code": ..., "message": ...}, ...extra}

Pure Python — no Hermes imports.
"""
from __future__ import annotations

import json
from typing import Any

import httpx

# Agent-actionable guidance per wire code. Appended to the message so the
# model knows what to do next without guessing.
_GUIDANCE = {
    "VALIDATION_FAILED": "Fix the input to match the tool's schema and retry.",
    "RATE_LIMITED": "Back off and retry later.",
    "CONFIRMATION_REQUIRED": "This call needs user confirmation.",
    "INVALID_CONFIRMATION": "The confirmation expired or was already used; the call must be confirmed again.",
    "HANDLER_TIMEOUT": "The provider timed out. Retrying may help; do not assume the action completed.",
    "HANDLER_ERROR": "The provider failed internally. Do not assume the action completed.",
    "NOT_FOUND": "The tool is not registered on the server anymore.",
    "UNAUTHORIZED": "The server rejected our credentials; the user must fix the auth token.",
    "INSUFFICIENT_SCOPE": "The configured credentials lack the scopes this tool requires.",
    "USER_DENIED": "Do NOT retry — the user explicitly declined this action.",
    "CONFIRMATION_TIMEOUT": "The user did not respond in time. Ask them before retrying.",
    "CONFIRMATION_PENDING": (
        "Approval was sent to the user. Tell the user an approval is waiting, "
        "and retry this exact call only after they approve."
    ),
    "CONFIRMATION_UNAVAILABLE": (
        "No approval channel is available in this context; the action is blocked fail-closed."
    ),
    "RECEIPT_INVALID": (
        "The server's signed receipt failed verification; the result was withheld as untrusted."
    ),
    "SERVER_UNREACHABLE": "The Glyph server is not reachable; the user may need to start it.",
    "TRUST_REQUIRED": "The tool is not trusted yet.",
    "CARD_CHANGED": "The tool's card changed since approval.",
    "CARD_REVOKED": "The tool was revoked by the operator.",
    "CARD_INVALID": "The tool's signature does not verify; never call it.",
    "ATTESTATION_REQUIRED": "Policy requires a supply-chain attestation this tool does not carry.",
    "ATTESTATION_UNTRUSTED": "The tool's attestation failed verification or violates the identity policy.",
}


def tool_error(code: str, message: str, **extra: Any) -> str:
    guidance = _GUIDANCE.get(code)
    full_message = f"{message} {guidance}" if guidance and guidance not in message else message
    payload: dict[str, Any] = {"ok": False, "error": {"code": code, "message": full_message}}
    payload.update(extra)
    return json.dumps(payload)


def parse_glyph_error(exc: httpx.HTTPStatusError) -> dict:
    """Extract `{code, message, details}` from a Glyph error response."""
    try:
        error = exc.response.json().get("error") or {}
    except (json.JSONDecodeError, ValueError):
        error = {}
    code = error.get("code") or f"HTTP_{exc.response.status_code}"
    message = error.get("message") or exc.response.text[:200] or "request failed"
    out = {"code": code, "message": message}
    if error.get("details") is not None:
        out["details"] = error["details"]
    return out
