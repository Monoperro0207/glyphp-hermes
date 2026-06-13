"""Configuration for the glyph plugin.

Lives at ``<HERMES_HOME>/glyph/glyph.yaml`` (``~/.hermes/glyph/glyph.yaml`` by
default). Pure Python — no Hermes imports — so it is fully testable outside a
Hermes process. The ``HERMES_HOME`` env var is the same isolation mechanism
hermes-agent itself uses.
"""
from __future__ import annotations

import os
import re
import tempfile
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Optional

import yaml

RISK_ORDER = {"safe": 0, "caution": 1, "danger": 2}

_ALIAS_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")


def hermes_home() -> Path:
    """Hermes' own home dir (``~/.hermes`` by default; ``HERMES_HOME`` wins).

    The same isolation knob hermes-agent itself uses. ``config.yaml`` (Hermes'
    config, with the ``plugins.enabled`` allow-list) lives directly here."""
    return Path(os.environ.get("HERMES_HOME", "~/.hermes")).expanduser()


def hermes_config_path() -> Path:
    """Hermes' config file — distinct from this plugin's ``glyph.yaml``."""
    return hermes_home() / "config.yaml"


def glyph_home() -> Path:
    """Root for all plugin state (config, pins, audit logs, pending queues)."""
    return hermes_home() / "glyph"


def config_path() -> Path:
    return glyph_home() / "glyph.yaml"


@dataclass(frozen=True)
class TofuPolicy:
    """Trust-on-first-use: auto-pin never-seen cards up to a risk tier."""

    enabled: bool = True
    max_risk_tier: str = "safe"

    def allows(self, tier: str) -> bool:
        if not self.enabled:
            return False
        return RISK_ORDER.get(tier, 99) <= RISK_ORDER.get(self.max_risk_tier, -1)


@dataclass(frozen=True)
class ReceiptPolicy:
    verify: bool = True
    on_failure: str = "block"  # block | warn


@dataclass(frozen=True)
class ConfirmationPolicy:
    # What to do when a glyph requires confirmation but there is no user to
    # ask (cron, non-interactive, outside Hermes). Fail-closed by default.
    non_interactive: str = "deny"  # deny (only valid value in v0.1; reserved)


@dataclass(frozen=True)
class AttestationPolicy:
    """Mirror of @glyphp/client `requireAttestation` ('none'|'danger'|'all')."""

    require: str = "none"  # none | danger | all
    issuers: tuple[str, ...] = ()
    identities: tuple[str, ...] = ()


@dataclass(frozen=True)
class ServerConfig:
    alias: str
    url: str
    auth_token_env: Optional[str] = None
    timeout_seconds: float = 30.0
    tofu: TofuPolicy = field(default_factory=TofuPolicy)
    receipts: ReceiptPolicy = field(default_factory=ReceiptPolicy)
    confirmations: ConfirmationPolicy = field(default_factory=ConfirmationPolicy)
    attestation: AttestationPolicy = field(default_factory=AttestationPolicy)
    auto_repin_review: bool = True
    check_key_registry: bool = False

    def auth_token(self) -> Optional[str]:
        if not self.auth_token_env:
            return None
        return os.environ.get(self.auth_token_env) or None

    def pin_path(self) -> Path:
        return glyph_home() / "pins" / f"{self.alias}.json"

    def audit_path(self) -> Path:
        return glyph_home() / "audit" / f"{self.alias}.jsonl"

    def pending_path(self) -> Path:
        return glyph_home() / "pending" / f"{self.alias}.json"


class ConfigError(ValueError):
    pass


def _validate_alias(alias: str) -> str:
    if not _ALIAS_RE.match(alias or ""):
        raise ConfigError(
            f"invalid server alias {alias!r}: must match {_ALIAS_RE.pattern}"
        )
    return alias


def _deep_merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


_DEFAULTS: dict[str, Any] = {
    "tofu": {"enabled": True, "max_risk_tier": "safe"},
    "receipts": {"verify": True, "on_failure": "block"},
    "confirmations": {"non_interactive": "deny"},
    "attestation": {"require": "none", "issuers": [], "identities": []},
    "auto_repin_review": True,
    "check_key_registry": False,
    "timeout_seconds": 30.0,
}


def _policies_from(merged: dict) -> dict:
    tofu = merged.get("tofu", {})
    receipts = merged.get("receipts", {})
    confirmations = merged.get("confirmations", {})
    attestation = merged.get("attestation", {})
    if receipts.get("on_failure") not in ("block", "warn"):
        raise ConfigError(
            f"receipts.on_failure must be 'block' or 'warn', got {receipts.get('on_failure')!r}"
        )
    if attestation.get("require") not in ("none", "danger", "all"):
        raise ConfigError(
            f"attestation.require must be none|danger|all, got {attestation.get('require')!r}"
        )
    if tofu.get("max_risk_tier") not in RISK_ORDER:
        raise ConfigError(
            f"tofu.max_risk_tier must be safe|caution|danger, got {tofu.get('max_risk_tier')!r}"
        )
    return {
        "tofu": TofuPolicy(
            enabled=bool(tofu.get("enabled", True)),
            max_risk_tier=tofu.get("max_risk_tier", "safe"),
        ),
        "receipts": ReceiptPolicy(
            verify=bool(receipts.get("verify", True)),
            on_failure=receipts.get("on_failure", "block"),
        ),
        "confirmations": ConfirmationPolicy(
            non_interactive=confirmations.get("non_interactive", "deny"),
        ),
        "attestation": AttestationPolicy(
            require=attestation.get("require", "none"),
            issuers=tuple(attestation.get("issuers") or ()),
            identities=tuple(attestation.get("identities") or ()),
        ),
        "auto_repin_review": bool(merged.get("auto_repin_review", True)),
        "check_key_registry": bool(merged.get("check_key_registry", False)),
        "timeout_seconds": float(merged.get("timeout_seconds", 30.0)),
    }


@dataclass
class GlyphConfig:
    servers: list[ServerConfig] = field(default_factory=list)
    defaults: dict = field(default_factory=lambda: dict(_DEFAULTS))

    @classmethod
    def load(cls, path: Optional[Path] = None) -> "GlyphConfig":
        path = path or config_path()
        if not path.exists():
            return cls()
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        defaults = _deep_merge(_DEFAULTS, raw.get("defaults") or {})
        servers: list[ServerConfig] = []
        for entry in raw.get("servers") or []:
            alias = _validate_alias(str(entry.get("alias", "")))
            url = str(entry.get("url", "")).rstrip("/")
            if not url:
                raise ConfigError(f"server {alias!r} has no url")
            merged = _deep_merge(defaults, entry)
            policies = _policies_from(merged)
            servers.append(
                ServerConfig(
                    alias=alias,
                    url=url,
                    auth_token_env=entry.get("auth_token_env") or None,
                    **policies,
                )
            )
        seen: set[str] = set()
        for server in servers:
            if server.alias in seen:
                raise ConfigError(f"duplicate server alias {server.alias!r}")
            seen.add(server.alias)
        return cls(servers=servers, defaults=defaults)

    def save(self, path: Optional[Path] = None) -> Path:
        path = path or config_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        doc = {
            "version": 1,
            "defaults": self.defaults,
            "servers": [
                {
                    "alias": s.alias,
                    "url": s.url,
                    **({"auth_token_env": s.auth_token_env} if s.auth_token_env else {}),
                    "tofu": {"enabled": s.tofu.enabled, "max_risk_tier": s.tofu.max_risk_tier},
                    "receipts": {"verify": s.receipts.verify, "on_failure": s.receipts.on_failure},
                    "confirmations": {"non_interactive": s.confirmations.non_interactive},
                    "attestation": {
                        "require": s.attestation.require,
                        "issuers": list(s.attestation.issuers),
                        "identities": list(s.attestation.identities),
                    },
                    "auto_repin_review": s.auto_repin_review,
                    "check_key_registry": s.check_key_registry,
                    "timeout_seconds": s.timeout_seconds,
                }
                for s in self.servers
            ],
        }
        # Atomic write: temp file in the same directory, then rename.
        fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".glyph-yaml-")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                yaml.safe_dump(doc, fh, sort_keys=False)
            os.replace(tmp, path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
        return path

    def get_server(self, alias: str) -> Optional[ServerConfig]:
        for server in self.servers:
            if server.alias == alias:
                return server
        return None

    def add_server(self, server: ServerConfig) -> None:
        _validate_alias(server.alias)
        if self.get_server(server.alias):
            raise ConfigError(f"server alias {server.alias!r} already exists")
        self.servers.append(replace(server, url=server.url.rstrip("/")))

    def remove_server(self, alias: str) -> bool:
        before = len(self.servers)
        self.servers = [s for s in self.servers if s.alias != alias]
        return len(self.servers) < before
