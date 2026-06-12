"""`hermes glyph ...` CLI subcommand — server management without an agent session.

Also runnable standalone for the demo:  python -m glyphp_hermes.cli <args>
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Callable, Optional

from .audit import ReceiptAuditLog
from .bridge import ServerBridge
from .config import (
    AttestationPolicy,
    ConfigError,
    GlyphConfig,
    ServerConfig,
    TofuPolicy,
)


def setup(parser: argparse.ArgumentParser) -> None:
    sub = parser.add_subparsers(dest="glyph_cmd")

    p_add = sub.add_parser("add", help="register a Glyph server")
    p_add.add_argument("alias")
    p_add.add_argument("url")
    p_add.add_argument("--auth-env", default=None, help="env var holding the bearer token")
    p_add.add_argument(
        "--tofu-max-risk", default="safe", choices=["safe", "caution", "danger"]
    )
    p_add.add_argument(
        "--require-attestation", default="none", choices=["none", "danger", "all"]
    )

    p_remove = sub.add_parser("remove", help="remove a server")
    p_remove.add_argument("alias")

    sub.add_parser("list", help="list configured servers")
    sub.add_parser("sync", help="sync all servers and show trust states")

    p_trust = sub.add_parser("trust", help="trust a pending/new glyph")
    p_trust.add_argument("alias")
    p_trust.add_argument("glyph_name")

    p_audit = sub.add_parser("audit", help="inspect the receipt audit log")
    p_audit.add_argument("--alias", default=None)
    p_audit.add_argument("-n", type=int, default=10)
    p_audit.add_argument("--verify", action="store_true", help="re-verify every receipt")

    p_call = sub.add_parser("call", help="call a glyph directly (no LLM)")
    p_call.add_argument("alias")
    p_call.add_argument("glyph_name")
    p_call.add_argument("input_json")
    p_call.add_argument(
        "--yes", action="store_true", help="auto-approve a confirmation gate"
    )


def handle(args: argparse.Namespace, **_kwargs: Any) -> int:
    cmd = getattr(args, "glyph_cmd", None)
    try:
        if cmd == "add":
            return _add(args)
        if cmd == "remove":
            return _remove(args)
        if cmd == "list":
            return _list()
        if cmd == "sync":
            return _sync(None)
        if cmd == "trust":
            return _trust(args)
        if cmd == "audit":
            return _audit(args)
        if cmd == "call":
            return _call(args)
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2
    print("usage: hermes glyph {add,remove,list,sync,trust,audit,call} ...", file=sys.stderr)
    return 1


def _add(args: argparse.Namespace) -> int:
    cfg = GlyphConfig.load()
    cfg.add_server(
        ServerConfig(
            alias=args.alias,
            url=args.url,
            auth_token_env=args.auth_env,
            tofu=TofuPolicy(enabled=True, max_risk_tier=args.tofu_max_risk),
            attestation=AttestationPolicy(require=args.require_attestation),
        )
    )
    path = cfg.save()
    print(f"added server '{args.alias}' -> {args.url} ({path})")
    return 0


def _remove(args: argparse.Namespace) -> int:
    cfg = GlyphConfig.load()
    if not cfg.remove_server(args.alias):
        print(f"no server named {args.alias!r}", file=sys.stderr)
        return 1
    cfg.save()
    print(f"removed '{args.alias}'")
    return 0


def _list() -> int:
    cfg = GlyphConfig.load()
    if not cfg.servers:
        print("no servers configured")
        return 0
    for server in cfg.servers:
        print(
            f"{server.alias}: {server.url} "
            f"(tofu<= {server.tofu.max_risk_tier}, receipts {server.receipts.on_failure}, "
            f"attestation {server.attestation.require})"
        )
    return 0


def _bridge_for(
    alias: str, *, confirmer: Optional[Callable[[str, str, str], str]] = None
) -> ServerBridge | None:
    cfg = GlyphConfig.load()
    server_cfg = cfg.get_server(alias)
    if server_cfg is None:
        print(f"no server named {alias!r}", file=sys.stderr)
        return None
    from . import _hermes

    return ServerBridge.from_config(
        server_cfg, confirmer or _hermes.request_user_confirmation
    )


def _sync(_args: Optional[argparse.Namespace]) -> int:
    cfg = GlyphConfig.load()
    if not cfg.servers:
        print("no servers configured")
        return 0
    from . import _hermes

    exit_code = 0
    for server_cfg in cfg.servers:
        bridge = ServerBridge.from_config(server_cfg, _hermes.request_user_confirmation)
        try:
            report = bridge.sync()
            print(report.summary())
            for binding in report.bindings:
                state = binding.blocked_code or "callable"
                print(f"  {binding.tool_name}: {state}")
            if not report.ok:
                exit_code = 1
        finally:
            bridge.close()
    return exit_code


def _trust(args: argparse.Namespace) -> int:
    bridge = _bridge_for(args.alias)
    if bridge is None:
        return 1
    try:
        bridge.sync()
        from .bridge import sanitize_tool_name

        tool_name = sanitize_tool_name(args.alias, args.glyph_name)
        print(bridge.trust_tool(tool_name))
        return 0
    finally:
        bridge.close()


def _audit(args: argparse.Namespace) -> int:
    cfg = GlyphConfig.load()
    servers = [s for s in cfg.servers if args.alias in (None, s.alias)]
    if not servers:
        print("no matching servers", file=sys.stderr)
        return 1
    exit_code = 0
    for server_cfg in servers:
        log = ReceiptAuditLog(server_cfg.audit_path())
        if args.verify:
            report = log.verify_all()
            print(
                f"[{server_cfg.alias}] {report['ok']}/{report['total']} receipts verify"
                + (f" — {report['bad']} BAD" if report["bad"] else "")
            )
            if report["bad"]:
                exit_code = 1
                for failure in report["failures"]:
                    print(f"  BAD: {failure}")
        else:
            for entry in log.tail(args.n):
                verdict = "ok " if entry.get("verified") else "BAD"
                print(
                    f"[{server_cfg.alias}] {entry.get('ts')} [{verdict}] "
                    f"{entry.get('toolName')} callId={entry.get('callId')}"
                )
    return exit_code


def _call(args: argparse.Namespace) -> int:
    try:
        input_value = json.loads(args.input_json)
    except json.JSONDecodeError as exc:
        print(f"input is not valid JSON: {exc}", file=sys.stderr)
        return 2

    def yes_confirmer(_summary: str, _description: str, _key: str) -> str:
        return "approved" if args.yes else "unavailable"

    bridge = _bridge_for(args.alias, confirmer=yes_confirmer)
    if bridge is None:
        return 1
    try:
        report = bridge.sync()
        if not report.ok:
            print(f"sync failed: {report.error}", file=sys.stderr)
            return 1
        from .bridge import sanitize_tool_name

        tool_name = sanitize_tool_name(args.alias, args.glyph_name)
        result = bridge.make_handler(tool_name)(input_value)
        print(result)
        return 0 if json.loads(result).get("ok") else 1
    finally:
        bridge.close()


def hermes_handle(args: argparse.Namespace, **kwargs: Any) -> int:
    """``handle`` for the Hermes CLI dispatcher, which discards return values
    (hermes_cli/main.py runs ``args.func(args)`` and exits 0 regardless).
    Raising SystemExit is the only way a blocked call reaches the shell as a
    nonzero exit code instead of a silent success."""
    code = handle(args, **kwargs)
    if code:
        raise SystemExit(code)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="glyphp-hermes")
    setup(parser)
    return handle(parser.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
