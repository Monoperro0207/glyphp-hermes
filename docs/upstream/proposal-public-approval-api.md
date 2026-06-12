# Upstream proposal draft — NousResearch/hermes-agent

> Status: **draft, not filed**. Paste into a new issue/discussion at
> https://github.com/NousResearch/hermes-agent when ready.
> Verified against commit `db7714d5f17b1c9d009b8e8211a1e8a005295383` (2026-06-11).

---

**Title:** Public blocking-approval API for plugin tools (gateway + CLI)

## Motivation

Plugins can register tools whose calls need an explicit human decision
*bound to that one call* — not a session-scoped pattern approval. Hermes
already has everything required internally:

- CLI: `tools.approval.prompt_dangerous_approval(...)` — public enough and
  works well for plugin tools.
- Gateway: the terminal guard gets a **blocking, per-call decision** via the
  private pair `_await_gateway_decision(session_key, notify_cb,
  approval_data, surface=...)` + `_gateway_notify_cbs` (tools/approval.py).
  The user answers on Telegram/Slack/Discord and the tool proceeds or not —
  one shot, no replay.

For plugins, only the session-scoped path is public today
(`submit_pending` → `resolve_gateway_approval` → `approve_session`/
`is_approved`). That semantics is wrong for one-shot confirmations: once the
pattern key lands in the session set, an identical later call silently
skips the human. Plugins that need one-shot semantics either reach into the
private symbols (fragile across releases) or rebuild a grant store on top of
the `post_approval_response` hook (works, but every plugin reinvents it).

## Proposal

Expose one public function in `tools.approval`:

```python
def request_tool_approval(
    *,
    summary: str,
    description: str = "",
    approval_key: str,
    surface: str = "plugin",
    timeout: float | None = None,
) -> Literal["approved", "denied", "timeout", "unavailable"]:
    """Blocking, one-shot approval for a single tool call.

    CLI sessions → prompt_dangerous_approval (allow_permanent=False).
    Gateway sessions → the same blocking flow the terminal guard uses.
    No session persistence: an identical later call asks again.
    Returns "unavailable" in non-interactive contexts (cron) — callers
    are expected to fail closed.
    """
```

Implementation is mostly plumbing around the existing
`_await_gateway_decision`; the contract (one-shot, fail-closed,
per-call binding) is the valuable part to freeze.

## Real-world usage

[glyphp-hermes](https://github.com/Monoperro0207/glyphp-hermes) maps Glyph
Protocol confirmation gates (prepare → single-use token bound to the exact
input) onto Hermes approvals. Today it feature-detects the private tier-1
symbols and degrades to a `submit_pending` + own one-shot grant store fed by
`post_approval_response` (tier 2). A public API would let it — and any
plugin with dangerous tools — drop both the private-symbol dependency and
the duplicated grant store.

Happy to contribute the implementation if the shape looks right.
