# Running glyphp-hermes inside the real Hermes agent

This walkthrough installs the plugin into a
[hermes-agent](https://github.com/NousResearch/hermes-agent) checkout and
exercises it both without and with an LLM.

## 1. Install the plugin into Hermes' environment

```bash
# inside the virtualenv / uv env where hermes-agent runs:
pip install glyphp-hermes          # or: pip install -e /path/to/glyphp-hermes
```

Entry-point plugins are opt-in, gated on `plugins.enabled` in
`~/.hermes/config.yaml` — add:

```yaml
plugins:
  enabled:
    - glyph
```

(`hermes plugins enable glyph` currently only discovers directory-installed
plugins, not pip entry-points, so edit the config directly.)

Verify: `hermes glyph list` answers (the CLI subcommand only exists if the
plugin loaded).

> Folder-install alternative (no pip): copy `src/glyphp_hermes/` to
> `~/.hermes/plugins/glyph/` — `plugin.yaml` ships inside the package — and
> then `hermes plugins enable glyph` works as usual.

## 2. Start the demo Glyph server

```bash
cd demo && npm install && npm run server
```

## 3. Register the server (no LLM needed)

```bash
hermes glyph add demo http://127.0.0.1:3100 --tofu-max-risk caution
hermes glyph sync
#   [demo] 4 tools (3 callable, 1 blocked)
#   glyph_demo_notes_list: callable
#   glyph_demo_notes_add: callable
#   glyph_demo_notes_delete: TRUST_REQUIRED
#   glyph_demo_notes_export: callable

# Direct call through the full trust chain — still no LLM:
hermes glyph call demo notes.list '{}'
hermes glyph call demo notes.add '{"text": "hello from hermes"}'
hermes glyph call demo notes.delete '{"id": 1}' --yes   # confirmation gate

# Audit evidence:
hermes glyph audit            # tail of signed receipts
hermes glyph audit --verify   # re-verify every receipt offline
```

## 4. With a live agent

Start `hermes` (any configured model) and try:

> *"add a note saying 'ship it', list the notes, then delete the note you just created"*

What you should observe:

1. `glyph_demo_notes_add` and `glyph_demo_notes_list` run normally — each
   call returns a verified receipt summary the model can cite.
2. `glyph_demo_notes_delete` is **blocked** the first time
   (`TRUST_REQUIRED`): the model relays the instruction to run
   `/glyph trust glyph_demo_notes_delete`.
3. After trusting it, the delete call triggers Hermes' **approval prompt**
   (the same UI as dangerous terminal commands). Denying returns
   `USER_DENIED` and the model must not retry.
4. `/glyph audit` shows the signed receipts of everything that actually ran.

In **gateway mode** (Telegram/Slack/Discord), step 3 becomes an approval
message on the platform; the model retries the call after you approve.
Each approval covers exactly one call with exactly that input (one-shot).

## 5. Session commands

| Command | Effect |
|---|---|
| `/glyph status` | every tool, its risk tier and trust state |
| `/glyph sync` | re-sync lexicons, reconcile added/removed tools live |
| `/glyph trust <tool>` | approve a new/changed card (shows the diff first) |
| `/glyph revoke <tool> [reason]` | block a tool immediately |
| `/glyph diff <tool>` | pending breaking changes for a parked tool |
| `/glyph audit [n]` | last n verified receipts |
