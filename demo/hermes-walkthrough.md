# Running glyphp-hermes inside the real Hermes agent

This walkthrough installs the plugin into a
[hermes-agent](https://github.com/NousResearch/hermes-agent) checkout and
exercises it both without and with an LLM.

## 1. Install the plugin into Hermes' environment

```bash
# inside the virtualenv / uv env where hermes-agent runs:
pip install glyphp-hermes          # or: pip install -e /path/to/glyphp-hermes
glyphp-hermes enable               # add glyph to ~/.hermes/config.yaml (idempotent, backs up)
# restart Hermes, then:
glyphp-hermes status               # confirm it is installed + enabled
```

Entry-point plugins are opt-in, gated on `plugins.enabled` in
`~/.hermes/config.yaml`. `glyphp-hermes enable` writes exactly that — it
creates the file if missing, is a no-op if `glyph` is already listed, and
preserves the rest of your config verbatim (backing it up to
`config.yaml.bak`). It exists because `hermes plugins enable glyph` only
discovers directory-installed plugins, not pip entry-points (a Hermes
CLI-discovery gap — see
[docs/upstream/issue-plugins-enable-entrypoints.md](../docs/upstream/issue-plugins-enable-entrypoints.md)).
For the same reason `hermes plugins list` won't show the plugin; use
`glyphp-hermes status` (or `hermes glyph list` once loaded) to verify instead.

> Manual / folder-install alternatives (no console script):
> - edit `~/.hermes/config.yaml` by hand with the `plugins.enabled: [glyph]`
>   block above; or
> - copy `src/glyphp_hermes/` to `~/.hermes/plugins/glyph/` — `plugin.yaml`
>   ships inside the package — and then `hermes plugins enable glyph` works.

## 2. Start the demo Glyph server

```bash
cd demo && npm install && npm run server
```

## 3. Register the server (no LLM needed)

```bash
hermes glyph add demo http://127.0.0.1:3100 --tofu-max-risk caution
hermes glyph sync
#   [demo] 4 tools (2 callable, 2 blocked)
#   glyph_demo_notes_list: callable
#   glyph_demo_notes_add: callable
#   glyph_demo_notes_delete: TRUST_REQUIRED   (danger > tofu-max-risk caution)
#   glyph_demo_notes_export: TRUST_REQUIRED   (danger > tofu-max-risk caution)

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
