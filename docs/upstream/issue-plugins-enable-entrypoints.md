# Upstream issue draft — NousResearch/hermes-agent

> Status: **draft, not filed**. Paste into a new issue at
> https://github.com/NousResearch/hermes-agent/issues when ready.
> Verified against commit `db7714d5f17b1c9d009b8e8211a1e8a005295383` (2026-06-11).

---

**Title:** `hermes plugins enable` cannot enable pip entry-point plugins the loader fully supports

## Summary

The plugin **loader** supports pip-installed plugins via the
`hermes_agent.plugins` entry-point group (`PluginManager._scan_entry_points`,
`hermes_cli/plugins.py:1482`), gated on the `plugins.enabled` allow-list. But
the **CLI discovery** used by `hermes plugins enable` / `list`
(`_discover_all_plugins`, `hermes_cli/plugins_cmd.py:880`) only scans the
bundled and `~/.hermes/plugins/` directories — it never queries entry
points. So the only supported way to *opt in* to an entry-point plugin
rejects it:

```console
$ pip install glyphp-hermes        # exposes hermes_agent.plugins → glyph
$ hermes plugins enable glyph
Plugin 'glyph' is not installed or bundled.
```

`cmd_enable` (plugins_cmd.py:745) calls `_resolve_plugin_key(name)`, which
walks `_discover_all_plugins()` — bundled + user dirs only — finds nothing,
and exits 1.

## Repro

1. `pip install` any package exposing the `hermes_agent.plugins` entry-point
   group (a minimal `register(ctx)` no-op is enough).
2. `hermes plugins enable <name>` → "not installed or bundled", exit 1.
3. Manually add the name under `plugins.enabled` in `~/.hermes/config.yaml`
   → the plugin loads perfectly on the next run, confirming this is purely a
   CLI-discovery gap.

## Proposed fix

Include entry points in CLI discovery, e.g. at the end of
`_discover_all_plugins` (plugins_cmd.py:880):

```python
    # Pip plugins (hermes_agent.plugins entry points) — same group the
    # loader scans in PluginManager._scan_entry_points.
    import importlib.metadata
    from hermes_cli.plugins import ENTRY_POINTS_GROUP
    try:
        eps = importlib.metadata.entry_points()
        group_eps = (
            eps.select(group=ENTRY_POINTS_GROUP)
            if hasattr(eps, "select")
            else eps.get(ENTRY_POINTS_GROUP, [])
        )
        for ep in group_eps:
            version = ""
            try:
                version = ep.dist.version if ep.dist else ""
            except Exception:
                pass
            seen.setdefault(
                ep.name, (ep.name, version, ep.value, "pip", ep.value, ep.name)
            )
    except Exception:
        pass
    return list(seen.values())
```

With that, `_resolve_plugin_key` matches the entry-point name and
`enable`/`disable`/`list` work for pip plugins exactly as the loader already
expects (the loader keys entry-point plugins by `ep.name`, so the enabled-set
entry matches).

`setdefault` keeps the current precedence (bundled/user dirs win on name
collision), mirroring `discover_and_load`.

## Context

Found while building [glyphp-hermes](https://github.com/Monoperro0207/glyphp-hermes),
a pip-installable plugin that bridges signed Glyph Protocol tool servers into
Hermes. Current workaround we document for users: edit
`~/.hermes/config.yaml` directly, or copy the package into
`~/.hermes/plugins/<name>/` so directory discovery sees it.

Happy to send this as a PR if the approach looks right.
