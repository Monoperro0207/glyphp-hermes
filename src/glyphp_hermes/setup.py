"""``glyphp-hermes`` console script — enable the plugin in Hermes without friction.

Hermes loads pip entry-point plugins (the ``hermes_agent.plugins`` group this
package registers) **only when they are listed under ``plugins.enabled`` in
``<HERMES_HOME>/config.yaml``**. Its ``hermes plugins enable`` command does not
discover entry-point plugins (a Hermes CLI-discovery gap, see
``docs/upstream/issue-plugins-enable-entrypoints.md``), so the supported opt-in
is editing that allow-list. This command does it for you:

    pip install glyphp-hermes
    glyphp-hermes enable      # adds `glyph` to plugins.enabled, then restart Hermes
    glyphp-hermes status      # confirm it is installed + enabled

``enable`` is idempotent, backs the config up before touching it, and preserves
the rest of the file verbatim (it only re-serializes — with a backup and a
printed note — for an unusual config shape it cannot edit textually).
"""
from __future__ import annotations

import argparse
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any, Optional

import yaml

from .config import hermes_config_path

_GLYPH = "glyph"
_RESTART_HINT = "Restart Hermes (or start a new session) for the change to take effect."


# ---- config helpers --------------------------------------------------------


def _enabled_list(data: Any) -> list:
    """The ``plugins.enabled`` list, or ``[]`` if absent/malformed."""
    if not isinstance(data, dict):
        return []
    plugins = data.get("plugins")
    if not isinstance(plugins, dict):
        return []
    enabled = plugins.get("enabled")
    return enabled if isinstance(enabled, list) else []


def _with_glyph(data: Any) -> dict:
    out = dict(data) if isinstance(data, dict) else {}
    raw_plugins = out.get("plugins")
    plugins = dict(raw_plugins) if isinstance(raw_plugins, dict) else {}
    raw_enabled = plugins.get("enabled")
    enabled = list(raw_enabled) if isinstance(raw_enabled, list) else []
    if _GLYPH not in enabled:
        enabled.append(_GLYPH)
    plugins["enabled"] = enabled
    out["plugins"] = plugins
    return out


def _backup(path: Path) -> Path:
    bak = path.with_name(path.name + ".bak")
    bak.write_bytes(path.read_bytes())
    return bak


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".hermes-cfg-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


# ---- minimal, comment-preserving text edits --------------------------------


def _append_plugins_block(text: str) -> str:
    """For a config with no ``plugins:`` key — append the block at EOF."""
    block = "plugins:\n  enabled:\n    - glyph\n"
    if not text.strip():
        return block
    if not text.endswith("\n"):
        text += "\n"
    return f"{text}\n{block}"


def _insert_into_enabled(text: str) -> Optional[str]:
    """Insert ``- glyph`` into an existing block-style ``plugins.enabled`` list.

    Returns the new text, or ``None`` if the config is not a clean block-style
    list (flow style, inline value, non-list content) — the caller falls back
    to a structured rewrite then.
    """
    lines = text.splitlines()
    p_idx = next(
        (i for i, ln in enumerate(lines) if re.match(r"^plugins:\s*(#.*)?$", ln)), None
    )
    if p_idx is None:
        return None

    e_idx: Optional[int] = None
    e_indent = 0
    for i in range(p_idx + 1, len(lines)):
        ln = lines[i]
        if not ln.strip() or ln.lstrip().startswith("#"):
            continue
        indent = len(ln) - len(ln.lstrip())
        if indent == 0:
            break  # left the plugins block
        m = re.match(r"^(\s+)enabled:\s*(.*?)\s*$", ln)
        if m:
            trailing = m.group(2)
            if trailing and not trailing.startswith("#"):
                return None  # inline/flow value, e.g. `enabled: [a, b]`
            e_idx, e_indent = i, len(m.group(1))
            break
    if e_idx is None:
        return None  # `plugins:` exists but no block `enabled:` — let caller rewrite

    last_item = e_idx
    item_indent: Optional[int] = None
    for i in range(e_idx + 1, len(lines)):
        ln = lines[i]
        if not ln.strip() or ln.lstrip().startswith("#"):
            continue
        indent = len(ln) - len(ln.lstrip())
        if indent <= e_indent:
            break  # left the enabled block
        if ln.lstrip().startswith("- "):
            last_item = i
            if item_indent is None:
                item_indent = indent
        else:
            return None  # unexpected content under enabled
    if item_indent is None:
        item_indent = e_indent + 2

    lines.insert(last_item + 1, " " * item_indent + f"- {_GLYPH}")
    return "\n".join(lines) + ("\n" if text.endswith("\n") else "")


def _remove_glyph_line(text: str) -> Optional[str]:
    """Drop a block-style ``- glyph`` list item. ``None`` if not found."""
    lines = text.splitlines()
    kept = [ln for ln in lines if not re.match(r"^\s*-\s+glyph\s*(#.*)?$", ln)]
    if len(kept) == len(lines):
        return None
    return "\n".join(kept) + ("\n" if text.endswith("\n") else "")


# ---- subcommands -----------------------------------------------------------


def _enable() -> int:
    path = hermes_config_path()
    if not path.exists():
        _atomic_write(path, _append_plugins_block(""))
        print(f"Created {path} with the glyph plugin enabled.")
        print(_RESTART_HINT)
        return 0

    text = path.read_text(encoding="utf-8")
    try:
        data = yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        print(f"error: {path} is not valid YAML ({exc}); not modifying it.", file=sys.stderr)
        return 2
    if _GLYPH in _enabled_list(data):
        print(f"glyph is already enabled in {path}. Nothing to do.")
        return 0

    bak = _backup(path)
    if isinstance(data, dict) and "plugins" in data:
        new_text = _insert_into_enabled(text)
        if new_text is None:
            new_text = yaml.safe_dump(_with_glyph(data), sort_keys=False)
            print(f"note: re-serialized {path.name} (original saved to {bak.name}).")
    else:
        new_text = _append_plugins_block(text)

    _atomic_write(path, new_text)
    after = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if _GLYPH not in _enabled_list(after):
        print(f"error: could not enable glyph; restored nothing, see {bak}.", file=sys.stderr)
        return 1
    print(f"Enabled the glyph plugin in {path} (backup: {bak.name}).")
    print(_RESTART_HINT)
    return 0


def _disable() -> int:
    path = hermes_config_path()
    if not path.exists():
        print(f"{path} does not exist; nothing to disable.")
        return 0
    text = path.read_text(encoding="utf-8")
    try:
        data = yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        print(f"error: {path} is not valid YAML ({exc}); not modifying it.", file=sys.stderr)
        return 2
    if _GLYPH not in _enabled_list(data):
        print(f"glyph is not enabled in {path}. Nothing to do.")
        return 0

    bak = _backup(path)
    new_text = _remove_glyph_line(text)
    if new_text is None:
        plugins = dict(data["plugins"])
        plugins["enabled"] = [x for x in plugins.get("enabled") or [] if x != _GLYPH]
        data["plugins"] = plugins
        new_text = yaml.safe_dump(data, sort_keys=False)
        print(f"note: re-serialized {path.name} (original saved to {bak.name}).")
    _atomic_write(path, new_text)
    print(f"Disabled the glyph plugin in {path} (backup: {bak.name}).")
    print(_RESTART_HINT)
    return 0


def _entry_point_registered() -> bool:
    """Whether pip exposes our ``hermes_agent.plugins`` → ``glyph`` entry-point
    — the exact metadata Hermes' loader scans."""
    import importlib.metadata as im

    try:
        # Python >=3.11 always returns the selectable EntryPoints interface.
        group = im.entry_points().select(group="hermes_agent.plugins")
        return any(ep.name == _GLYPH for ep in group)
    except Exception:  # noqa: BLE001 — metadata lookup is best-effort
        return False


def _status() -> int:
    registered = _entry_point_registered()
    path = hermes_config_path()
    enabled = False
    if path.exists():
        try:
            enabled = _GLYPH in _enabled_list(yaml.safe_load(path.read_text(encoding="utf-8")))
        except yaml.YAMLError:
            pass

    print("glyphp-hermes plugin status")
    print(f"  entry-point registered:    {'yes' if registered else 'no'}")
    print(f"  hermes config:             {path}")
    print(f"  glyph in plugins.enabled:  {'yes' if enabled else 'no'}")
    if registered and enabled:
        print("  → Hermes loads it on the next session (restart if it is running).")
    elif registered and not enabled:
        print("  → installed but not enabled. Run: glyphp-hermes enable")
    else:
        print("  → not installed in this environment. Run: pip install glyphp-hermes")
    print("  note: `hermes plugins list` does not show pip entry-point plugins (a Hermes")
    print("        CLI-discovery gap); use this command to verify instead.")
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="glyphp-hermes",
        description="Enable the Glyph plugin inside Hermes (pip-native, no manual YAML).",
    )
    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("enable", help="add glyph to Hermes' plugins.enabled (default)")
    sub.add_parser("disable", help="remove glyph from Hermes' plugins.enabled")
    sub.add_parser("status", help="show install + enable status")
    sub.add_parser("doctor", help="alias for status")

    args = parser.parse_args(argv)
    cmd = args.cmd or "enable"
    if cmd == "enable":
        return _enable()
    if cmd == "disable":
        return _disable()
    return _status()  # status / doctor


if __name__ == "__main__":
    raise SystemExit(main())
