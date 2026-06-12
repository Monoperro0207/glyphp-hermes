"""glyphp-hermes — native Glyph Protocol integration for hermes-agent.

This module is the object returned by Hermes' entry-point loader
(``hermes_agent.plugins`` → ``glyph = "glyphp_hermes"``) and is also valid as a
folder-install plugin (``~/.hermes/plugins/glyph/`` = a copy of this package,
``plugin.yaml`` sits alongside).

Everything is imported lazily so ``import glyphp_hermes`` never pulls Hermes
internals — the package stays importable (and testable) outside a Hermes
process.
"""
from __future__ import annotations

from ._version import __version__

__all__ = ["register", "__version__"]


def register(ctx) -> None:
    """Hermes plugin entry point. ``ctx`` is a hermes PluginContext."""
    from .plugin import register as _register

    _register(ctx)
