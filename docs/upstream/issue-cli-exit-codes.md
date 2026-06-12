# Upstream issue draft — NousResearch/hermes-agent

> Status: **draft, not filed**. Paste into a new issue at
> https://github.com/NousResearch/hermes-agent/issues when ready.
> Verified against commit `db7714d5f17b1c9d009b8e8211a1e8a005295383` (2026-06-11).

---

**Title:** CLI dispatcher discards subcommand return values — every `hermes <cmd>` exits 0

## Summary

`main()` executes the selected subcommand as a bare statement
(`hermes_cli/main.py:12082`):

```python
    # Execute the command
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()
```

The return value of `args.func(args)` is dropped and `main()` returns
`None`, so the process exits 0 no matter what the subcommand reported.
A plugin CLI command (registered via `register_cli_command`) that returns a
nonzero exit code — the standard argparse-handler convention — is silently
flattened into success.

## Impact

Scripts and CI that gate on exit codes treat failures as passes. Example
from a plugin: `hermes glyph call ...` prints a structured error
(`TRUST_REQUIRED`, `CONFIRMATION_UNAVAILABLE`, ...) and returns 1, but the
shell sees 0. The only workaround available to a plugin is raising
`SystemExit` from its handler, which works but is the exception path doing
the dispatcher's job.

## Proposed fix

Propagate the handler's return value, preserving `None` → 0:

```python
    if hasattr(args, "func"):
        result = args.func(args)
        if isinstance(result, int) and result != 0:
            raise SystemExit(result)
    else:
        parser.print_help()
```

This matches what the `secrets` sub-dispatcher already does internally
(`hermes_cli/main.py:11151` returns `args.func(args)`), and it is
backwards-compatible: handlers returning `None` keep exiting 0.
