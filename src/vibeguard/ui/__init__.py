"""The local web UI — a browser front end for the same Engine the CLI drives.

The package is optional. ``fastapi`` and ``uvicorn`` live in the ``[ui]`` extra, and
nothing in the core import graph reaches in here: ``vibeguard.cli`` imports
:func:`vibeguard.ui.server.create_app` lazily inside the ``ui`` command, so a plain
install keeps working without the extra.

Importing this module does **not** import FastAPI. Ask for
:func:`vibeguard.ui.server.create_app` (or call :func:`missing_dependency`) when you
want to know whether the extra is present.
"""

from __future__ import annotations

__all__ = ["missing_dependency", "UI_EXTRA_HINT"]

#: What to tell a user who ran ``vibeguard ui`` without the extra installed.
UI_EXTRA_HINT = 'pip install "vibeguard[ui]"'


def missing_dependency() -> str | None:
    """The name of the missing web dependency, or None when the extra is installed."""
    for module in ("fastapi", "uvicorn"):
        try:
            __import__(module)
        except ImportError:
            return module
    return None
