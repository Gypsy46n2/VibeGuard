"""Which files describe *this* project, and which are only material it carries.

A repository's ``tests/``, ``examples/``, and ``vendor/`` trees are full of
frameworks, databases, and Kubernetes manifests that the project does not actually
run. Reading them as the production stack is how a Python CLI ends up profiled as a
Flask + Express + Kubernetes deployment with 37k LOC — and how scale-gated rules
that have no business firing get switched on.

So discovery splits the scanned file list in two:

* **primary** — the files that define what this project *is*. Tech detection, LOC,
  service counts, and sensitivity all read only these.
* **fixture** — test, example, sample, demo, vendored, and generated material. Rules
  still scan it (a real vulnerability in ``tests/`` is still a vulnerability); it
  simply never gets to define the project's identity.

Everything is relative to the **scan root**, which is what makes the split correct
for both cases: ``examples/vulnerable-app/app.py`` is fixture material when you scan
the repository, and is plain ``app.py`` — primary — when you scan that directory
directly.

Defaults are extended, never replaced, by ``[vibeguard] fixture_paths`` in
``.vibeguard.toml``.
"""

from __future__ import annotations

import fnmatch
from pathlib import PurePosixPath

__all__ = [
    "DEFAULT_FIXTURE_PATHS",
    "is_fixture_path",
    "split_primary",
]

#: Path patterns whose contents describe test/example/vendor material rather than the
#: project itself. A bare name (no ``/``) matches any *directory component*; anything
#: containing ``/`` or a glob character is matched against the whole relative path.
DEFAULT_FIXTURE_PATHS: list[str] = [
    # tests
    "test",
    "tests",
    "spec",
    "specs",
    "e2e",
    "__tests__",
    "__mocks__",
    "mocks",
    "testdata",
    # fixtures
    "fixture",
    "fixtures",
    "__fixtures__",
    # examples / samples / demos
    "example",
    "examples",
    "sample",
    "samples",
    "sample_*",
    "demo",
    "demos",
    "demo_*",
    # vendored / third-party / installed
    "vendor",
    "vendored",
    "third_party",
    "thirdparty",
    "node_modules",
    "site-packages",
    ".venv",
    "venv",
    "bower_components",
    # generated output
    "dist",
    "build",
    "__pycache__",
]

_TEST_NAME_HINTS = ("test_", "_test.", ".test.", ".spec.", "_spec.", "conftest.py")


def _matches_component(part: str, pattern: str) -> bool:
    return fnmatch.fnmatchcase(part.lower(), pattern.lower())


def is_fixture_path(relpath: str, patterns: list[str] | None = None) -> bool:
    """True when ``relpath`` is test, example, sample, or vendored material.

    ``relpath`` is POSIX-relative to the scan root. Directory-name patterns match any
    component of the path; path-shaped patterns (containing ``/``) are matched against
    the whole path with ``fnmatch``. A file whose *name* is test-shaped
    (``test_x.py``, ``x.spec.ts``, ``conftest.py``) counts too.
    """
    pats = DEFAULT_FIXTURE_PATHS if patterns is None else patterns
    path = PurePosixPath(str(relpath))
    parts = path.parts[:-1]
    name = path.name.lower()
    for pattern in pats:
        pat = pattern.strip().strip("/")
        if not pat:
            continue
        if "/" in pat:
            if fnmatch.fnmatchcase(str(path).lower(), pat.lower()) or fnmatch.fnmatchcase(
                str(path).lower(), f"*/{pat.lower()}"
            ):
                return True
            continue
        if any(_matches_component(part, pat) for part in parts):
            return True
    return any(hint in name for hint in _TEST_NAME_HINTS)


def split_primary(
    files: list[str], patterns: list[str] | None = None
) -> tuple[list[str], list[str]]:
    """Split ``files`` into ``(primary, fixture)``.

    When *every* file looks like fixture material the split is abandoned and all files
    are treated as primary: that means the scan root is itself a test or example tree,
    and profiling it as "no project at all" would be worse than profiling it honestly.
    """
    primary: list[str] = []
    fixture: list[str] = []
    for rel in files:
        (fixture if is_fixture_path(rel, patterns) else primary).append(rel)
    if not primary:
        return list(files), []
    return primary, fixture
