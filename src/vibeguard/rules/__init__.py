"""Built-in rule packs.

Each pack module exposes ``RULES: list[type[Rule]]``; the registry
(:mod:`vibeguard.core.registry`) discovers them by name.
"""

PACKS = (
    "core",
    "secrets",
    "security",
    "database",
    "web",
    "devops",
    "python",
    "node",
)

__all__ = ["PACKS"]
