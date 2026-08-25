"""Built-in rule packs.

Each pack module exposes ``RULES: list[type[Rule]]``; the registry
(:mod:`vibeguard.core.registry`) discovers them by name.
"""

PACKS = (
    "core",
    "secrets",
    "security",
    "api",
    "database",
    "reliability",
    "observability",
    "containers",
    "deployment",
    "dependencies",
    "disaster_recovery",
    "testing",
    "performance",
    "scaling",
    "cost",
    "network",
    "web",
    "devops",
    "python",
    "node",
)

__all__ = ["PACKS"]
