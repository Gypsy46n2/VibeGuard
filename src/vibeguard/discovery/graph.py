"""Architecture graph inference (M1: app + datastores + external services)."""

from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path, PurePosixPath

from vibeguard.core.models import ArchEdge, ArchitectureGraph, ArchNode, TechProfile

__all__ = ["build_graph"]

Reader = Callable[[str], str]

_URL_RE = re.compile(r"https?://([A-Za-z0-9\.\-]+)")
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "host.docker.internal"}
_CONFIG_NAMES = {
    "settings.py",
    "config.py",
    "config.json",
    "config.yaml",
    "config.yml",
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
}
_MAX_EXTERNAL_SERVICES = 20


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


def build_graph(root: Path, files: list[str], read: Reader, tech: TechProfile) -> ArchitectureGraph:
    """Build a coarse node/edge view: the app, its datastores, and external calls."""
    app_label = root.name or "app"
    app = ArchNode(
        id="app",
        kind="service",
        label=app_label,
        meta={
            "languages": sorted(tech.languages),
            "frameworks": list(tech.frameworks),
        },
    )
    nodes: list[ArchNode] = [app]
    edges: list[ArchEdge] = []
    seen: set[str] = {"app"}

    def add(node: ArchNode, edge_kind: str) -> None:
        if node.id in seen:
            return
        seen.add(node.id)
        nodes.append(node)
        edges.append(ArchEdge(src="app", dst=node.id, kind=edge_kind))

    for db in tech.databases:
        add(ArchNode(id=f"db:{_slug(db)}", kind="database", label=db), "reads_writes")
    for cache in tech.caches:
        add(ArchNode(id=f"cache:{_slug(cache)}", kind="cache", label=cache), "caches")
    for broker in tech.brokers:
        add(ArchNode(id=f"broker:{_slug(broker)}", kind="broker", label=broker), "publishes")
    for worker in tech.workers:
        add(ArchNode(id=f"worker:{_slug(worker)}", kind="worker", label=worker), "dispatches")

    hosts: list[str] = []
    for rel in files:
        name = PurePosixPath(rel).name.lower()
        if name not in _CONFIG_NAMES and not name.startswith(".env"):
            continue
        for host in _URL_RE.findall(read(rel)):
            host = host.lower()
            if host in _LOCAL_HOSTS or host.endswith(".local") or host in hosts:
                continue
            hosts.append(host)
    for host in (tech.external_services + hosts)[:_MAX_EXTERNAL_SERVICES]:
        add(ArchNode(id=f"ext:{_slug(host)}", kind="external", label=host), "calls")

    return ArchitectureGraph(nodes=nodes, edges=edges)
