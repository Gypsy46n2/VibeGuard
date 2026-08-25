"""Repository discovery: file walking, tech profile, scale, architecture graph."""

from vibeguard.discovery.context import ScanContext
from vibeguard.discovery.files import collect_files
from vibeguard.discovery.graph import build_graph
from vibeguard.discovery.scale import detect_scale
from vibeguard.discovery.tech import detect_tech

__all__ = ["ScanContext", "collect_files", "build_graph", "detect_scale", "detect_tech"]
