"""Diagram rendering — mermaid safety, SVG well-formedness, and health colouring."""

from __future__ import annotations

import shutil
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
from typer.testing import CliRunner

from conftest import make_finding, make_report
from vibeguard.cli import app
from vibeguard.core.models import (
    ArchEdge,
    ArchitectureGraph,
    ArchNode,
    Category,
    CategoryScore,
    ChecklistItem,
    ChecklistStatus,
    ScanReport,
)
from vibeguard.reporting.diagram import (
    MAX_NODES,
    graph_is_trivial,
    health_class,
    mermaid_architecture,
    node_health,
    svg_architecture,
    svg_checklist,
    svg_scores,
)
from vibeguard.reporting.html import render_html
from vibeguard.reporting.markdown import render_markdown

runner = CliRunner()

HOSTILE_LABEL = 'evil "label" [x]-->'


def graph_report(**overrides) -> ScanReport:
    """A report whose graph has one node per column plus a couple of edges."""
    graph = ArchitectureGraph(
        nodes=[
            ArchNode(id="edge", kind="entrypoint", label="public ingress"),
            ArchNode(id="app", kind="service", label="checkout"),
            ArchNode(id="db", kind="database", label="postgres"),
            ArchNode(id="cache", kind="cache", label="redis"),
            ArchNode(id="bus", kind="broker", label="rabbitmq"),
            ArchNode(id="ext", kind="external", label="api.stripe.test"),
        ],
        edges=[
            ArchEdge(src="edge", dst="app", kind="serves"),
            ArchEdge(src="app", dst="db", kind="reads_writes"),
            ArchEdge(src="app", dst="cache", kind="caches"),
            ArchEdge(src="app", dst="bus", kind="publishes"),
            ArchEdge(src="app", dst="ext", kind="calls"),
        ],
    )
    overrides.setdefault("graph", graph)
    return make_report(make_finding(), **overrides)


def scored(**by_category: int) -> list[CategoryScore]:
    return [
        CategoryScore(category=category, score=score, applicable=True, finding_count=0)
        for category, score in ((Category(name), value) for name, value in by_category.items())
    ]


# --------------------------------------------------------------------- mermaid


def test_mermaid_opens_a_left_to_right_flowchart():
    assert mermaid_architecture(graph_report()).splitlines()[0] == "flowchart LR"


def test_every_node_and_edge_reaches_the_mermaid_block():
    report = graph_report()
    text = mermaid_architecture(report)
    for node in report.graph.nodes:
        assert node.label in text
    for edge in report.graph.edges:
        assert f"|{edge.kind}|" in text


def test_a_hostile_node_label_cannot_break_out_of_mermaid_syntax():
    report = graph_report(
        graph=ArchitectureGraph(
            nodes=[ArchNode(id="a", kind="service", label=HOSTILE_LABEL)], edges=[]
        )
    )
    text = mermaid_architecture(report)
    label_line = next(line for line in text.splitlines() if "evil" in line)
    body = label_line.strip().removeprefix('n0["').removesuffix('"]')
    for forbidden in ('"', "[", "]", "(", ")", "{", "}", "<", ">", "|", "\\", "`"):
        assert forbidden not in body, forbidden
    assert "#quot;" in body and "#91;" in body


def test_mermaid_escapes_hostile_edge_labels_too():
    report = graph_report(
        graph=ArchitectureGraph(
            nodes=[ArchNode(id="a", kind="service", label="a"),
                   ArchNode(id="b", kind="database", label="b")],
            edges=[ArchEdge(src="a", dst="b", kind="pipe|injection")],
        )
    )
    line = next(line for line in mermaid_architecture(report).splitlines() if "-->" in line)
    assert line.count("|") == 2  # the two mermaid delimiters, and nothing else


def test_mermaid_groups_nodes_into_kind_subgraphs():
    text = mermaid_architecture(graph_report())
    for title in ("entrypoints", "app / services", "external"):
        assert f'"{title}"' in text
    assert '"data #38; infrastructure"' in text  # `&` escaped, never raw


def test_mermaid_uses_a_distinct_shape_per_kind():
    text = mermaid_architecture(graph_report())
    assert 'n2[("postgres")]' in text
    assert 'n4{{"rabbitmq"}}' in text
    assert 'n5(["api.stripe.test"])' in text
    assert 'n0(("public ingress"))' in text


def test_mermaid_declares_every_health_class():
    text = mermaid_architecture(graph_report())
    for band in ("ok", "warn", "bad", "unknown"):
        assert f"classDef {band} " in text


# ---------------------------------------------------------------------- health


@pytest.mark.parametrize(
    ("score", "band"),
    [
        (100, "ok"),
        (85, "ok"),
        (84, "warn"),
        (60, "warn"),
        (59, "bad"),
        (0, "bad"),
        (None, "unknown"),
    ],
)
def test_health_bands_are_drawn_at_85_and_60(score: int | None, band: str):
    assert health_class(score) == band


def test_each_node_kind_takes_its_own_category_score():
    report = graph_report(
        scores_before=scored(database=20, performance=70, reliability=95, api=50),
        overall_before=90,
    )
    bands = {node.id: node_health(report, node)[0] for node in report.graph.nodes}
    assert bands == {
        "db": "bad",       # database 20
        "cache": "warn",   # performance 70
        "bus": "ok",       # reliability 95
        "ext": "bad",      # api 50
        "edge": "bad",     # entrypoints follow api too
        "app": "ok",       # service falls back to the overall 90
    }


def test_a_fix_run_is_coloured_by_the_repaired_scores():
    report = graph_report(
        scores_before=scored(database=10),
        scores_after=scored(database=95),
        overall_before=10,
        overall_after=95,
    )
    db = next(node for node in report.graph.nodes if node.id == "db")
    assert node_health(report, db) == ("ok", 95)


def test_a_category_with_no_applicable_rules_is_neutral_not_green():
    report = graph_report(
        scores_before=[
            CategoryScore(category=Category.DATABASE, score=100, applicable=False,
                          finding_count=0)
        ],
        overall_before=100,
    )
    db = next(node for node in report.graph.nodes if node.id == "db")
    assert node_health(report, db) == ("unknown", None)


def test_a_report_with_no_scores_at_all_is_neutral():
    report = graph_report(scores_before=[], overall_before=100)
    assert {node_health(report, node)[0] for node in report.graph.nodes} == {"unknown"}


# ------------------------------------------------------------------------ SVG


def parsed(svg: str) -> ET.Element:
    return ET.fromstring(svg)


@pytest.mark.parametrize("render", [svg_architecture, svg_scores, svg_checklist])
def test_every_svg_is_well_formed_xml(render):
    root = parsed(render(graph_report(scores_before=scored(database=40), overall_before=40)))
    assert root.tag == "{http://www.w3.org/2000/svg}svg"
    assert root.get("viewBox")


@pytest.mark.parametrize("render", [svg_architecture, svg_scores, svg_checklist])
def test_no_svg_references_anything_off_the_page(render):
    svg = render(graph_report())
    for forbidden in ("<script", "<image", "xlink:href", "@import", "http://www.w3.org/1999/xlink"):
        assert forbidden not in svg, forbidden
    assert svg.count("http") == svg.count("http://www.w3.org/2000/svg")


def test_a_hostile_label_is_escaped_in_the_svg():
    report = graph_report(
        graph=ArchitectureGraph(
            nodes=[ArchNode(id="a", kind="service", label=HOSTILE_LABEL),
                   ArchNode(id="b", kind="database", label="db")],
            edges=[ArchEdge(src="a", dst="b", kind="reads")],
        )
    )
    svg = svg_architecture(report)
    parsed(svg)  # would raise on a broken tag
    assert "[x]-->" not in svg


def test_the_architecture_svg_draws_a_box_and_a_label_for_every_node():
    report = graph_report()
    root = parsed(svg_architecture(report))
    texts = [element.text for element in root.iter("{http://www.w3.org/2000/svg}text")]
    for node in report.graph.nodes:
        assert node.label in texts


def test_the_architecture_svg_caps_at_thirty_nodes_and_says_how_many_it_dropped():
    graph = ArchitectureGraph(
        nodes=[ArchNode(id=f"n{i}", kind="external", label=f"svc{i}") for i in range(42)],
        edges=[],
    )
    report = graph_report(graph=graph)
    root = parsed(svg_architecture(report))
    texts = [element.text or "" for element in root.iter("{http://www.w3.org/2000/svg}text")]
    assert any("and 12 more" in text for text in texts)
    assert "svc41" not in texts
    assert f"svc{MAX_NODES - 1}" in texts


def test_the_mermaid_diagram_caps_at_thirty_nodes_too():
    graph = ArchitectureGraph(
        nodes=[ArchNode(id=f"n{i}", kind="external", label=f"svc{i}") for i in range(42)],
        edges=[ArchEdge(src="n0", dst="n41", kind="calls")],
    )
    text = mermaid_architecture(graph_report(graph=graph))
    assert "and 12 more" in text
    assert "svc41" not in text
    # An edge to a dropped node would name an id the diagram never declared.
    assert "n41" not in text


def test_the_score_chart_bands_each_bar_by_health():
    report = graph_report(scores_before=scored(database=95, api=70, security=10))
    svg = svg_scores(report)
    for colour in ("#1a7f4b", "#b8860b", "#b21b1b"):
        assert colour in svg


def test_the_score_chart_marks_the_after_score_on_a_fix_run():
    plain = svg_scores(graph_report(scores_before=scored(database=40), overall_before=40))
    fixed = svg_scores(
        graph_report(
            scores_before=scored(database=40),
            scores_after=scored(database=90),
            overall_before=40,
            overall_after=90,
        )
    )
    assert "after repairs" not in plain
    assert "after repairs" in fixed
    assert "→ 90" in fixed


def test_the_score_chart_says_so_when_a_category_has_no_rules():
    report = graph_report(
        scores_before=[
            CategoryScore(category=Category.COST, score=100, applicable=False, finding_count=0)
        ]
    )
    assert "no applicable rules" in svg_scores(report)


def test_the_checklist_chart_has_one_bar_per_section_plus_a_total():
    items = [
        ChecklistItem(topic_id="security.a", section="security", name="a",
                      category=Category.SECURITY, status=ChecklistStatus.PASS, detectors=[]),
        ChecklistItem(topic_id="security.b", section="security", name="b",
                      category=Category.SECURITY, status=ChecklistStatus.FAIL, detectors=[]),
        ChecklistItem(topic_id="db.a", section="database", name="c",
                      category=Category.DATABASE, status=ChecklistStatus.NOT_APPLICABLE,
                      detectors=[]),
    ]
    svg = svg_checklist(graph_report(checklist=items))
    parsed(svg)
    for expected in ("security", "database", "all sections", "3 topics across 2 sections"):
        assert expected in svg


def test_empty_score_and_checklist_charts_still_render():
    report = graph_report(scores_before=[], checklist=[])
    assert "no category scores" in svg_scores(report)
    assert "no checklist" in svg_checklist(report)
    parsed(svg_scores(report))
    parsed(svg_checklist(report))


# -------------------------------------------------------------- trivial graph


def test_a_single_node_graph_is_trivial():
    assert graph_is_trivial(ArchitectureGraph())
    assert graph_is_trivial(
        ArchitectureGraph(nodes=[ArchNode(id="a", kind="service", label="a")], edges=[])
    )
    assert not graph_is_trivial(graph_report().graph)


def test_both_renderers_replace_a_trivial_graph_with_a_note():
    report = make_report(
        make_finding(),
        graph=ArchitectureGraph(nodes=[ArchNode(id="a", kind="service", label="solo")]),
    )
    markdown = render_markdown(report)
    html = render_html(report)
    assert "```mermaid" not in markdown
    assert "single-node architecture" in markdown
    assert "single-node architecture" in html
    assert "<svg" in html  # the score and checklist charts are still drawn


# --------------------------------------------------------- renderer wiring


def test_the_markdown_report_carries_an_architecture_section_with_a_mermaid_fence():
    text = render_markdown(graph_report())
    assert "## Architecture" in text
    assert "```mermaid" in text
    assert "flowchart LR" in text
    assert "6 node(s) and 5 edge(s)" in text
    # Near the top: before the executive summary, so it is the first thing seen.
    assert text.index("## Architecture") < text.index("## Executive summary")


def test_the_markdown_mermaid_fence_is_closed():
    text = render_markdown(graph_report())
    assert text.count("```mermaid") == 1
    fence = text.split("```mermaid", 1)[1]
    assert fence.lstrip().startswith("flowchart LR")
    assert "```" in fence


def test_the_html_report_opens_with_the_glance_section():
    text = render_html(graph_report())
    assert "Architecture &amp; health at a glance" in text
    assert text.count("<svg") == 3
    assert text.index("at a glance") < text.index("Executive summary")


def test_the_html_report_is_still_self_contained_with_diagrams():
    text = render_html(graph_report())
    assert "<script src=" not in text
    assert "<link " not in text
    assert "<img" not in text
    assert "@import" not in text
    assert 'href="https://' not in text
    assert "xlink" not in text


def test_the_html_diagrams_need_no_javascript():
    text = render_html(graph_report())
    glance = text.split("Architecture &amp; health at a glance", 1)[1].split("<h2>", 1)[0]
    assert "<script" not in glance
    assert "onclick" not in glance


# --------------------------------------------------------------------- the CLI


def test_graph_command_prints_mermaid(sample_app: Path, tmp_path: Path):
    repo = tmp_path / "repo"
    shutil.copytree(sample_app, repo)
    result = runner.invoke(app, ["graph", str(repo)])
    assert result.exit_code == 0, result.output
    assert "flowchart LR" in result.stdout


def test_graph_command_writes_svg_to_a_file(sample_app: Path, tmp_path: Path):
    repo = tmp_path / "repo"
    shutil.copytree(sample_app, repo)
    destination = tmp_path / "arch.svg"
    result = runner.invoke(
        app, ["graph", str(repo), "--format", "svg", "--out", str(destination)]
    )
    assert result.exit_code == 0, result.output
    assert destination.is_file()
    parsed(destination.read_text(encoding="utf-8"))


def test_graph_command_refuses_a_missing_directory(tmp_path: Path):
    result = runner.invoke(app, ["graph", str(tmp_path / "nope")])
    assert result.exit_code == 2


def test_graph_is_listed_in_the_help():
    assert "graph" in runner.invoke(app, ["--help"]).stdout
