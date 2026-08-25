"""The local web UI — endpoints, the SSE bridge, and the front end's self-containment.

Every test drives the real FastAPI app through ``TestClient``; nothing is mocked out
of the engine, so a scan here is the same scan the CLI runs. The three properties the
UI's safety story rests on each have a test that fails loudly if it is weakened:
paths outside the configured roots are refused, a second scan is rejected rather than
queued, and ``/api/fix`` will not move without ``confirm: true``.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from html.parser import HTMLParser
from pathlib import Path

import pytest

from vibeguard.core.models import ScanReport

pytest.importorskip("fastapi", reason="the web UI needs the [ui] extra")

from fastapi.testclient import TestClient  # noqa: E402

from vibeguard.ui.server import create_app  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures"
INDEX = Path(__file__).resolve().parents[1] / "src" / "vibeguard" / "ui" / "index.html"


# --------------------------------------------------------------------------- fixtures


@pytest.fixture
def sandbox(tmp_path: Path) -> Path:
    """A copy of the sample Flask app inside a tmp root the server is allowed to see."""
    target = tmp_path / "workspace" / "sample_flask_app"
    shutil.copytree(FIXTURES / "sample_flask_app", target)
    (tmp_path / "workspace" / "notes").mkdir()
    return target


@pytest.fixture
def client(tmp_path: Path, sandbox: Path):
    app = create_app(roots=[tmp_path], initial_path=sandbox)
    with TestClient(app) as test_client:
        yield test_client


def drain(client: TestClient, scan_id: str, limit: int = 4000) -> list[dict]:
    """Read the whole SSE stream for ``scan_id`` into a list of decoded frames."""
    frames: list[dict] = []
    with client.stream("GET", f"/api/scan/{scan_id}/events") as response:
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/event-stream")
        event = None
        for line in response.iter_lines():
            if line.startswith("event: "):
                event = line[len("event: ") :].strip()
            elif line.startswith("data: "):
                frames.append({"event": event, "data": json.loads(line[len("data: ") :])})
                if event == "end" or len(frames) > limit:
                    break
    return frames


def terminal(frames: list[dict], name: str) -> dict:
    for frame in frames:
        if frame["event"] == name:
            return frame["data"]
    raise AssertionError(f"no {name!r} frame in {[f['event'] for f in frames]}")


# ------------------------------------------------------------------------------- meta


def test_meta_reports_version_and_roots(client: TestClient, tmp_path: Path, sandbox: Path):
    body = client.get("/api/meta").json()
    assert body["version"]
    assert body["host"] == "127.0.0.1"
    assert body["initial_path"] == str(sandbox)
    assert body["roots"] == [str(tmp_path.resolve())]
    assert body["mascot"] == "/assets/mascot.png"


def test_index_and_mascot_are_served(client: TestClient):
    page = client.get("/")
    assert page.status_code == 200
    assert "VibeGuard" in page.text
    mascot = client.get("/assets/mascot.png")
    assert mascot.status_code == 200
    assert mascot.headers["content-type"] == "image/png"


# ----------------------------------------------------------------------------- browse


def test_browse_lists_directories_with_hints(client: TestClient, sandbox: Path):
    body = client.get("/api/browse", params={"path": str(sandbox.parent)}).json()
    names = [entry["name"] for entry in body["entries"]]
    assert "sample_flask_app" in names
    assert "notes" in names
    hinted = next(e for e in body["entries"] if e["name"] == "sample_flask_app")
    assert "requirements.txt" in hinted["hints"]
    assert "Dockerfile" in hinted["hints"]
    # Every row carries the path the picker will browse into next; without it a click
    # falls back to the server's default directory and silently scans the wrong thing.
    assert hinted["path"] == str(sandbox)
    assert all(client.get("/api/browse", params={"path": e["path"]}).status_code == 200
               for e in body["entries"])
    assert [crumb["path"] for crumb in body["crumbs"]][-1] == str(sandbox.parent)


def test_browse_hides_dot_directories_and_noise(client: TestClient, tmp_path: Path):
    (tmp_path / "node_modules").mkdir()
    (tmp_path / ".secrets").mkdir()
    (tmp_path / "src").mkdir()
    body = client.get("/api/browse", params={"path": str(tmp_path)}).json()
    names = [entry["name"] for entry in body["entries"]]
    assert "src" in names
    assert "node_modules" not in names
    assert ".secrets" not in names


@pytest.mark.parametrize("escape", ["..", "../..", "../../etc"])
def test_browse_refuses_relative_escapes(client: TestClient, tmp_path: Path, escape: str):
    response = client.get("/api/browse", params={"path": str(tmp_path / escape)})
    assert response.status_code == 403
    assert "outside" in response.json()["detail"]


def test_browse_refuses_absolute_paths_outside_the_roots(client: TestClient):
    assert client.get("/api/browse", params={"path": "/etc"}).status_code == 403
    assert client.get("/api/browse", params={"path": "/"}).status_code == 403


def test_browse_refuses_a_symlink_that_points_out(client: TestClient, tmp_path: Path):
    link = tmp_path / "escape"
    link.symlink_to("/etc")
    # Resolution happens before the root check, so the link cannot smuggle a path out.
    assert client.get("/api/browse", params={"path": str(link)}).status_code == 403


def test_browse_rejects_a_file(client: TestClient, sandbox: Path):
    response = client.get("/api/browse", params={"path": str(sandbox / "app.py")})
    assert response.status_code == 400


# ------------------------------------------------------------------------------- scan


def test_scan_streams_events_and_ends_with_a_valid_report(client: TestClient, sandbox: Path):
    started = client.post("/api/scan", json={"path": str(sandbox), "mode": "audit"})
    assert started.status_code == 202
    scan_id = started.json()["scan_id"]

    frames = drain(client, scan_id)
    names = [frame["event"] for frame in frames]
    assert "scan.started" in names
    assert "scan.stage" in names
    assert "scan.completed" in names
    assert names[-1] == "end"

    report_json = terminal(frames, "result")["report"]
    report = ScanReport.model_validate(report_json)
    assert report.repo == str(sandbox)
    assert report.mode == "audit"
    assert report.checklist
    # The projection the browser needs, alongside the canonical report.
    assert set(report_json["diagrams"]) == {"scores", "architecture", "checklist"}
    assert report_json["diagrams"]["scores"].startswith("<svg")
    assert isinstance(report_json["safe_autofix_candidates"], int)

    # A scan writes what the CLI writes, so the next run has something to diff against.
    assert (sandbox / "vibeguard-report.json").is_file()
    assert (sandbox / "vibeguard-report.md").is_file()
    assert list((sandbox / ".vibeguard" / "history").glob("*.json"))


def test_scan_with_no_write_leaves_nothing_behind(client: TestClient, sandbox: Path):
    started = client.post(
        "/api/scan",
        json={"path": str(sandbox), "mode": "audit", "options": {"no_write": True}},
    )
    frames = drain(client, started.json()["scan_id"])
    assert terminal(frames, "result")["report"]["history_ts"] is None
    assert not (sandbox / "vibeguard-report.json").exists()
    assert not (sandbox / ".vibeguard").exists()


def test_scan_refuses_a_path_outside_the_roots(client: TestClient):
    assert client.post("/api/scan", json={"path": "/etc"}).status_code == 403


def test_scan_refuses_a_second_run_while_one_is_in_flight(client: TestClient, sandbox: Path):
    # Hold the very lock the server takes, rather than racing a real scan.
    lock = client.app.state.vibeguard.busy
    assert lock.acquire(blocking=False)
    try:
        response = client.post("/api/scan", json={"path": str(sandbox)})
        assert response.status_code == 409
        assert "already running" in response.json()["detail"]
    finally:
        lock.release()


def test_scan_status_is_addressable_after_the_stream_closes(client: TestClient, sandbox: Path):
    scan_id = client.post("/api/scan", json={"path": str(sandbox)}).json()["scan_id"]
    drain(client, scan_id)
    status = client.get(f"/api/scan/{scan_id}").json()
    assert status["state"] == "done"
    assert status["report"]["repo"] == str(sandbox)
    assert client.get("/api/scan/nope").status_code == 404


@pytest.mark.parametrize("fmt", ["md", "html", "json"])
def test_scan_download_renders_each_format(client: TestClient, sandbox: Path, fmt: str):
    scan_id = client.post("/api/scan", json={"path": str(sandbox)}).json()["scan_id"]
    drain(client, scan_id)
    response = client.get(f"/api/scan/{scan_id}/download", params={"fmt": fmt})
    assert response.status_code == 200
    assert "attachment" in response.headers["content-disposition"]
    assert response.text.strip()


def test_scan_error_is_reported_on_the_stream(client: TestClient, tmp_path: Path, monkeypatch):
    from vibeguard.engine.orchestrator import Engine

    def boom(self, path, **kwargs):
        raise RuntimeError("detection exploded")

    monkeypatch.setattr(Engine, "audit", boom)
    scan_id = client.post("/api/scan", json={"path": str(tmp_path)}).json()["scan_id"]
    frames = drain(client, scan_id)
    failure = terminal(frames, "error")
    assert failure["code"] == "engine_error"
    assert "detection exploded" in failure["error"]
    # The lock must come back, or the server is bricked by one bad scan.
    assert client.app.state.vibeguard.busy.acquire(blocking=False)
    client.app.state.vibeguard.busy.release()


# -------------------------------------------------------------------------------- fix


def test_fix_requires_an_explicit_confirmation(client: TestClient, sandbox: Path):
    response = client.post("/api/fix", json={"path": str(sandbox)})
    assert response.status_code == 400
    assert "confirm" in response.json()["detail"]

    response = client.post("/api/fix", json={"path": str(sandbox), "confirm": False})
    assert response.status_code == 400


def test_fix_refuses_a_dirty_worktree(client: TestClient, sandbox: Path):
    def git(*args: str) -> None:
        subprocess.run(["git", *args], cwd=sandbox, check=True, capture_output=True)

    git("init")
    git("config", "user.email", "test@example.invalid")
    git("config", "user.name", "test")
    git("add", ".")
    git("commit", "-m", "initial")
    (sandbox / "app.py").write_text("# edited\n", encoding="utf-8")

    response = client.post("/api/fix", json={"path": str(sandbox), "confirm": True})
    assert response.status_code == 412
    detail = response.json()["detail"]
    assert detail["code"] == "dirty_worktree"
    assert "app.py" in detail["message"]


def test_fix_refuses_a_directory_that_is_not_a_repository(client: TestClient, sandbox: Path):
    response = client.post("/api/fix", json={"path": str(sandbox), "confirm": True})
    assert response.status_code == 412
    assert response.json()["detail"]["code"] == "no_git_repo"


def test_fix_refuses_a_path_outside_the_roots(client: TestClient):
    assert client.post("/api/fix", json={"path": "/etc", "confirm": True}).status_code == 403


# ------------------------------------------------------------------- history & reports


def test_history_lists_stored_scans_and_serves_them_back(client: TestClient, sandbox: Path):
    empty = client.get("/api/history", params={"path": str(sandbox)}).json()
    assert empty["entries"] == []

    scan_id = client.post("/api/scan", json={"path": str(sandbox)}).json()["scan_id"]
    frames = drain(client, scan_id)
    ts = terminal(frames, "result")["report"]["history_ts"]
    assert ts

    listing = client.get("/api/history", params={"path": str(sandbox)}).json()
    assert len(listing["entries"]) == 1
    entry = listing["entries"][0]
    assert entry["ts"] == ts
    assert entry["mode"] == "audit"
    assert isinstance(entry["overall"], int)

    stored = client.get(f"/api/report/{ts}", params={"path": str(sandbox)}).json()
    assert ScanReport.model_validate(stored).repo == str(sandbox)
    assert stored["history_ts"] == ts
    assert stored["diagrams"]["checklist"].startswith("<svg")


@pytest.mark.parametrize(
    ("fmt", "needle"),
    [("md", "# VibeGuard report"), ("html", "<!doctype html>"), ("json", '"schema_version"')],
)
def test_stored_report_downloads_render(client: TestClient, sandbox: Path, fmt: str, needle: str):
    scan_id = client.post("/api/scan", json={"path": str(sandbox)}).json()["scan_id"]
    ts = terminal(drain(client, scan_id), "result")["report"]["history_ts"]
    response = client.get(
        f"/api/report/{ts}/download", params={"path": str(sandbox), "fmt": fmt}
    )
    assert response.status_code == 200
    assert needle in response.text
    assert "vibeguard-report." + fmt in response.headers["content-disposition"]


def test_unknown_stored_report_is_a_404(client: TestClient, sandbox: Path):
    response = client.get("/api/report/nope", params={"path": str(sandbox)})
    assert response.status_code == 404


def test_stored_report_cannot_be_addressed_by_traversal(client: TestClient, sandbox: Path):
    # The id is matched against the filenames that exist, never joined onto a path.
    response = client.get("/api/report/..%2F..%2Fetc%2Fpasswd", params={"path": str(sandbox)})
    assert response.status_code == 404


# ---------------------------------------------------------------------------- frontend


def test_index_html_is_a_single_well_formed_document():
    text = INDEX.read_text(encoding="utf-8")

    class Checker(HTMLParser):
        def __init__(self) -> None:
            super().__init__()
            self.stack: list[str] = []
            self.void = {"meta", "link", "img", "br", "hr", "input", "source"}

        def handle_starttag(self, tag: str, attrs: list) -> None:
            if tag not in self.void:
                self.stack.append(tag)

        def handle_endtag(self, tag: str) -> None:
            if tag in self.void:
                return
            assert self.stack, f"</{tag}> with nothing open"
            assert self.stack.pop() == tag, f"</{tag}> does not close the open element"

    checker = Checker()
    checker.feed(text)
    assert checker.stack == [], f"unclosed elements: {checker.stack}"
    assert text.lstrip().startswith("<!doctype html>")
    assert "<title>VibeGuard</title>" in text


def test_index_html_has_no_external_references():
    """Same bar as the HTML report: it must work with no network at all."""
    text = INDEX.read_text(encoding="utf-8")
    for forbidden in ('src="http', "src='http", 'href="http', "href='http",
                      "url(http", "@import", "//cdn.", "//fonts.", "integrity="):
        assert forbidden not in text, f"index.html reaches outside for {forbidden!r}"
    # The only absolute URL in the file is the SVG namespace, which is an identifier
    # rather than something the browser fetches.
    for url in {chunk.split('"')[0] for chunk in text.split("http") if chunk.startswith("://")}:
        assert url == "://www.w3.org/2000/svg", f"unexpected absolute URL http{url}"


def test_ui_command_is_registered_and_documents_the_loopback_bind():
    from typer.testing import CliRunner

    from vibeguard.cli import app

    result = CliRunner().invoke(app, ["ui", "--help"])
    assert result.exit_code == 0
    assert "--no-browser" in result.stdout
    assert "--port" in result.stdout


def test_ui_command_exits_2_with_an_install_hint_when_the_extra_is_missing(monkeypatch):
    from typer.testing import CliRunner

    import vibeguard.ui
    from vibeguard.cli import app

    monkeypatch.setattr(vibeguard.ui, "missing_dependency", lambda: "fastapi")
    result = CliRunner().invoke(app, ["ui", "."])
    assert result.exit_code == 2
    assert 'pip install "vibeguard[ui]"' in result.output


def test_serve_is_not_given_a_way_to_bind_a_routable_address():
    """D61: the loopback bind is a constant, not something a caller can widen."""
    import inspect

    from vibeguard.ui import server

    assert server.HOST == "127.0.0.1"
    assert "host" not in inspect.signature(server.serve).parameters
    assert "--host" not in Path(server.__file__).read_text(encoding="utf-8")


def test_index_html_never_assigns_report_data_as_markup():
    """Findings carry code from the scanned repo; only our own SVG may be markup."""
    text = INDEX.read_text(encoding="utf-8")
    assignments = [line.strip() for line in text.splitlines() if ".innerHTML" in line]
    assert assignments == ["frame.innerHTML = svg;"], assignments
    assert "outerHTML" not in text
    assert "insertAdjacentHTML" not in text
    assert "document.write" not in text
