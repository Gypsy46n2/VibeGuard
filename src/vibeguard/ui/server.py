"""The local web UI's HTTP layer — ARCHITECTURE.md §10.4 made concrete.

§10 says the JSON report plus the event stream are the contract for any dashboard, and
this server is nothing more than an HTTP adaptation of exactly those two things: every
endpoint either returns a :class:`~vibeguard.core.models.ScanReport` (or a projection
of one) or bridges :class:`~vibeguard.core.events.EventBus` onto Server-Sent Events.
The :class:`~vibeguard.engine.orchestrator.Engine` is used directly as a library —
the server never shells out to the CLI, so there is one pipeline and one report shape,
not two that can drift.

Three properties are load-bearing and are asserted by the tests:

**Loopback only.**
    The server binds ``127.0.0.1`` and nothing else (DECISIONS.md D61). It has no
    authentication because it is not reachable from another machine; give it a
    routable interface and that reasoning collapses, so the bind address is not a
    parameter a caller can widen.

**Rooted browsing.**
    ``/api/browse`` — and every endpoint that takes a ``path`` — resolves the request
    against a fixed list of roots (the user's home, plus whatever directory
    ``vibeguard ui PATH`` was pointed at) and refuses anything outside. Resolution
    happens *before* the check, so ``..`` segments and symlinks cannot walk out.

**Safe-mode repairs only.**
    ``/api/fix`` runs ``Engine.fix(root, "safe")`` and requires an explicit
    ``confirm: true`` in the body (DECISIONS.md D62). Interactive mode asks a human to
    approve individual diffs one at a time; a v1 web UI has nowhere honest to put that
    conversation, so it is not offered rather than being approximated.

One scan runs at a time per server. A second request gets ``409`` rather than a queue:
scans are minutes long and CPU-bound, and two of them interleaving their progress into
one UI would be worse than being told to wait.
"""

from __future__ import annotations

import json
import logging
import threading
from collections import OrderedDict
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from fastapi import Body, FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response, StreamingResponse
from pydantic import BaseModel, Field

from vibeguard import __version__
from vibeguard.baseline import history_files, load_history_report, write_history
from vibeguard.core.config import VibeguardConfig
from vibeguard.core.events import EventBus
from vibeguard.core.models import AutofixSafety, ScanReport
from vibeguard.engine.orchestrator import Engine
from vibeguard.fixers.git_safety import (
    DirtyWorktreeError,
    GitSafety,
    GitSafetyError,
    NoGitRepoError,
)
from vibeguard.reporting import render_html, render_markdown, write_reports
from vibeguard.reporting.diagram import svg_architecture, svg_checklist, svg_scores

__all__ = ["create_app", "serve", "DEFAULT_PORT", "HOST"]

log = logging.getLogger(__name__)

#: The only address this server ever binds. Not a parameter — see the module docstring.
HOST = "127.0.0.1"

DEFAULT_PORT = 8321

#: How many finished jobs stay addressable, so a reload can still fetch its result.
_JOB_HISTORY = 12

#: Filenames that mark a directory as "a project" in the folder picker.
_MANIFESTS: tuple[str, ...] = (
    "pyproject.toml",
    "requirements.txt",
    "setup.py",
    "package.json",
    "Cargo.toml",
    "go.mod",
    "Gemfile",
    "composer.json",
    "pom.xml",
    "build.gradle",
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
)

#: Directory names the picker hides — noise, never a scan target a human wants.
_PICKER_SKIP: frozenset[str] = frozenset(
    {
        ".git",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        "dist",
        "build",
        ".idea",
        ".vscode",
    }
)


# --------------------------------------------------------------------- request bodies


class ScanOptions(BaseModel):
    """The subset of engine options the UI exposes. Deliberately small."""

    local_only: bool = False
    #: Leave nothing behind — no report files, no history entry (CLI ``--no-write``).
    no_write: bool = False


class ScanRequest(BaseModel):
    path: str
    #: Only ``audit`` exists here; repairs go through ``/api/fix`` so that the
    #: confirmation requirement cannot be reached by flipping a mode string.
    mode: Literal["audit"] = "audit"
    options: ScanOptions = Field(default_factory=ScanOptions)


class FixRequest(BaseModel):
    path: str
    #: Must be ``true``. A repair writes to the user's repository, so the intent is
    #: carried in the request body rather than inferred from the route being called.
    confirm: bool = False
    local_only: bool = False


# ------------------------------------------------------------------------------ jobs


class _Job:
    """One running (or finished) engine invocation and the events it produced.

    Events are buffered rather than streamed straight out, so a browser that connects
    late — or reconnects after a reload — replays the whole run instead of joining
    halfway through with no idea what it missed.
    """

    def __init__(self, kind: str, path: Path) -> None:
        self.id = uuid4().hex
        self.kind = kind
        self.path = str(path)
        self.started = datetime.now(UTC)
        self.events: list[dict[str, Any]] = []
        self.report: dict[str, Any] | None = None
        self.error: str | None = None
        self.error_code: str | None = None
        self.finished = False
        self._cv = threading.Condition()

    # -- producer side
    def emit(self, name: str, payload: dict[str, Any]) -> None:
        record = {
            "event": name,
            "ts": datetime.now(UTC).isoformat(),
            "data": _jsonable(payload),
        }
        with self._cv:
            self.events.append(record)
            self._cv.notify_all()

    def finish(
        self,
        *,
        report: dict[str, Any] | None = None,
        error: str | None = None,
        error_code: str | None = None,
    ) -> None:
        with self._cv:
            self.report = report
            self.error = error
            self.error_code = error_code
            self.finished = True
            self._cv.notify_all()

    # -- consumer side
    def stream(self) -> Iterator[str]:
        """Yield SSE frames for every event, then the terminal ``result``/``error``."""
        index = 0
        while True:
            with self._cv:
                # A bounded wait rather than an open-ended one: on timeout the loop
                # drops the lock and emits a comment frame, so neither the producer is
                # blocked by a suspended generator nor the connection is taken for dead
                # while a long discovery pass produces no events.
                if index >= len(self.events) and not self.finished:
                    self._cv.wait(timeout=15.0)
                pending = self.events[index:]
                index += len(pending)
                done = self.finished and index >= len(self.events)
            if not pending and not done:
                yield ": keep-alive\n\n"
                continue
            for record in pending:
                yield _sse(record["event"], record)
            if done:
                break
        if self.error is not None:
            yield _sse("error", {"error": self.error, "code": self.error_code})
        else:
            yield _sse("result", {"report": self.report})
        yield _sse("end", {"id": self.id})

    def status(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "path": self.path,
            "started": self.started.isoformat(),
            "state": "error" if self.error else ("done" if self.finished else "running"),
            "error": self.error,
            "code": self.error_code,
            "events": len(self.events),
        }


def _sse(event: str, data: dict[str, Any]) -> str:
    """One Server-Sent Events frame. ``json.dumps`` guarantees a single-line payload."""
    return f"event: {event}\ndata: {json.dumps(data, default=str)}\n\n"


def _jsonable(payload: dict[str, Any]) -> dict[str, Any]:
    """Round-trip a payload through JSON so a stray object cannot break the stream."""
    try:
        return json.loads(json.dumps(payload, default=str))
    except (TypeError, ValueError):  # pragma: no cover - defensive
        return {"repr": repr(payload)[:500]}


# ------------------------------------------------------------------------------ app


def create_app(*, roots: list[Path] | None = None, initial_path: Path | None = None) -> FastAPI:
    """Build the FastAPI application.

    ``roots`` are the directories the UI may browse and scan; every path in every
    request is resolved and then checked against them. The default is the user's home
    directory alone.
    """
    resolved_roots = _normalise_roots(roots)
    start = (initial_path or Path.cwd()).resolve()
    if not _within(start, resolved_roots):
        start = resolved_roots[0]

    app = FastAPI(
        title="VibeGuard",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    state = _ServerState(resolved_roots, start)
    app.state.vibeguard = state

    _register_routes(app, state)
    return app


class _ServerState:
    """Everything the request handlers share: the roots, the lock, and the jobs."""

    def __init__(self, roots: list[Path], initial_path: Path) -> None:
        self.roots = roots
        self.initial_path = initial_path
        self.busy = threading.Lock()
        self.jobs: OrderedDict[str, _Job] = OrderedDict()
        self._jobs_lock = threading.Lock()

    def remember(self, job: _Job) -> None:
        with self._jobs_lock:
            self.jobs[job.id] = job
            while len(self.jobs) > _JOB_HISTORY:
                self.jobs.popitem(last=False)

    def get(self, job_id: str) -> _Job:
        with self._jobs_lock:
            job = self.jobs.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="no such scan")
        return job

    def resolve(self, raw: str | None) -> Path:
        """Resolve a client-supplied path inside the roots, or refuse it."""
        candidate = Path(raw).expanduser() if raw else self.initial_path
        try:
            resolved = candidate.resolve()
        except OSError as exc:  # pragma: no cover - platform specific
            raise HTTPException(status_code=400, detail=f"unreadable path: {exc}") from exc
        if not _within(resolved, self.roots):
            raise HTTPException(
                status_code=403,
                detail=(
                    f"{resolved} is outside the directories this server may read "
                    f"({', '.join(str(r) for r in self.roots)}). Start the server with "
                    "that directory as its argument to browse it."
                ),
            )
        return resolved


def _normalise_roots(roots: list[Path] | None) -> list[Path]:
    """Resolve, de-duplicate, and drop roots contained in another root."""
    candidates: list[Path] = []
    for raw in roots or [Path.home()]:
        try:
            resolved = Path(raw).expanduser().resolve()
        except OSError:  # pragma: no cover - platform specific
            continue
        if resolved.is_dir():
            candidates.append(resolved)
    if not candidates:  # pragma: no cover - a home that does not exist
        candidates = [Path.cwd().resolve()]
    kept: list[Path] = []
    for candidate in candidates:
        if any(candidate != other and _is_within(candidate, other) for other in candidates):
            continue
        if candidate not in kept:
            kept.append(candidate)
    return kept


def _is_within(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def _within(path: Path, roots: list[Path]) -> bool:
    return any(_is_within(path, root) for root in roots)


# --------------------------------------------------------------------------- routes


def _register_routes(app: FastAPI, state: _ServerState) -> None:
    package = Path(__file__).resolve().parent

    @app.get("/", response_class=HTMLResponse)
    def index() -> HTMLResponse:
        return HTMLResponse((package / "index.html").read_text(encoding="utf-8"))

    @app.get("/assets/mascot.png")
    def mascot() -> FileResponse:
        return FileResponse(package / "assets" / "mascot.png", media_type="image/png")

    # ------------------------------------------------------------------- meta
    @app.get("/api/meta")
    def meta() -> dict[str, Any]:
        return {
            "version": __version__,
            "cwd": str(Path.cwd()),
            "home": str(Path.home()),
            "roots": [str(root) for root in state.roots],
            "initial_path": str(state.initial_path),
            "mascot": "/assets/mascot.png",
            "host": HOST,
        }

    # ----------------------------------------------------------------- browse
    @app.get("/api/browse")
    def browse(path: str | None = Query(default=None)) -> dict[str, Any]:
        target = state.resolve(path)
        if not target.is_dir():
            raise HTTPException(status_code=400, detail=f"not a directory: {target}")
        entries: list[dict[str, Any]] = []
        try:
            children = sorted(target.iterdir(), key=lambda p: p.name.lower())
        except OSError as exc:
            raise HTTPException(status_code=403, detail=f"cannot read {target}: {exc}") from exc
        for child in children:
            if child.name in _PICKER_SKIP or child.name.startswith("."):
                continue
            try:
                if not child.is_dir():
                    continue
            except OSError:  # pragma: no cover - broken symlink
                continue
            entries.append({"path": str(child), **_describe_dir(child)})
        parent = target.parent
        return {
            "path": str(target),
            "parent": str(parent) if _within(parent, state.roots) and parent != target else None,
            "roots": [str(root) for root in state.roots],
            "crumbs": _crumbs(target, state.roots),
            **_describe_dir(target),
            "entries": entries,
        }

    # ------------------------------------------------------------------- scan
    @app.post("/api/scan")
    def scan(request: ScanRequest = Body(...)) -> JSONResponse:
        root = state.resolve(request.path)
        if not root.is_dir():
            raise HTTPException(status_code=400, detail=f"not a directory: {root}")
        job = _Job("audit", root)
        _start(state, job, lambda: _run_audit(root, request.options, job))
        return JSONResponse({"scan_id": job.id, **job.status()}, status_code=202)

    # -------------------------------------------------------------------- fix
    @app.post("/api/fix")
    def fix(request: FixRequest = Body(...)) -> JSONResponse:
        if request.confirm is not True:
            raise HTTPException(
                status_code=400,
                detail=(
                    "a repair writes to your repository — send {\"confirm\": true} to "
                    "say so explicitly."
                ),
            )
        root = state.resolve(request.path)
        if not root.is_dir():
            raise HTTPException(status_code=400, detail=f"not a directory: {root}")

        # Preflight here rather than only inside the job: a dirty worktree is the one
        # refusal a user hits constantly, and answering it with an HTTP status beats
        # opening a progress stream that immediately fails.
        config = _config(root, local_only=request.local_only)
        try:
            GitSafety(root, allow_no_git=config.fix.allow_no_git).preflight()
        except DirtyWorktreeError as exc:
            raise HTTPException(
                status_code=412, detail={"code": "dirty_worktree", "message": str(exc)}
            ) from exc
        except NoGitRepoError as exc:
            raise HTTPException(
                status_code=412, detail={"code": "no_git_repo", "message": str(exc)}
            ) from exc
        except GitSafetyError as exc:
            raise HTTPException(
                status_code=412, detail={"code": "git_error", "message": str(exc)}
            ) from exc

        job = _Job("fix", root)
        _start(state, job, lambda: _run_fix(root, config, job))
        return JSONResponse({"scan_id": job.id, **job.status()}, status_code=202)

    # ----------------------------------------------------------------- events
    @app.get("/api/scan/{scan_id}/events")
    def events(scan_id: str) -> StreamingResponse:
        job = state.get(scan_id)
        return StreamingResponse(
            job.stream(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
        )

    @app.get("/api/scan/{scan_id}")
    def scan_status(scan_id: str) -> dict[str, Any]:
        job = state.get(scan_id)
        return {**job.status(), "report": job.report}

    @app.get("/api/scan/{scan_id}/download")
    def scan_download(
        scan_id: str, fmt: Literal["md", "html", "json"] = Query(default="md")
    ) -> Response:
        job = state.get(scan_id)
        if job.report is None:
            raise HTTPException(status_code=409, detail="that scan has no report yet")
        return _rendered(ScanReport.model_validate(job.report), fmt)

    # ---------------------------------------------------------------- history
    @app.get("/api/history")
    def history(
        path: str | None = Query(default=None), limit: int = Query(default=25, ge=1, le=200)
    ) -> dict[str, Any]:
        root = state.resolve(path)
        config = _config(root)
        stored = history_files(config.state_root(root))
        entries: list[dict[str, Any]] = []
        for entry in reversed(stored[-limit:]):
            report = load_history_report(entry)
            if report is None:
                continue
            entries.append(
                {
                    "ts": entry.stem,
                    "scan_date": report.scan_date.isoformat(),
                    "mode": report.mode,
                    "repo": report.repo,
                    "overall": (
                        report.overall_after
                        if report.overall_after is not None
                        else report.overall_before
                    ),
                    "counts": report.counts,
                    "findings": len(report.findings),
                }
            )
        return {"path": str(root), "entries": entries}

    @app.get("/api/report/{ts}")
    def stored_report(ts: str, path: str | None = Query(default=None)) -> dict[str, Any]:
        root = state.resolve(path)
        report = _load_stored(state, ts, path)
        return _report_payload(report, history_ts=ts, root=root)

    @app.get("/api/report/{ts}/download")
    def download(
        ts: str,
        path: str | None = Query(default=None),
        fmt: Literal["md", "html", "json"] = Query(default="md"),
    ) -> Response:
        return _rendered(_load_stored(state, ts, path), fmt)


def _rendered(report: ScanReport, fmt: str) -> Response:
    """One stored report as a downloadable file, rendered by the shared renderers."""
    if fmt == "md":
        body, media, name = render_markdown(report), "text/markdown", "vibeguard-report.md"
    elif fmt == "html":
        body, media, name = render_html(report), "text/html", "vibeguard-report.html"
    else:
        body = report.model_dump_json(indent=2)
        media, name = "application/json", "vibeguard-report.json"
    return Response(
        content=body,
        media_type=media,
        headers={"Content-Disposition": f'attachment; filename="{name}"'},
    )


def _load_stored(state: _ServerState, ts: str, path: str | None) -> ScanReport:
    """Fetch one stored history entry by its timestamp id.

    The id is matched against the filenames that actually exist rather than joined
    onto a directory, so a crafted ``ts`` cannot name a file outside the history.
    """
    root = state.resolve(path)
    config = _config(root)
    for entry in history_files(config.state_root(root)):
        if entry.stem == ts:
            report = load_history_report(entry)
            if report is None:
                raise HTTPException(status_code=422, detail=f"history entry {ts} is unreadable")
            return report
    raise HTTPException(status_code=404, detail=f"no stored scan {ts} for {root}")


def _describe_dir(directory: Path) -> dict[str, Any]:
    """Name, git marker, and manifest hints — what the picker shows per row."""
    hints: list[str] = []
    is_git = False
    try:
        is_git = (directory / ".git").exists()
        for manifest in _MANIFESTS:
            if (directory / manifest).is_file():
                hints.append(manifest)
    except OSError:  # pragma: no cover - permission denied mid-walk
        pass
    return {"name": directory.name or str(directory), "is_git": is_git, "hints": hints}


def _crumbs(target: Path, roots: list[Path]) -> list[dict[str, str]]:
    """Breadcrumb trail from the containing root down to ``target``."""
    root = next((r for r in roots if _is_within(target, r)), roots[0])
    chain = [target, *target.parents]
    trail = [p for p in reversed(chain) if _is_within(p, root)]
    return [{"name": p.name or str(p), "path": str(p)} for p in trail]


# ------------------------------------------------------------------------- running


def _config(root: Path, *, local_only: bool = False) -> VibeguardConfig:
    return VibeguardConfig.load(root).merge_cli(local_only=local_only or None)


def _start(state: _ServerState, job: _Job, work: Any) -> None:
    """Take the single-scan lock and run ``work`` on a background thread."""
    if not state.busy.acquire(blocking=False):
        raise HTTPException(
            status_code=409,
            detail="a scan is already running — wait for it to finish, or reload the page.",
        )
    state.remember(job)

    def runner() -> None:
        try:
            work()
        except Exception as exc:  # the UI must survive any engine failure
            log.warning("ui job %s failed", job.id, exc_info=True)
            job.finish(error=str(exc) or exc.__class__.__name__, error_code="engine_error")
        finally:
            state.busy.release()

    threading.Thread(target=runner, name=f"vibeguard-ui-{job.id}", daemon=True).start()


def _bus(job: _Job) -> EventBus:
    bus = EventBus()
    bus.subscribe("*", job.emit)
    return bus


def _run_audit(root: Path, options: ScanOptions, job: _Job) -> None:
    config = _config(root, local_only=options.local_only)
    bus = _bus(job)
    engine = Engine(config, events=bus)
    report = engine.audit(root)
    stored = None if options.no_write else _persist(report, root, config, bus, job)
    job.finish(report=_report_payload(report, history_ts=stored, root=root))


def _run_fix(root: Path, config: VibeguardConfig, job: _Job) -> None:
    bus = _bus(job)
    engine = Engine(config, events=bus)
    try:
        report = engine.fix(root, "safe")
    except DirtyWorktreeError as exc:
        job.finish(error=str(exc), error_code="dirty_worktree")
        return
    except NoGitRepoError as exc:
        job.finish(error=str(exc), error_code="no_git_repo")
        return
    except GitSafetyError as exc:
        job.finish(error=str(exc), error_code="git_error")
        return
    git = engine.last_git_safety
    if git is not None:
        job.emit("repair.summary", {"safety": git.describe()})
    # A fix run always records itself: it changed the repository, and a change with no
    # record is the one thing worse than not repairing at all (DECISIONS.md D60).
    stored = _persist(report, root, config, bus, job)
    job.finish(report=_report_payload(report, history_ts=stored, root=root))


def _persist(
    report: ScanReport, root: Path, config: VibeguardConfig, bus: EventBus, job: _Job
) -> str | None:
    """Write the report files and the history entry, exactly as the CLI does.

    The engine never writes (DECISIONS.md D32); persistence is the caller's job, and
    the UI is a caller. Failures here are surfaced as a warning event rather than
    losing a scan the user just waited for. Returns the history entry's id, which is
    what the download buttons address the stored report by.
    """
    destination = config.state_root(root)
    try:
        paths = write_reports(report, destination, ("json", "md", "html"), events=bus)
        job.emit("report.written", {"paths": [str(p) for p in paths]})
    except OSError as exc:
        job.emit("report.failed", {"error": f"could not write reports to {destination}: {exc}"})
    if not config.history.enabled:
        return None
    try:
        return write_history(report, destination, keep=config.history.keep).stem
    except OSError as exc:
        job.emit("report.failed", {"error": f"could not record history: {exc}"})
        return None


def _report_payload(
    report: ScanReport, *, history_ts: str | None = None, root: Path | None = None
) -> dict[str, Any]:
    """The report as JSON, plus what the browser cannot derive for itself.

    The diagrams are rendered here by the very renderers the HTML report uses
    (``reporting.diagram``), so the web UI and the file on disk show the same picture
    rather than two hand-rolled approximations of it.
    """
    payload = report.model_dump(mode="json")
    payload["safe_autofix_candidates"] = sum(
        1
        for finding in report.findings
        if not finding.suppressed
        and finding.fix is None
        and finding.autofix_safety is AutofixSafety.SAFE_AUTOFIX
    )
    payload["diagrams"] = {
        "scores": svg_scores(report),
        "architecture": svg_architecture(report),
        "checklist": svg_checklist(report),
    }
    payload["history_ts"] = history_ts
    payload["scan_path"] = str(root) if root is not None else report.repo
    return payload


# -------------------------------------------------------------------------- serving


def serve(
    *,
    roots: list[Path] | None = None,
    initial_path: Path | None = None,
    port: int = DEFAULT_PORT,
    open_browser: bool = True,
) -> None:  # pragma: no cover - exercised by hand, not by the suite
    """Run the UI on ``127.0.0.1:port`` until interrupted."""
    import uvicorn

    app = create_app(roots=roots, initial_path=initial_path)
    url = f"http://{HOST}:{port}/"
    if open_browser:
        import webbrowser

        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    uvicorn.run(app, host=HOST, port=port, log_level="warning")
