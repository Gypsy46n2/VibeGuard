# NoteNest — a deliberately vulnerable example app

> **DO NOT DEPLOY THIS. DO NOT RUN IT ON A MACHINE YOU CARE ABOUT.**
>
> Every file here is broken on purpose. It exists so VibeGuard has something honest
> to find, and so you can see what a report on a real vibe-coded app looks like
> before you point the tool at your own.

NoteNest is what "build me a notes SaaS" produces in an afternoon: a Flask app, a
SQLite file, a Dockerfile copied from a blog post, and a deploy workflow that ships
to production on every push. It works. It is also indefensible.

All credentials in this directory are **fabricated**. They authenticate nothing,
anywhere. `AKIAIOSFODNN7EXAMPLE` is AWS's own documentation placeholder.

## Try it

```bash
vibeguard audit examples/vulnerable-app
vibeguard ci    examples/vulnerable-app --fail-on high   # exits 1
```

## What is wrong with it

| File | What it does wrong |
|---|---|
| `app.py` | SQL built with f-strings in the login query (`' OR 1=1 --` logs you in); MD5 for passwords; session tokens from `random`; `CORS(origins="*")` with credentials; a JWT secret in source; `jwt.decode(..., verify_signature=False)`; `set_cookie` with no Secure/HttpOnly/SameSite; `verify=False` on an outbound call; no timeout on any HTTP call; an open redirect; SSRF via a user-supplied URL; `/admin/export` with no auth check; `debug=True` bound to `0.0.0.0`; `print()` for diagnostics |
| `db.py` | A new connection per call, never closed; `SELECT *`; every query interpolated; no migration tooling |
| `integrations.py` | Outbound HTTP with no timeouts, a new connection per call, one synchronous call per subscriber in the request path, and a bare `except: pass` |
| `templates/notes.html` | `\| safe` on user-controlled title and body (stored XSS), plus an `innerHTML` sink fed from the query string |
| `requirements.txt` | Nothing pinned, no lockfile |
| `.env` | Committed to git, with database URL, signing secret, and cloud keys in it |
| `Dockerfile` | `FROM python:latest`, runs as root, no HEALTHCHECK, dependency install after copying the whole context, secret baked in with `ENV` |
| `docker-compose.yml` | `privileged: true`, no resource limits, dev mode in the environment |
| `.github/workflows/deploy.yml` | Deploys to production on push with no test step, echoes a token, `curl -k` |
| everywhere | No tests, no logging framework, no backups for the SQLite file that lives on the container filesystem |

## What VibeGuard makes of it

At the time of writing: **77 findings across 13 categories from 51 distinct rules**
(7 critical, 27 high), overall score **55/100**.

The integration test `tests/test_examples.py` asserts a tolerant floor (≥20
findings across ≥6 categories) rather than these exact numbers — rules get added,
and an example is not a golden file.

### Two things it deliberately does *not* say

* **No `/healthz` endpoint is not reported here.** `VG-OBS-004` requires
  `min_scale = medium`; NoteNest classifies as *small*. Proportionality is the
  point — a weekend project is not marked down for lacking an SRE practice. Grow
  the app and the rule starts applying.
* **Per-request `sqlite3.connect()` is not reported as a pooling defect.**
  `VG-DB-002` covers drivers where a connection is expensive; for SQLite, a
  connection per request is what Flask's own documentation recommends. The real
  problem — the database file living on an ephemeral container filesystem with no
  backup — is reported instead, as `VG-DR-003` and `VG-DR-001`.

See `../repaired-app/` for what `vibeguard fix --safe` does to this, and what it
honestly refuses to do.
