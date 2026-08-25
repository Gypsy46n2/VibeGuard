# VibeGuard

> Audits, repairs, hardens, tests, and reports on vibe-coded applications, bringing
> them closer to production grade.

**Pipeline:** Detect → Explain → Repair → Test → Validate → Report

VibeGuard scans a repository with zero external installs (built-in regex, AST, and
config-parsing rules), optionally merges findings from external scanners when they are
present, and reports proportionally to the project's scale — a toy CRUD app never gets
told to adopt Kubernetes.

## Status

Milestone **M1 — core skeleton**: models, config, events, discovery, rule registry,
scoring, an end-to-end audit pipeline, and the CLI. Rule packs (M2), repair and
validation (M3), and rich reporting (M4) follow.

Working today:

```bash
pip install -e ".[dev]"
vibeguard audit path/to/repo          # writes vibeguard-report.json
vibeguard audit path/to/repo -o jsonl # streams events as JSON lines
vibeguard ci path/to/repo --fail-on high
vibeguard rules
vibeguard doctor
```

`vibeguard fix`, `vibeguard report`, and `vibeguard baseline` are scaffolded and
report their milestone when invoked.

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — design and roadmap
- [docs/INTERFACES.md](docs/INTERFACES.md) — binding contracts (normative)
- [docs/DECISIONS.md](docs/DECISIONS.md) — recorded contract interpretations

## License

Apache-2.0.
