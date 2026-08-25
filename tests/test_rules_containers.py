"""Positive and negative coverage for the containers pack (VG-CTR-001..012)."""

from __future__ import annotations

from pathlib import Path

import pytest

from conftest import run_rule
from vibeguard.rules.containers import RULES
from vibeguard.rules.containers.compose import (
    ComposeNoResourceLimitsRule,
    ComposePrivilegedServiceRule,
)
from vibeguard.rules.containers.dockerfile_quality import (
    DockerfileNoHealthcheckRule,
    ImageLayerBloatRule,
    InstallAfterFullContextCopyRule,
)
from vibeguard.rules.containers.dockerfile_security import (
    ContainerRunsAsRootRule,
    SecretBakedIntoImageRule,
    UnpinnedBaseImageRule,
)
from vibeguard.rules.containers.kubernetes import (
    K8sInsecureWorkloadRule,
    K8sNoProbesRule,
    K8sNoResourceLimitsRule,
)
from vibeguard.rules.containers.rollout import NoProgressiveRolloutRule

APP = "print('hello')\n"

BAD_DOCKERFILE = """\
FROM python:latest
ENV API_KEY=sk-live-abcdef1234567890
RUN apt-get update && apt-get install -y curl
COPY . .
RUN pip install -r requirements.txt
CMD ["python", "app.py"]
"""

GOOD_DOCKERFILE = """\
FROM python:3.12-slim@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
RUN adduser --system --no-create-home app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
USER app
HEALTHCHECK CMD curl -fsS http://localhost:8000/healthz || exit 1
CMD ["python", "app.py"]
"""

BAD_COMPOSE = """\
services:
  api:
    image: myapp:latest
    privileged: true
    network_mode: host
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
"""

GOOD_COMPOSE = """\
services:
  api:
    image: myapp:1.2.3
    restart: unless-stopped
    user: "1000:1000"
    mem_limit: 512m
    cpus: 0.5
"""

BAD_K8S = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  template:
    spec:
      hostNetwork: true
      containers:
        - name: api
          image: myapp:latest
          securityContext:
            privileged: true
"""

GOOD_K8S = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  strategy:
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
  template:
    spec:
      containers:
        - name: api
          image: myapp@sha256:bbbb
          securityContext:
            runAsNonRoot: true
            runAsUser: 1000
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
          livenessProbe:
            httpGet: {path: /healthz, port: 8000}
          readinessProbe:
            httpGet: {path: /ready, port: 8000}
          startupProbe:
            httpGet: {path: /healthz, port: 8000}
          resources:
            requests: {cpu: 100m, memory: 128Mi}
            limits: {cpu: 500m, memory: 512Mi}
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: api
spec:
  minReplicas: 2
  maxReplicas: 10
"""


def _ids(findings: list) -> list[str]:
    return sorted({f.rule_id for f in findings})


# --------------------------------------------------------------------- Dockerfile


@pytest.mark.parametrize(
    ("rule", "rule_id"),
    [
        (ContainerRunsAsRootRule, "VG-CTR-001"),
        (DockerfileNoHealthcheckRule, "VG-CTR-002"),
        (UnpinnedBaseImageRule, "VG-CTR-003"),
        (InstallAfterFullContextCopyRule, "VG-CTR-004"),
        (SecretBakedIntoImageRule, "VG-CTR-005"),
        (ImageLayerBloatRule, "VG-CTR-006"),
    ],
)
def test_dockerfile_rules_fire(tmp_path: Path, rule: type, rule_id: str) -> None:
    findings = run_rule(rule, tmp_path, {"Dockerfile": BAD_DOCKERFILE, "app.py": APP})
    assert _ids(findings) == [rule_id]


@pytest.mark.parametrize(
    "rule",
    [
        ContainerRunsAsRootRule,
        DockerfileNoHealthcheckRule,
        UnpinnedBaseImageRule,
        InstallAfterFullContextCopyRule,
        SecretBakedIntoImageRule,
        ImageLayerBloatRule,
    ],
)
def test_dockerfile_rules_silent_on_good_dockerfile(tmp_path: Path, rule: type) -> None:
    assert run_rule(rule, tmp_path, {"Dockerfile": GOOD_DOCKERFILE, "app.py": APP}) == []


def test_root_user_flags_explicit_user_root(tmp_path: Path) -> None:
    dockerfile = "FROM python:3.12-slim\nUSER root\nCMD [\"python\", \"app.py\"]\n"
    findings = run_rule(ContainerRunsAsRootRule, tmp_path, {"Dockerfile": dockerfile})
    assert [f.rule_id for f in findings] == ["VG-CTR-001"]
    assert "USER root" in findings[0].evidence[0].snippet


def test_unpinned_base_ignores_multi_stage_alias(tmp_path: Path) -> None:
    dockerfile = (
        "FROM python:3.12-slim AS build\nRUN echo build\n"
        "FROM build\nUSER app\nCMD [\"python\", \"app.py\"]\n"
    )
    assert run_rule(UnpinnedBaseImageRule, tmp_path, {"Dockerfile": dockerfile}) == []


def test_healthcheck_rule_ignores_builder_only_stage(tmp_path: Path) -> None:
    dockerfile = "FROM python:3.12-slim AS build\nRUN pip install --no-cache-dir build\n"
    assert run_rule(DockerfileNoHealthcheckRule, tmp_path, {"Dockerfile": dockerfile}) == []


def test_secret_rule_redacts_evidence(tmp_path: Path) -> None:
    findings = run_rule(SecretBakedIntoImageRule, tmp_path, {"Dockerfile": BAD_DOCKERFILE})
    assert findings
    assert "sk-live-abcdef1234567890" not in findings[0].evidence[0].snippet


def test_secret_rule_ignores_placeholder_arg(tmp_path: Path) -> None:
    dockerfile = 'FROM python:3.12-slim\nARG API_KEY\nENV API_KEY=${API_KEY}\nUSER app\n'
    assert run_rule(SecretBakedIntoImageRule, tmp_path, {"Dockerfile": dockerfile}) == []


def test_dockerfile_parsing_survives_garbage(tmp_path: Path) -> None:
    junk = "\x00\x01 not a dockerfile \\\n\\\n" + "#" * 500
    for rule in (ContainerRunsAsRootRule, UnpinnedBaseImageRule, ImageLayerBloatRule):
        assert run_rule(rule, tmp_path, {"Dockerfile": junk}) == []


# ------------------------------------------------------------------------ compose


@pytest.mark.parametrize(
    ("rule", "rule_id"),
    [
        (ComposePrivilegedServiceRule, "VG-CTR-007"),
        (ComposeNoResourceLimitsRule, "VG-CTR-008"),
    ],
)
def test_compose_rules_fire(tmp_path: Path, rule: type, rule_id: str) -> None:
    findings = run_rule(rule, tmp_path, {"docker-compose.yml": BAD_COMPOSE, "app.py": APP})
    assert _ids(findings) == [rule_id]


@pytest.mark.parametrize("rule", [ComposePrivilegedServiceRule, ComposeNoResourceLimitsRule])
def test_compose_rules_silent_on_good_compose(tmp_path: Path, rule: type) -> None:
    assert run_rule(rule, tmp_path, {"docker-compose.yml": GOOD_COMPOSE, "app.py": APP}) == []


def test_compose_rules_survive_malformed_yaml(tmp_path: Path) -> None:
    broken = "services:\n  api:\n   - [unclosed\n\t\tbad: indent\n"
    for rule in (ComposePrivilegedServiceRule, ComposeNoResourceLimitsRule):
        assert run_rule(rule, tmp_path, {"docker-compose.yml": broken}) == []


def test_compose_cap_add_and_root_user_detected(tmp_path: Path) -> None:
    compose = (
        "services:\n  api:\n    image: app:1.0\n    restart: always\n"
        "    user: root\n    cap_add: [SYS_ADMIN]\n    mem_limit: 256m\n"
    )
    findings = run_rule(ComposePrivilegedServiceRule, tmp_path, {"docker-compose.yml": compose})
    assert [f.rule_id for f in findings] == ["VG-CTR-007"]
    note = findings[0].evidence[0].note
    assert "SYS_ADMIN" in note and "user: root" in note


# --------------------------------------------------------------------- kubernetes


@pytest.mark.parametrize(
    ("rule", "rule_id"),
    [
        (K8sNoProbesRule, "VG-CTR-009"),
        (K8sNoResourceLimitsRule, "VG-CTR-010"),
        (K8sInsecureWorkloadRule, "VG-CTR-011"),
    ],
)
def test_k8s_rules_fire(tmp_path: Path, rule: type, rule_id: str) -> None:
    findings = run_rule(rule, tmp_path, {"k8s/deploy.yaml": BAD_K8S, "app.py": APP})
    assert _ids(findings) == [rule_id]


@pytest.mark.parametrize(
    "rule", [K8sNoProbesRule, K8sNoResourceLimitsRule, K8sInsecureWorkloadRule]
)
def test_k8s_rules_silent_on_hardened_manifest(tmp_path: Path, rule: type) -> None:
    assert run_rule(rule, tmp_path, {"k8s/deploy.yaml": GOOD_K8S, "app.py": APP}) == []


@pytest.mark.parametrize(
    "rule", [K8sNoProbesRule, K8sNoResourceLimitsRule, K8sInsecureWorkloadRule]
)
def test_k8s_rules_not_applicable_without_manifests(tmp_path: Path, rule: type) -> None:
    """Compose-only / Dockerfile-only projects must leave the k8s topics untouched."""
    files = {
        "Dockerfile": GOOD_DOCKERFILE,
        "docker-compose.yml": GOOD_COMPOSE,
        "app.py": APP,
    }
    assert run_rule(rule, tmp_path, files) == []


def test_k8s_rules_gate_is_applicable_false(tmp_path: Path) -> None:
    from conftest import context_from

    ctx = context_from(tmp_path, {"Dockerfile": GOOD_DOCKERFILE, "app.py": APP})
    for rule in (K8sNoProbesRule, K8sNoResourceLimitsRule, K8sInsecureWorkloadRule):
        assert rule().applicable(ctx) is False


def test_k8s_rules_survive_malformed_manifest(tmp_path: Path) -> None:
    broken = "apiVersion: v1\nkind: [unterminated\n  bad:\n\t- x\n"
    for rule in (K8sNoProbesRule, K8sNoResourceLimitsRule, K8sInsecureWorkloadRule):
        assert run_rule(rule, tmp_path, {"k8s/broken.yaml": broken}) == []


# ------------------------------------------------------------------------ rollout


def test_no_progressive_rollout_fires(tmp_path: Path) -> None:
    bare = BAD_K8S  # a Deployment with no strategy, no HPA, no chart
    findings = run_rule(NoProgressiveRolloutRule, tmp_path, {"k8s/deploy.yaml": bare})
    assert [f.rule_id for f in findings] == ["VG-CTR-012"]
    assert findings[0].autofix_safety.value == "informational"


def test_no_progressive_rollout_silent_with_hpa_and_strategy(tmp_path: Path) -> None:
    assert run_rule(NoProgressiveRolloutRule, tmp_path, {"k8s/deploy.yaml": GOOD_K8S}) == []


def test_no_progressive_rollout_not_applicable_without_orchestrator(tmp_path: Path) -> None:
    assert run_rule(NoProgressiveRolloutRule, tmp_path, {"Dockerfile": GOOD_DOCKERFILE}) == []


# --------------------------------------------------------------------- pack-level


def test_pack_registers_every_rule_id_in_order() -> None:
    assert [rule.id for rule in RULES] == [f"VG-CTR-{n:03d}" for n in range(1, 13)]


def test_shared_fixture_app_trips_the_expected_rules() -> None:
    from conftest import FIXTURES, make_context

    ctx = make_context(FIXTURES / "containers_vulnerable")
    fired = {
        rule_cls.id
        for rule_cls in RULES
        if (rule := rule_cls()).applicable(ctx) and rule.detect(ctx)
    }
    assert {f"VG-CTR-{n:03d}" for n in (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11)} <= fired


def test_no_rule_raises_on_an_empty_repo(tmp_path: Path) -> None:
    from conftest import context_from

    ctx = context_from(tmp_path, {"README.md": "# empty\n"})
    for rule_cls in RULES:
        rule = rule_cls()
        findings = rule.detect(ctx) if rule.applicable(ctx) else []
        assert isinstance(findings, list)
