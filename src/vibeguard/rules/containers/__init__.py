"""VibeGuard containers rule pack.

Dockerfile, docker-compose, and Kubernetes manifest checks. Detection is pure
config parsing (see :mod:`vibeguard.rules.containers._parse`): a Dockerfile
instruction tokenizer and guarded ``yaml.safe_load_all`` for compose and k8s.

The Kubernetes rules gate on ``applicable()`` so a project with no manifests
leaves those checklist topics at NOT_APPLICABLE instead of generating noise.
"""

from __future__ import annotations

from vibeguard.core.rule import Rule
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

RULES: list[type[Rule]] = [
    ContainerRunsAsRootRule,  # VG-CTR-001
    DockerfileNoHealthcheckRule,  # VG-CTR-002
    UnpinnedBaseImageRule,  # VG-CTR-003
    InstallAfterFullContextCopyRule,  # VG-CTR-004
    SecretBakedIntoImageRule,  # VG-CTR-005
    ImageLayerBloatRule,  # VG-CTR-006
    ComposePrivilegedServiceRule,  # VG-CTR-007
    ComposeNoResourceLimitsRule,  # VG-CTR-008
    K8sNoProbesRule,  # VG-CTR-009
    K8sNoResourceLimitsRule,  # VG-CTR-010
    K8sInsecureWorkloadRule,  # VG-CTR-011
    NoProgressiveRolloutRule,  # VG-CTR-012
]

__all__ = [
    "RULES",
    "ComposeNoResourceLimitsRule",
    "ComposePrivilegedServiceRule",
    "ContainerRunsAsRootRule",
    "DockerfileNoHealthcheckRule",
    "ImageLayerBloatRule",
    "InstallAfterFullContextCopyRule",
    "K8sInsecureWorkloadRule",
    "K8sNoProbesRule",
    "K8sNoResourceLimitsRule",
    "NoProgressiveRolloutRule",
    "SecretBakedIntoImageRule",
    "UnpinnedBaseImageRule",
]
