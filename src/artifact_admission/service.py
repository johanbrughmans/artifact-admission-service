"""Plugin and artifact release admission domain logic.

Purpose: Model artifact validation and state transition verification without OMV concepts.
Bounded Context: artifact_admission.domain.admission
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ArtifactLifecycleState(str, Enum):
    CANDIDATE = "CANDIDATE"
    VERIFIED = "VERIFIED"
    RELEASED = "RELEASED"


@dataclass(frozen=True, slots=True)
class PluginArtifact:
    plugin_id: str
    version: str
    artifact_sha256: str
    signature: str
    sandbox_isolation_level: str


def evaluate_admission_state(
    artifact: PluginArtifact,
    has_audit_evidence: bool,
    has_signature_evidence: bool,
    has_release_authority: bool,
) -> ArtifactLifecycleState:
    """Evaluate current admission state for a candidate plugin."""
    if not (has_audit_evidence and has_signature_evidence):
        return ArtifactLifecycleState.CANDIDATE
    if not has_release_authority:
        return ArtifactLifecycleState.VERIFIED
    return ArtifactLifecycleState.RELEASED
