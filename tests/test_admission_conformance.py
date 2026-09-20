"""Conformance and adversarial verification suite for artifact-admission-service.

Independent Consumer #2 demonstrating portability and fail-closed security invariants
using Semanti-piler installed as a clean wheel package.
"""
from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from semantipiler.api.conformance import (
    CONFORMANCE_EVIDENCE_BUNDLE_SCHEMA_VERSION,
    evaluate_consumer_conformance,
)

_ROOT = Path(__file__).resolve().parent.parent


class ArtifactAdmissionConformanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.profile_path = _ROOT / "semantipiler-profile.json"

    def test_positive_trajectory_conformance_passes(self) -> None:
        bundle = evaluate_consumer_conformance(
            self.profile_path,
            consumer_root=_ROOT,
            candidate_sha="independent-consumer-candidate-sha",
        )
        self.assertEqual(bundle.status, "PASS")
        self.assertEqual(bundle.consumer_id, "consumer:artifact-admission-service")
        self.assertEqual(bundle.profile_id, "consumer-profile:artifact-admission-service")
        self.assertEqual(bundle.schema_version, CONFORMANCE_EVIDENCE_BUNDLE_SCHEMA_VERSION)

        payload = bundle.to_dict()
        self.assertEqual(payload["evaluations"]["evidence_satisfaction"]["verdict"], "SATISFIED")
        self.assertEqual(payload["evaluations"]["transition_admissibility"]["verdict"], "SATISFIED")
        self.assertEqual(payload["evaluations"]["capability_coverage"]["verdict"], "SATISFIED")

    def test_adversarial_1_missing_signature_evidence_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_root = Path(tmp_dir)
            shutil.copytree(_ROOT, tmp_root / "repo", ignore=shutil.ignore_patterns(".venv", ".git", "__pycache__", "tests"))
            repo = tmp_root / "repo"

            # Mutate evidence contract: remove signature binding
            ev_file = repo / "contracts/evidence.json"
            ev_data = json.loads(ev_file.read_text(encoding="utf-8"))
            ev_data["bindings"] = [b for b in ev_data["bindings"] if b["requirement_id"] != "evidence:plugin-signature-verified"]
            ev_file.write_text(json.dumps(ev_data, indent=2), encoding="utf-8")

            bundle = evaluate_consumer_conformance(repo / "semantipiler-profile.json", consumer_root=repo)
            self.assertEqual(bundle.status, "FAIL")
            self.assertNotEqual(bundle.evidence_satisfaction.verdict.value, "SATISFIED")

    def test_adversarial_2_mismatched_verifier_identity_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_root = Path(tmp_dir)
            shutil.copytree(_ROOT, tmp_root / "repo", ignore=shutil.ignore_patterns(".venv", ".git", "__pycache__", "tests"))
            repo = tmp_root / "repo"

            # Mutate evidence verifier identity to an untrusted verifier
            ev_file = repo / "contracts/evidence.json"
            ev_data = json.loads(ev_file.read_text(encoding="utf-8"))
            ev_data["bindings"][1]["verifier_identity"] = "rogue-untrusted-signer"
            ev_file.write_text(json.dumps(ev_data, indent=2), encoding="utf-8")

            bundle = evaluate_consumer_conformance(repo / "semantipiler-profile.json", consumer_root=repo)
            self.assertEqual(bundle.status, "FAIL")
            self.assertNotEqual(bundle.evidence_satisfaction.verdict.value, "SATISFIED")

    def test_adversarial_3_insufficient_authority_scope_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_root = Path(tmp_dir)
            shutil.copytree(_ROOT, tmp_root / "repo", ignore=shutil.ignore_patterns(".venv", ".git", "__pycache__", "tests"))
            repo = tmp_root / "repo"

            # Require privileged scope for release transition that caller envelope does not possess
            tr_file = repo / "contracts/transitions.json"
            tr_data = json.loads(tr_file.read_text(encoding="utf-8"))
            tr_data["transitions"][1]["required_authority"]["allowed_scopes"] = ["release.governor"]
            tr_file.write_text(json.dumps(tr_data, indent=2), encoding="utf-8")

            bundle = evaluate_consumer_conformance(repo / "semantipiler-profile.json", consumer_root=repo)
            self.assertEqual(bundle.status, "FAIL")
            self.assertNotEqual(bundle.transition_admissibility.verdict.value, "SATISFIED")

    def test_adversarial_4_forbidden_effect_delta_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_root = Path(tmp_dir)
            shutil.copytree(_ROOT, tmp_root / "repo", ignore=shutil.ignore_patterns(".venv", ".git", "__pycache__", "tests"))
            repo = tmp_root / "repo"

            # Transition introduces forbidden mutation effect
            tr_file = repo / "contracts/transitions.json"
            tr_data = json.loads(tr_file.read_text(encoding="utf-8"))
            tr_data["transitions"][0]["effect_delta"] = ["forbidden_effect"]
            tr_file.write_text(json.dumps(tr_data, indent=2), encoding="utf-8")

            bundle = evaluate_consumer_conformance(repo / "semantipiler-profile.json", consumer_root=repo)
            self.assertEqual(bundle.status, "FAIL")
            self.assertNotEqual(bundle.transition_admissibility.verdict.value, "SATISFIED")

    def test_adversarial_5_unsupported_capability_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_root = Path(tmp_dir)
            shutil.copytree(_ROOT, tmp_root / "repo", ignore=shutil.ignore_patterns(".venv", ".git", "__pycache__", "tests"))
            repo = tmp_root / "repo"

            # Baseline requires a capability that the consumer has no claim for
            base_file = repo / "conformance/baseline.json"
            base_data = json.loads(base_file.read_text(encoding="utf-8"))
            base_data["coverage_requirements"].append({
                "requirement_id": "coverage-req:hardware-enclave-attestation",
                "capability_id": "capability://hardware-enclave-attestation@v1",
                "required_dimensions": {"hardware_enclave": True},
            })
            base_file.write_text(json.dumps(base_data, indent=2), encoding="utf-8")

            bundle = evaluate_consumer_conformance(repo / "semantipiler-profile.json", consumer_root=repo)
            self.assertEqual(bundle.status, "FAIL")
            self.assertNotEqual(bundle.capability_coverage.verdict.value, "SATISFIED")

    def test_adversarial_6_substitution_disallowed_when_forbidden(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_root = Path(tmp_dir)
            shutil.copytree(_ROOT, tmp_root / "repo", ignore=shutil.ignore_patterns(".venv", ".git", "__pycache__", "tests"))
            repo = tmp_root / "repo"

            # Claim offers bounded substitution but baseline forbids it
            base_file = repo / "conformance/baseline.json"
            base_data = json.loads(base_file.read_text(encoding="utf-8"))
            base_data["coverage_requirements"][0]["exact_realization_id"] = "realization://different-hardware@v1"
            base_data["coverage_requirements"][0]["allow_bounded_substitution"] = False
            base_file.write_text(json.dumps(base_data, indent=2), encoding="utf-8")

            bundle = evaluate_consumer_conformance(repo / "semantipiler-profile.json", consumer_root=repo)
            self.assertEqual(bundle.status, "FAIL")
            self.assertNotEqual(bundle.capability_coverage.verdict.value, "SATISFIED")
