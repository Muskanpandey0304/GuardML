"""
Step 5 tests: Risk scoring.
Every worked example from the spec must give the EXACT score.
"""
import pytest
from guardml.toolguard.risk import (
    compute_risk,
    Reversibility,
    BlastRadius,
    _label,
)


class TestRiskLabel:
    def test_0_is_low(self):
        assert _label(0) == "low"

    def test_30_is_low(self):
        assert _label(30) == "low"

    def test_31_is_medium(self):
        assert _label(31) == "medium"

    def test_69_is_medium(self):
        assert _label(69) == "medium"

    def test_70_is_high(self):
        assert _label(70) == "high"

    def test_100_is_high(self):
        assert _label(100) == "high"


class TestWorkedExamples:
    """Exact worked examples from the spec — every score must match."""

    def test_mlflow_list_runs_staging(self):
        """5+0+0+0 = 5 (low) → ALLOW"""
        r = compute_risk(
            base_risk=5, env_bonus=0,
            reversibility=Reversibility.REVERSIBLE,
            blast_radius=BlastRadius.ONE_RESOURCE,
        )
        assert r.score == 5
        assert r.label == "low"

    def test_drift_report_production(self):
        """5+20+0+0 = 25 (low) → ALLOW (read allowed in prod)"""
        r = compute_risk(
            base_risk=5, env_bonus=20,
            reversibility=Reversibility.REVERSIBLE,
            blast_radius=BlastRadius.ONE_RESOURCE,
        )
        assert r.score == 25
        assert r.label == "low"

    def test_docker_restart_model_api_staging(self):
        """25+0+0+10+15 = 50 (medium) → ALLOW with reason"""
        r = compute_risk(
            base_risk=25, env_bonus=0,
            reversibility=Reversibility.REVERSIBLE,
            blast_radius=BlastRadius.ONE_SERVICE,
            protected_target=True,
        )
        assert r.score == 50
        assert r.label == "medium"

    def test_docker_restart_model_api_production(self):
        """25+20+0+10+15 = 70 (high) → NEEDS_APPROVAL"""
        r = compute_risk(
            base_risk=25, env_bonus=20,
            reversibility=Reversibility.REVERSIBLE,
            blast_radius=BlastRadius.ONE_SERVICE,
            protected_target=True,
        )
        assert r.score == 70
        assert r.label == "high"

    def test_mlflow_set_alias_production_to_v1(self):
        """45+20+0+0+15 = 80 (high) → NEEDS_APPROVAL"""
        r = compute_risk(
            base_risk=45, env_bonus=20,
            reversibility=Reversibility.REVERSIBLE,  # snapshot makes it reversible
            blast_radius=BlastRadius.ONE_RESOURCE,
            protected_target=True,
        )
        assert r.score == 80
        assert r.label == "high"

    def test_mlflow_set_alias_after_tainted_read(self):
        """Same call after tainted session: 45+20+0+0+15+15 = 95 (high)"""
        r = compute_risk(
            base_risk=45, env_bonus=20,
            reversibility=Reversibility.REVERSIBLE,
            blast_radius=BlastRadius.ONE_RESOURCE,
            protected_target=True,
            tainted_session=True,
        )
        assert r.score == 95
        assert r.label == "high"

    def test_trigger_retrain_staging(self):
        """45+0+10+10 = 65 (medium) → NEEDS_APPROVAL (write_high in staging)"""
        r = compute_risk(
            base_risk=45, env_bonus=0,
            reversibility=Reversibility.PARTLY,
            blast_radius=BlastRadius.ONE_SERVICE,
        )
        assert r.score == 65
        assert r.label == "medium"


class TestRiskFactors:
    def test_capped_at_100(self):
        r = compute_risk(
            base_risk=45, env_bonus=20,
            reversibility=Reversibility.IRREVERSIBLE,
            blast_radius=BlastRadius.GLOBAL,
            protected_target=True,
            tainted_session=True,
            repeat_penalty=True,
        )
        assert r.score == 100

    def test_repeat_penalty_adds_10(self):
        r1 = compute_risk(25, 0, repeat_penalty=False)
        r2 = compute_risk(25, 0, repeat_penalty=True)
        assert r2.score == r1.score + 10

    def test_tainted_session_adds_15(self):
        r1 = compute_risk(25, 0, tainted_session=False)
        r2 = compute_risk(25, 0, tainted_session=True)
        assert r2.score == r1.score + 15

    def test_protected_target_adds_15(self):
        r1 = compute_risk(25, 0, protected_target=False)
        r2 = compute_risk(25, 0, protected_target=True)
        assert r2.score == r1.score + 15

    def test_irreversible_adds_25(self):
        r1 = compute_risk(25, 0, reversibility=Reversibility.REVERSIBLE)
        r2 = compute_risk(25, 0, reversibility=Reversibility.IRREVERSIBLE)
        assert r2.score == r1.score + 25

    def test_global_blast_adds_20(self):
        r1 = compute_risk(25, 0, blast_radius=BlastRadius.ONE_RESOURCE)
        r2 = compute_risk(25, 0, blast_radius=BlastRadius.GLOBAL)
        assert r2.score == r1.score + 20

    def test_factors_listed(self):
        r = compute_risk(25, 20, protected_target=True)
        assert any("base_risk" in f for f in r.factors)
        assert any("env_bonus" in f for f in r.factors)
        assert any("protected_target" in f for f in r.factors)
