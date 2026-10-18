"""
Step 5: Risk scoring.
Formula (cap at 100):
  score = base_risk(tool_class)
        + env_bonus (production=+20)
        + reversibility (reversible=0, partly=+10, irreversible=+25)
        + blast_radius (one_resource=0, one_service=+10, global=+20)
        + protected_target (+15 if touching a protected resource)
        + tainted_session (+15 if write follows reading untrusted text)
        + repeat_penalty (+10 if same write tried twice OR blocked call this session)
        + untrusted_provenance (+20 if a write argument came from tool output, not the user)

Labels: 0-30=low, 31-69=medium, 70-100=high

Worked examples from spec (all verified by tests):
  mlflow_list_runs staging           : 5+0+0+0+0+0+0 = 5  (low)   ALLOW
  drift_report production            : 5+20+0+0+0+0+0 = 25 (low)   ALLOW
  docker_restart model-api staging   : 25+0+0+10+15+0+0 = 50 (medium) ALLOW w/reason
  docker_restart model-api production: 25+20+0+10+15+0+0 = 70 (high) NEEDS_APPROVAL
  mlflow_set_alias prod->v1 prod     : 45+20+0+0+15+0+0 = 80 (high) NEEDS_APPROVAL
  same + tainted                     : 45+20+0+0+15+15+0 = 95 (high)
  trigger_retrain staging            : 45+0+10+10+0+0+0 = 65 (medium) NEEDS_APPROVAL
"""
from __future__ import annotations

from typing import Dict, List, Tuple


# ---------------------------------------------------------------------------
# Constants (declared in code, not at runtime from LLM)
# ---------------------------------------------------------------------------
class Reversibility:
    REVERSIBLE = 0
    PARTLY = 10
    IRREVERSIBLE = 25


class BlastRadius:
    ONE_RESOURCE = 0
    ONE_SERVICE = 10
    GLOBAL = 20


# ---------------------------------------------------------------------------
# Score result
# ---------------------------------------------------------------------------
class RiskResult:
    def __init__(self, score: int, label: str, factors: List[str]):
        self.score = score
        self.label = label
        self.factors = factors

    def as_dict(self) -> Dict:
        return {"score": self.score, "label": self.label, "factors": self.factors}


def _label(score: int) -> str:
    if score <= 30:
        return "low"
    if score <= 69:
        return "medium"
    return "high"


# ---------------------------------------------------------------------------
# Main scoring function
# ---------------------------------------------------------------------------
def compute_risk(
    base_risk: int,
    env_bonus: int = 0,
    reversibility: int = Reversibility.REVERSIBLE,
    blast_radius: int = BlastRadius.ONE_RESOURCE,
    protected_target: bool = False,
    tainted_session: bool = False,
    repeat_penalty: bool = False,
    untrusted_provenance: bool = False,
) -> RiskResult:
    """
    All parameters come from tool metadata or session state — NEVER from the LLM.
    """
    factors: List[str] = []
    score = base_risk
    factors.append(f"base_risk={base_risk}")

    if env_bonus:
        score += env_bonus
        factors.append(f"env_bonus=+{env_bonus}")

    if reversibility:
        score += reversibility
        factors.append(f"reversibility=+{reversibility}")

    if blast_radius:
        score += blast_radius
        factors.append(f"blast_radius=+{blast_radius}")

    if protected_target:
        score += 15
        factors.append("protected_target=+15")

    if tainted_session:
        score += 15
        factors.append("tainted_session=+15")

    if repeat_penalty:
        score += 10
        factors.append("repeat_penalty=+10")

    if untrusted_provenance:
        score += 20
        factors.append("untrusted_provenance=+20")

    score = min(score, 100)
    label = _label(score)
    return RiskResult(score=score, label=label, factors=factors)


# ---------------------------------------------------------------------------
# Tool risk metadata (fixed in code, not runtime-settable by LLM)
# ---------------------------------------------------------------------------
class ToolRiskMeta:
    """
    Each tool declares its own reversibility and blast_radius.
    Format: (reversibility, blast_radius)
    """
    _META: Dict[str, Tuple[int, int]] = {
        # MLflow reads
        "mlflow_list_runs": (Reversibility.REVERSIBLE, BlastRadius.ONE_RESOURCE),
        "mlflow_get_run": (Reversibility.REVERSIBLE, BlastRadius.ONE_RESOURCE),
        "mlflow_compare_runs": (Reversibility.REVERSIBLE, BlastRadius.ONE_RESOURCE),
        "mlflow_list_model_versions": (Reversibility.REVERSIBLE, BlastRadius.ONE_RESOURCE),
        "mlflow_get_production_model": (Reversibility.REVERSIBLE, BlastRadius.ONE_RESOURCE),
        # MLflow writes
        "mlflow_set_alias": (Reversibility.REVERSIBLE, BlastRadius.ONE_RESOURCE),
        "trigger_retrain": (Reversibility.PARTLY, BlastRadius.ONE_SERVICE),
        # Drift / quality reads
        "drift_report": (Reversibility.REVERSIBLE, BlastRadius.ONE_RESOURCE),
        "data_quality_check": (Reversibility.REVERSIBLE, BlastRadius.ONE_RESOURCE),
        # DVC reads
        "dvc_status": (Reversibility.REVERSIBLE, BlastRadius.ONE_RESOURCE),
        "dvc_diff": (Reversibility.REVERSIBLE, BlastRadius.ONE_RESOURCE),
        # System reads
        "gpu_status": (Reversibility.REVERSIBLE, BlastRadius.ONE_RESOURCE),
        "disk_memory_status": (Reversibility.REVERSIBLE, BlastRadius.ONE_RESOURCE),
        # Docker
        "docker_ps": (Reversibility.REVERSIBLE, BlastRadius.ONE_RESOURCE),
        "docker_logs": (Reversibility.REVERSIBLE, BlastRadius.ONE_RESOURCE),
        "docker_stats": (Reversibility.REVERSIBLE, BlastRadius.ONE_RESOURCE),
        "docker_restart": (Reversibility.REVERSIBLE, BlastRadius.ONE_SERVICE),
        # kubectl
        "kubectl_get_pods": (Reversibility.REVERSIBLE, BlastRadius.ONE_RESOURCE),
        "kubectl_logs": (Reversibility.REVERSIBLE, BlastRadius.ONE_RESOURCE),
        # Health
        "health_check": (Reversibility.REVERSIBLE, BlastRadius.ONE_RESOURCE),
        # Snapshots
        "create_snapshot": (Reversibility.REVERSIBLE, BlastRadius.ONE_RESOURCE),
        "restore_snapshot": (Reversibility.REVERSIBLE, BlastRadius.ONE_RESOURCE),
    }

    @classmethod
    def get(cls, tool_name: str) -> Tuple[int, int]:
        return cls._META.get(
            tool_name, (Reversibility.PARTLY, BlastRadius.ONE_SERVICE)
        )


def score_risk(risk_level, environment: str = 'staging', args: dict = None) -> dict:
    from guardml.tools.base import RiskLevel
    args = args or {}
    base = 5 if risk_level == RiskLevel.READ else (25 if risk_level == RiskLevel.WRITE_LOW else 45)
    env_bonus = 20 if environment == 'production' else 0
    protected = any(v in ('production', 'prod') for v in args.values() if isinstance(v, str))
    res = compute_risk(base_risk=base, env_bonus=env_bonus, protected_target=protected)
    return res.as_dict()

