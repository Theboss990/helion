from __future__ import annotations

from helion.attack_intelligence import ActionMode
from helion.attack_intelligence import AttackIntelligenceCase
from helion.attack_intelligence import AttackPath
from helion.attack_intelligence import AttackSignal
from helion.attack_intelligence import CandidateFinding
from helion.attack_intelligence import DecisionOutcome
from helion.attack_intelligence import Priority
from helion.attack_intelligence import ValidationEvidence
from helion.attack_intelligence import ValidationState


def _signal() -> AttackSignal:
    return AttackSignal(
        source="passive-dns",
        title="Wildcard subdomain signal",
        detail="Passive telemetry links the asset to the target scope.",
        confidence=0.82,
    )


def test_priority_uses_impact_likelihood_matrix() -> None:
    finding = CandidateFinding(title="ADCS exposure", signals=(_signal(),), impact=5, likelihood=4)

    assert finding.priority is Priority.CRITICAL


def test_report_projection_requires_manual_validation() -> None:
    finding = CandidateFinding(
        title="Cloud privilege path",
        signals=(_signal(),),
        impact=4,
        likelihood=4,
        validation=ValidationEvidence(
            summary="Validated from passive evidence and operator review.",
            state=ValidationState.MANUAL_VALIDATED,
            validator="analyst-1",
        ),
    )
    case = AttackIntelligenceCase(case_id="case-1", candidates=(finding,))

    assert finding.is_reportable()
    assert case.decisions()[0].outcome is DecisionOutcome.REPORT
    assert case.report_projection()[0].title == "Cloud privilege path"


def test_unvalidated_high_priority_candidate_is_held() -> None:
    finding = CandidateFinding(title="Unreviewed path", signals=(_signal(),), impact=4, likelihood=4)
    case = AttackIntelligenceCase(case_id="case-2", candidates=(finding,))

    assert not finding.is_reportable()
    assert case.decisions()[0].outcome is DecisionOutcome.HOLD


def test_active_attack_path_is_blocked_by_passive_only_gate() -> None:
    finding = CandidateFinding(
        title="Unsafe active path",
        signals=(_signal(),),
        attack_paths=(AttackPath(name="exploit", steps=("run exploit",), mode=ActionMode.ACTIVE),),
        impact=5,
        likelihood=5,
        validation=ValidationEvidence(
            summary="Operator reviewed but active execution is still disallowed.",
            state=ValidationState.MANUAL_VALIDATED,
            validator="analyst-1",
        ),
    )
    case = AttackIntelligenceCase(case_id="case-3", candidates=(finding,))

    assert not finding.is_reportable()
    assert case.decisions()[0].outcome is DecisionOutcome.HOLD
    assert "passive-only" in case.decisions()[0].rationale


def test_non_passive_signal_blocks_reportability() -> None:
    signal = AttackSignal(
        source="scanner",
        title="Active scan result",
        detail="Signal came from active probing.",
        confidence=0.9,
        passive=False,
    )
    finding = CandidateFinding(
        title="Unsafe signal",
        signals=(signal,),
        impact=4,
        likelihood=4,
        validation=ValidationEvidence(
            summary="Reviewed.",
            state=ValidationState.MANUAL_VALIDATED,
            validator="analyst-1",
        ),
    )

    assert not finding.is_reportable()
    assert finding.unresolved_blockers()[0].severity is Priority.CRITICAL
