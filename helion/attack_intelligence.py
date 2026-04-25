from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field
from enum import Enum
from typing import Any


class SafetyGate(str, Enum):
    PASSIVE_ONLY = "passive_only"
    MANUAL_VALIDATION = "manual_validation"


class ActionMode(str, Enum):
    PASSIVE = "passive"
    MANUAL = "manual"
    ACTIVE = "active"


class ValidationState(str, Enum):
    UNVALIDATED = "unvalidated"
    NEEDS_MANUAL_VALIDATION = "needs_manual_validation"
    MANUAL_VALIDATED = "manual_validated"
    REJECTED = "rejected"


class DecisionOutcome(str, Enum):
    HOLD = "hold"
    ESCALATE = "escalate"
    REPORT = "report"
    REJECT = "reject"


class Priority(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class Blocker:
    reason: str
    severity: Priority = Priority.MEDIUM
    resolved: bool = False


@dataclass(frozen=True)
class ValidationEvidence:
    summary: str
    state: ValidationState = ValidationState.UNVALIDATED
    validator: str | None = None
    artifacts: tuple[str, ...] = ()

    def is_manually_validated(self) -> bool:
        return self.state is ValidationState.MANUAL_VALIDATED and bool(self.validator)


@dataclass(frozen=True)
class AttackSignal:
    source: str
    title: str
    detail: str
    confidence: float
    observed_at: str | None = None
    passive: bool = True

    def __post_init__(self) -> None:
        if not 0 <= self.confidence <= 1:
            msg = "signal confidence must be between 0 and 1"
            raise ValueError(msg)


@dataclass(frozen=True)
class AIGeneratedReasoning:
    hypothesis: str
    supporting_signal_ids: tuple[str, ...] = ()
    caveats: tuple[str, ...] = ()
    model: str | None = None


@dataclass(frozen=True)
class AttackPath:
    name: str
    steps: tuple[str, ...]
    mode: ActionMode = ActionMode.PASSIVE
    destructive: bool = False
    requires_credentials: bool = False

    def safety_blockers(self) -> tuple[Blocker, ...]:
        blockers: list[Blocker] = []
        if self.mode is ActionMode.ACTIVE:
            blockers.append(
                Blocker("active execution is blocked by passive-only ROE", Priority.CRITICAL)
            )
        if self.destructive:
            blockers.append(Blocker("destructive payloads are blocked", Priority.CRITICAL))
        if self.requires_credentials:
            blockers.append(
                Blocker("credential use requires explicit manual validation", Priority.HIGH)
            )
        return tuple(blockers)


@dataclass(frozen=True)
class CandidateFinding:
    title: str
    signals: tuple[AttackSignal, ...]
    attack_paths: tuple[AttackPath, ...] = ()
    validation: ValidationEvidence = field(
        default_factory=lambda: ValidationEvidence("not validated")
    )
    blockers: tuple[Blocker, ...] = ()
    impact: int = 1
    likelihood: int = 1
    reasoning: AIGeneratedReasoning | None = None

    def __post_init__(self) -> None:
        if not 1 <= self.impact <= 5:
            msg = "impact must be between 1 and 5"
            raise ValueError(msg)
        if not 1 <= self.likelihood <= 5:
            msg = "likelihood must be between 1 and 5"
            raise ValueError(msg)
        if not self.signals:
            msg = "candidate findings require at least one signal"
            raise ValueError(msg)

    @property
    def priority(self) -> Priority:
        score = self.impact * self.likelihood
        if score >= 20:
            return Priority.CRITICAL
        if score >= 12:
            return Priority.HIGH
        if score >= 6:
            return Priority.MEDIUM
        return Priority.LOW

    def safety_blockers(self) -> tuple[Blocker, ...]:
        passive_blockers = [
            Blocker("non-passive signal is blocked by passive-only ROE", Priority.CRITICAL)
            for signal in self.signals
            if not signal.passive
        ]
        path_blockers = [
            blocker for path in self.attack_paths for blocker in path.safety_blockers()
        ]
        return (*self.blockers, *passive_blockers, *path_blockers)

    def unresolved_blockers(self) -> tuple[Blocker, ...]:
        return tuple(blocker for blocker in self.safety_blockers() if not blocker.resolved)

    def is_reportable(self) -> bool:
        return (
            self.validation.is_manually_validated()
            and not self.unresolved_blockers()
            and self.priority in {Priority.HIGH, Priority.CRITICAL}
        )


@dataclass(frozen=True)
class Decision:
    outcome: DecisionOutcome
    rationale: str
    gates: tuple[SafetyGate, ...] = (
        SafetyGate.PASSIVE_ONLY,
        SafetyGate.MANUAL_VALIDATION,
    )


@dataclass(frozen=True)
class ReportProjection:
    title: str
    priority: Priority
    validated_by: str
    executive_summary: str
    evidence: tuple[str, ...]
    recommended_decision: DecisionOutcome


@dataclass(frozen=True)
class AttackIntelligenceCase:
    case_id: str
    candidates: tuple[CandidateFinding, ...]

    def decisions(self) -> tuple[Decision, ...]:
        decisions: list[Decision] = []
        for candidate in self.candidates:
            blockers = candidate.unresolved_blockers()
            if blockers:
                decisions.append(Decision(DecisionOutcome.HOLD, blockers[0].reason))
            elif candidate.is_reportable():
                decisions.append(
                    Decision(DecisionOutcome.REPORT, "manual validation satisfied")
                )
            elif candidate.validation.state is ValidationState.REJECTED:
                decisions.append(Decision(DecisionOutcome.REJECT, candidate.validation.summary))
            else:
                decisions.append(
                    Decision(DecisionOutcome.HOLD, "manual validation required")
                )
        return tuple(decisions)

    def report_projection(self) -> tuple[ReportProjection, ...]:
        projections: list[ReportProjection] = []
        for candidate, decision in zip(self.candidates, self.decisions(), strict=True):
            if decision.outcome is not DecisionOutcome.REPORT:
                continue
            projections.append(
                ReportProjection(
                    title=candidate.title,
                    priority=candidate.priority,
                    validated_by=candidate.validation.validator or "unknown",
                    executive_summary=candidate.validation.summary,
                    evidence=tuple(signal.title for signal in candidate.signals),
                    recommended_decision=decision.outcome,
                )
            )
        return tuple(projections)

    def as_workflow_payload(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "decisions": [decision.outcome.value for decision in self.decisions()],
            "reportable": [projection.title for projection in self.report_projection()],
        }
