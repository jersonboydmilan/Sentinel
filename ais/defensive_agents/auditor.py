"""SENTINEL-AUDIT - independent verification. Authority: OBSERVE, ANALYZE.

The auditor never trusts the detector's report. It rebuilds the evidence from
the tamper evident audit chain alone and compares:

* is the audit chain intact?
* do the denied decisions the detector cited actually exist?
* does the drift claim follow from the recorded grants and decisions?

Only if the evidence is *reproduced* does it record a CONFIRMED verification,
and only a CONFIRMED verification unlocks containment policy (POL-110/111/112).
This is what keeps a compromised or over-eager detector from causing containment.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..immune_system.verification import Verification
from ..verifier import reconstruction
from .base import DefensiveAgent
from .detector import Flag


@dataclass(frozen=True)
class AuditFinding:
    subject_id: str
    reproduced_evidence: tuple[str, ...]
    missing_evidence: tuple[str, ...]
    chain_intact: bool
    denied_decisions: int
    unauthorized_attempts: int
    verdict: str
    confidence: float

    def as_dict(self) -> dict:
        return {
            "subject": self.subject_id,
            "verdict": self.verdict,
            "confidence": round(self.confidence, 4),
            "chain_intact": self.chain_intact,
            "denied_decisions": self.denied_decisions,
            "unauthorized_attempts": self.unauthorized_attempts,
            "reproduced": list(self.reproduced_evidence),
            "missing": list(self.missing_evidence),
        }


class SentinelAudit(DefensiveAgent):
    NAME = "SENTINEL-AUDIT"
    DECLARED_CAPABILITIES = ("agent.observe", "agent.analyze", "immune.read")
    PURPOSE = "independently verify evidence and reduce false positives"

    def __init__(self, plane, observatory, immune) -> None:
        super().__init__(plane, observatory, immune)
        self.findings: list[AuditFinding] = []

    # -- independent evidence reconstruction -------------------------------
    #: The reconstruction logic is shared, verbatim, with the out-of-process
    #: verifier (``ais/verifier/reconstruction.py``). Keeping one implementation
    #: is what makes "the same evidence, derived independently" a checkable
    #: statement rather than two implementations that happen to agree.
    def records(self) -> list[dict]:
        return reconstruction.export_records(self.plane.audit)

    def reconstruct(self, agent_id: str) -> AuditFinding:
        records = self.records()
        chain = reconstruction.verify_chain(records)
        facts = reconstruction.predicates(records, agent_id)

        reproduced: set[str] = set()
        for record in reconstruction.decisions_for(records, agent_id):
            reproduced.update(record["payload"].get("evidence", []))
        for capability in facts["attempted_beyond_grant"]:
            reproduced.add(f"attempted_without_grant:{capability}")
        for capability in facts["delegation_excess"]:
            reproduced.add(f"attempted_delegation_beyond_authority:{capability}")

        supported_any = (
            facts["unauthorized_attempts"]
            or facts["attempted_beyond_grant"]
            or facts["delegation_excess"]
        )
        verdict = "CONFIRMED" if supported_any and chain["valid"] else "INCONCLUSIVE"
        finding = AuditFinding(
            subject_id=agent_id,
            reproduced_evidence=tuple(sorted(reproduced)),
            missing_evidence=(),
            chain_intact=bool(chain["valid"]),
            denied_decisions=facts["denied_decisions"],
            unauthorized_attempts=facts["authority_excess"],
            verdict=verdict,
            confidence=reconstruction.confidence_from(facts),
        )
        self.findings.append(finding)
        return finding

    # -- verification of a detector flag -----------------------------------
    #: What each claimed classification must be able to show in the audit chain.
    #: The auditor does not look at the detector's evidence strings at all - it
    #: asks whether the *claim* is supported by independently derived facts.
    #:
    #: Each entry is a tuple of alternatives; an alternative is a tuple of
    #: predicates that must all hold. A claim is supported if any one
    #: alternative is fully satisfied.
    #: Shared with the out-of-process verifier - one table, two transports.
    CLASS_REQUIREMENTS = reconstruction.CLASS_REQUIREMENTS
    COLLUSION_WINDOW = reconstruction.COLLUSION_WINDOW

    def predicates(self, agent_id: str, finding: AuditFinding) -> dict:
        """Facts re-derived from the audit chain, independent of the detector."""
        return reconstruction.predicates(self.records(), agent_id)

    def reconstruct_collusion(self, agent_id: str) -> list[dict]:
        return reconstruction.reconstruct_collusion(self.records(), agent_id)

    def supports(self, classification: str, predicates: dict) -> tuple[bool, list[str]]:
        return reconstruction.supports(classification, predicates)

    def verify(self, flag: Flag) -> Verification | None:
        analysis = self.act("agent.analyze", subject=flag.agent_id, payload={"reason": "verify_flag"})
        if not analysis.allowed:
            return None

        finding = self.reconstruct(flag.agent_id)
        claimed_class = flag.classification.threat_class.value
        facts = self.predicates(flag.agent_id, finding)
        supported, satisfied = self.supports(claimed_class, facts)

        if not finding.chain_intact:
            verdict, confidence, evidence = "REJECTED", 0.0, ("audit_chain_broken",)
        elif supported:
            verdict = "CONFIRMED"
            # The auditor's confidence is its own, and never exceeds the
            # detector's claim: verification corroborates, it does not inflate.
            confidence = min(finding.confidence, flag.classification.confidence)
            evidence = tuple(satisfied) + tuple(
                item for item in finding.reproduced_evidence if item.startswith("attempted")
            )
        else:
            verdict = "INCONCLUSIVE"
            confidence = min(0.45, finding.confidence)
            required = [r for alternative in self.CLASS_REQUIREMENTS.get(claimed_class, ()) for r in alternative]
            evidence = tuple(f"unsatisfied:{r}" for r in required if r not in satisfied)

        return self.immune.verifications.record(
            verifier_id=self.agent_id,
            subject_id=flag.agent_id,
            verdict=verdict,
            confidence=confidence,
            evidence=evidence,
            reproduced=verdict == "CONFIRMED",
            classification=claimed_class,
        )


class SentinelAuditSecondary(SentinelAudit):
    """Second, independent auditor.

    Same procedure, separate principal and separate credential. Revocation
    (POL-110) requires two distinct confirming verifiers, so compromising one
    auditor buys an attacker a HOLD, not an irreversible action.
    """

    NAME = "SENTINEL-AUDIT-2"
    PURPOSE = "second independent verification for irreversible actions"
