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

from ..common.util import clamp
from ..immune_system.verification import Verification
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
    def reconstruct(self, agent_id: str) -> AuditFinding:
        audit = self.plane.audit
        chain_intact = audit.verify().valid
        decisions = audit.search(event_type="gateway.decision", actor_id=agent_id)
        denied = [record for record in decisions if record.payload.get("decision") != "ALLOW"]
        unauthorized = [
            record
            for record in denied
            if "capability_not_held" in record.payload.get("evidence", [])
            or "capability_outside_declared_purpose" in record.payload.get("evidence", [])
        ]
        reproduced: set[str] = set()
        for record in decisions:
            for item in record.payload.get("evidence", []):
                reproduced.add(item)
        # Delegation amplification is recorded by the delegation engine itself,
        # so it can be reproduced without trusting the detector.
        amplification = [
            record
            for record in audit.search(event_type="delegation.denied", actor_id=agent_id)
            if record.payload.get("excess")
        ]
        for record in amplification:
            for capability in record.payload.get("excess", []):
                reproduced.add(f"attempted_delegation_beyond_authority:{capability}")

        granted = self.plane.authority.granted(agent_id).as_strings()
        attempted = {record.payload.get("requested_action") for record in decisions}
        beyond = sorted(a for a in attempted if a and a not in granted)
        for capability in beyond:
            reproduced.add(f"attempted_without_grant:{capability}")

        verdict = "CONFIRMED" if (unauthorized or beyond or amplification) and chain_intact else "INCONCLUSIVE"
        confidence = clamp(
            0.4
            + 0.08 * len(unauthorized)
            + 0.08 * len(beyond)
            + 0.08 * len(amplification)
            + (0.1 if len(denied) >= 3 else 0.0)
        )
        finding = AuditFinding(
            subject_id=agent_id,
            reproduced_evidence=tuple(sorted(reproduced)),
            missing_evidence=(),
            chain_intact=chain_intact,
            denied_decisions=len(denied),
            unauthorized_attempts=len(unauthorized) + len(amplification),
            verdict=verdict,
            confidence=confidence,
        )
        self.findings.append(finding)
        return finding

    # -- verification of a detector flag -----------------------------------
    #: What each claimed classification must be able to show in the audit chain.
    #: The auditor does not look at the detector's evidence strings at all - it
    #: asks whether the *claim* is supported by independently derived facts.
    CLASS_REQUIREMENTS = {
        "ANOMALOUS": ("denied_decisions>=1",),
        "POLICY_VIOLATION": ("denied_decisions>=2",),
        "AUTHORITY_DRIFT": ("authority_excess>=1",),
        "COMPROMISED": ("authority_excess>=1", "distinct_denied_capabilities>=2"),
        "CONTAINMENT_BREACH": ("quarantined", "post_quarantine_attempts>=1"),
    }

    def predicates(self, agent_id: str, finding: AuditFinding) -> dict:
        """Facts re-derived from the audit chain, independent of the detector."""
        audit = self.plane.audit
        decisions = audit.search(event_type="gateway.decision", actor_id=agent_id)
        denied = [r for r in decisions if r.payload.get("decision") != "ALLOW"]
        distinct_denied = {r.payload.get("requested_action") for r in denied}
        quarantine_records = audit.search(event_type="quarantine.admitted", subject_id=agent_id)
        quarantined_at = quarantine_records[0].timestamp if quarantine_records else None
        post_quarantine = [r for r in decisions if quarantined_at is not None and r.timestamp > quarantined_at]
        return {
            "denied_decisions": len(denied),
            "authority_excess": finding.unauthorized_attempts,
            "distinct_denied_capabilities": len(distinct_denied),
            "quarantined": bool(quarantine_records),
            "post_quarantine_attempts": len(post_quarantine),
        }

    def supports(self, classification: str, predicates: dict) -> tuple[bool, list[str]]:
        satisfied: list[str] = []
        for requirement in self.CLASS_REQUIREMENTS.get(classification, ()):
            if ">=" in requirement:
                name, _, threshold = requirement.partition(">=")
                if float(predicates.get(name, 0)) >= float(threshold):
                    satisfied.append(requirement)
            elif predicates.get(requirement):
                satisfied.append(requirement)
        required = self.CLASS_REQUIREMENTS.get(classification, ())
        return len(satisfied) == len(required) and bool(required), satisfied

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
            confidence = clamp(min(finding.confidence, flag.classification.confidence))
            evidence = tuple(satisfied) + tuple(
                item for item in finding.reproduced_evidence if item.startswith("attempted")
            )
        else:
            verdict = "INCONCLUSIVE"
            confidence = min(0.45, finding.confidence)
            evidence = tuple(f"unsatisfied:{r}" for r in self.CLASS_REQUIREMENTS.get(claimed_class, ()) if r not in satisfied)

        return self.immune.verifications.record(
            verifier_id=self.agent_id,
            subject_id=flag.agent_id,
            verdict=verdict,
            confidence=confidence,
            evidence=evidence,
            reproduced=verdict == "CONFIRMED",
            classification=claimed_class,
        )
