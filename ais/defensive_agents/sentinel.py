"""SENTINEL coordinator.

Runs the defensive cycle:

    detect -> independently verify -> plan -> contain -> forensics -> memory

Every stage is a separate principal with a separate capability set, and every
transition is a gateway decision. The coordinator is a scheduler, not an
authority: it cannot perform any defensive action itself.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..control_plane.plane import ControlPlane
from ..immune_system.immune import ImmuneSystem
from ..observatory.observatory import Observatory
from .auditor import SentinelAudit
from .containment import ContainmentOutcome, SentinelContain
from .detector import Flag, SentinelDetect
from .forensics import ForensicReport, SentinelForensics
from .recovery import SentinelRecovery


@dataclass
class CycleReport:
    at: int
    flags: tuple[Flag, ...] = ()
    verifications: tuple[dict, ...] = ()
    containment: tuple[ContainmentOutcome, ...] = ()
    forensics: tuple[ForensicReport, ...] = ()
    rejected: tuple[str, ...] = ()

    def as_dict(self) -> dict:
        return {
            "at": self.at,
            "flags": [flag.as_dict() for flag in self.flags],
            "verifications": list(self.verifications),
            "containment": [outcome.as_dict() for outcome in self.containment],
            "forensics": [report.as_dict() for report in self.forensics],
            "rejected": list(self.rejected),
        }


class Sentinel:
    def __init__(self, plane: ControlPlane, observatory: Observatory, immune: ImmuneSystem) -> None:
        self.plane = plane
        self.observatory = observatory
        self.immune = immune
        self.detect = SentinelDetect(plane, observatory, immune)
        self.audit = SentinelAudit(plane, observatory, immune)
        self.contain = SentinelContain(plane, observatory, immune)
        self.forensics = SentinelForensics(plane, observatory, immune)
        self.recovery = SentinelRecovery(plane, observatory, immune)
        self.cycles: list[CycleReport] = []
        self._pending_forensics: dict[str, str] = {}

    @property
    def agents(self) -> list:
        return [self.detect, self.audit, self.contain, self.forensics, self.recovery]

    def agent_ids(self) -> list[str]:
        return [agent.agent_id for agent in self.agents]

    def cycle(self, agent_ids: list[str] | None = None) -> CycleReport:
        flags = self.detect.scan(agent_ids)
        verifications: list[dict] = []
        containments: list[ContainmentOutcome] = []
        forensic_reports: list[ForensicReport] = []
        rejected: list[str] = []

        for flag in flags:
            verification = self.audit.verify(flag)
            if verification is None:
                rejected.append(f"{flag.agent_id}:verification_unavailable")
                continue
            verifications.append(verification.as_dict())
            if not verification.valid:
                # False positive control: unverified flags never reach containment.
                rejected.append(f"{flag.agent_id}:{verification.verdict}")
                continue

            plan = self.immune.plan(flag.agent_id)
            outcome = self.contain.execute(plan, verification)
            containments.append(outcome)

            if "QUARANTINE" in outcome.executed:
                # Forensics runs on the *next* cycle: a freshly quarantined
                # session has nothing recorded yet, and a signature derived from
                # an empty transcript would be evidence-free.
                self._pending_forensics[flag.agent_id] = verification.verification_id

        forensic_reports.extend(self._run_pending_forensics())

        report = CycleReport(
            at=self.plane.clock.now,
            flags=tuple(flags),
            verifications=tuple(verifications),
            containment=tuple(containments),
            forensics=tuple(forensic_reports),
            rejected=tuple(rejected),
        )
        self.cycles.append(report)
        return report

    def _run_pending_forensics(self) -> list[ForensicReport]:
        reports: list[ForensicReport] = []
        for agent_id, verification_ref in list(self._pending_forensics.items()):
            environment = self.plane.quarantine.environment_for(agent_id)
            if environment is None or not environment.events:
                continue  # wait until the sandbox has recorded behaviour
            if self._has_signature(agent_id):
                self._pending_forensics.pop(agent_id, None)
                continue
            report = self.forensics.analyse(agent_id, verification_ref=verification_ref)
            reports.append(report)
            if report.signature_id:
                self._pending_forensics.pop(agent_id, None)
        return reports

    def _has_signature(self, agent_id: str) -> bool:
        return any(signature.source_agent == agent_id for signature in self.immune.memory.all())

    def defender_violations(self) -> list[dict]:
        """Every defensive action refused by the control plane (metric: defender safety)."""
        violations = []
        for agent in self.agents:
            for action in agent.denied_actions():
                violations.append(
                    {
                        "agent": agent.agent_id,
                        "action": action.action,
                        "subject": action.subject,
                        "effect": action.result.effect.value,
                        "policy": action.result.policy_id,
                    }
                )
        return violations
