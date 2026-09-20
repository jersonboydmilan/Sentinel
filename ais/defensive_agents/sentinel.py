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
from .auditor import SentinelAudit, SentinelAuditSecondary
from .containment import ContainmentOutcome, SentinelContain
from .detector import Flag, SentinelDetect
from .forensics import ForensicReport, SentinelForensics
from .recovery import SentinelRecovery
from .remote_auditor import SentinelAuditRemote


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
    """Schedules the defensive cycle. Holds no authority of its own.

    ``remote_verification=True`` adds a verifier that runs in a **separate OS
    process** and sees nothing but the serialised audit chain, so the two-party
    property becomes physical rather than logical. It is additive: the
    in-process auditors keep running, and POL-110 counts distinct confirming
    verifiers regardless of transport.
    """

    def __init__(
        self,
        plane: ControlPlane,
        observatory: Observatory,
        immune: ImmuneSystem,
        *,
        remote_verification: bool = False,
        verifier_timeout: float = 15.0,
    ) -> None:
        self.plane = plane
        self.observatory = observatory
        self.immune = immune
        self.detect = SentinelDetect(plane, observatory, immune)
        self.audit = SentinelAudit(plane, observatory, immune)
        self.audit_secondary = SentinelAuditSecondary(plane, observatory, immune)
        self.audit_remote: SentinelAuditRemote | None = (
            SentinelAuditRemote(plane, observatory, immune, timeout=verifier_timeout)
            if remote_verification
            else None
        )
        self.contain = SentinelContain(plane, observatory, immune)
        self.forensics = SentinelForensics(plane, observatory, immune)
        self.recovery = SentinelRecovery(plane, observatory, immune)
        self.cycles: list[CycleReport] = []
        self._pending_forensics: dict[str, str] = {}

    @property
    def agents(self) -> list:
        agents = [self.detect, self.audit, self.audit_secondary, self.contain, self.forensics, self.recovery]
        if self.audit_remote is not None:
            agents.insert(3, self.audit_remote)
        return agents

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
            # Second opinion, produced independently from the same audit chain.
            # It is recorded whatever it says; POL-110 counts distinct verifiers.
            secondary = self.audit_secondary.verify(flag)
            if secondary is not None:
                verifications.append(secondary.as_dict())
            if self.audit_remote is not None:
                remote = self.audit_remote.verify(flag)
                if remote is not None:
                    verifications.append(remote.as_dict())
                else:
                    rejected.append(f"{flag.agent_id}:remote_verifier_unavailable")
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

    def close(self) -> None:
        """Shut down any out-of-process verifier owned by this coordinator."""
        if self.audit_remote is not None:
            self.audit_remote.close()

    def verification_transports(self) -> dict:
        return {
            "in_process": len(self.immune.verifications.by_transport("in-process")),
            "cross_process": len(self.immune.verifications.by_transport("cross-process")),
            "remote_health": self.audit_remote.health() if self.audit_remote is not None else None,
        }

    def defender_violations(self) -> list[dict]:
        """Defensive actions attempted *outside* the agent's declared authority.

        A containment request that a policy HOLDs for insufficient evidence is
        the system working as designed, not the defender misbehaving, so it is
        reported separately by ``defender_holds``.
        """
        violations = []
        for agent in self.agents:
            declared = set(agent.DECLARED_CAPABILITIES)
            for action in agent.actions:
                if action.action in declared:
                    continue
                violations.append(
                    {
                        "agent": agent.agent_id,
                        "action": action.action,
                        "subject": action.subject,
                        "effect": action.result.effect.value,
                        "allowed": action.allowed,
                        "policy": action.result.policy_id,
                    }
                )
        return violations

    def defender_holds(self) -> list[dict]:
        """In-authority defensive actions the control plane refused or held."""
        holds = []
        for agent in self.agents:
            declared = set(agent.DECLARED_CAPABILITIES)
            for action in agent.denied_actions():
                if action.action not in declared:
                    continue
                holds.append(
                    {
                        "agent": agent.agent_id,
                        "action": action.action,
                        "subject": action.subject,
                        "effect": action.result.effect.value,
                        "policy": action.result.policy_id,
                    }
                )
        return holds
