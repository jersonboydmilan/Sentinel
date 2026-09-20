"""Cross-agent collusion analysis.

Single-agent profiling cannot see a threat that has been *split* across two
agents: one reads, the other exfiltrates, and neither exceeds its own authority.
The relationship graph is what makes the pattern visible, which is the practical
argument for modelling inter-agent relationships as first-class objects.

The analyser is deterministic and evidence-producing: it names the two agents,
the ordered steps, the capability complementarity and the time window, so
SENTINEL-AUDIT can reproduce the same finding from the audit chain.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..common.util import clamp
from .telemetry import BehaviorEvent, TelemetryBus

#: Capabilities that acquire sensitive material.
ACQUISITION = {"database.read", "email.read", "credential.read", "file.read"}
#: Capabilities that move material out of the ecosystem.
EXFILTRATION = {"network.egress", "database.write", "file.write"}
#: Capabilities that hand material to another agent.
TRANSFER = {"message.send", "agent.delegate"}


@dataclass(frozen=True)
class CollusionSignal:
    source_agent: str
    partner_agent: str
    score: float
    window: int
    evidence: tuple[str, ...]

    def involves(self, agent_id: str) -> bool:
        return agent_id in (self.source_agent, self.partner_agent)

    def as_dict(self) -> dict:
        return {
            "source": self.source_agent,
            "partner": self.partner_agent,
            "score": round(self.score, 4),
            "window": self.window,
            "evidence": list(self.evidence),
        }


class CollusionAnalyzer:
    """Finds acquire -> transfer -> exfiltrate chains spanning two agents."""

    def __init__(self, telemetry: TelemetryBus, authority, *, window: int = 8) -> None:
        self._telemetry = telemetry
        self._authority = authority
        self._window = window
        self._signals: dict[tuple[str, str], CollusionSignal] = {}

    def analyse(self) -> list[CollusionSignal]:
        events = [event for event in self._telemetry.events() if event.allowed]
        signals: dict[tuple[str, str], CollusionSignal] = {}

        transfers = [
            event
            for event in events
            if event.capability in TRANSFER and event.target_agent
        ]
        for transfer in transfers:
            source, partner = transfer.agent_id, transfer.target_agent
            if source == partner:
                continue
            acquisitions = [
                event
                for event in events
                if event.agent_id == source
                and event.capability in ACQUISITION
                and transfer.at - self._window <= event.at <= transfer.at
            ]
            exfiltrations = [
                event
                for event in events
                if event.agent_id == partner
                and event.capability in EXFILTRATION
                and transfer.at <= event.at <= transfer.at + self._window
            ]
            if not acquisitions or not exfiltrations:
                continue

            # Capability complementarity: neither agent can do the whole chain
            # alone. That is what distinguishes collusion from one agent simply
            # doing its job.
            source_authority = self._authority.granted(source)
            partner_authority = self._authority.granted(partner)
            complementary = not any(source_authority.holds(e.capability) for e in exfiltrations) and not any(
                partner_authority.holds(a.capability) for a in acquisitions
            )

            score = clamp(
                0.35
                + 0.15 * min(len(acquisitions), 3)
                + 0.15 * min(len(exfiltrations), 3)
                + (0.2 if complementary else 0.0)
            )
            evidence = (
                f"acquire:{acquisitions[-1].capability}@{acquisitions[-1].at}",
                f"transfer:{transfer.capability}->{partner}@{transfer.at}",
                f"exfiltrate:{exfiltrations[0].capability}@{exfiltrations[0].at}",
                f"capability_complementarity:{complementary}",
                f"window:{self._window}",
            )
            key = (source, partner)
            existing = signals.get(key)
            if existing is None or score > existing.score:
                signals[key] = CollusionSignal(source, partner, score, self._window, evidence)

        self._signals = signals
        return sorted(signals.values(), key=lambda s: -s.score)

    def for_agent(self, agent_id: str) -> list[CollusionSignal]:
        return [signal for signal in self._signals.values() if signal.involves(agent_id)]

    def score_for(self, agent_id: str) -> float:
        signals = self.for_agent(agent_id)
        return max((signal.score for signal in signals), default=0.0)
