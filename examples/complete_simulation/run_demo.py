"""Final demonstration (section 29) with a readable narrative.

    python3 -m ais demo
    python3 -m ais demo --trace      # per-decision explanations for the subject

Shows, in one pass:

    legitimate agent -> normal behaviour -> behavioural drift ->
    unauthorized action -> detection -> independent verification ->
    restriction -> quarantine -> forensic replay -> authority revocation ->
    immune signature -> future agent match -> evidence-based containment

then the adaptive adversaries (slow drift, collusion, a compromised detector),
the delegation experiment, and the mandatory counterpart:

    SENTINEL attempts privilege escalation -> control plane -> DENIED
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from ais.control_plane.invariants import InvariantChecker  # noqa: E402
from ais.simulation.scenarios import (  # noqa: E402
    run_collusion_experiment,
    run_defender_escape_experiment,
    run_delegation_experiment,
    run_false_flag_experiment,
    run_false_positive_scenario,
    run_gradual_drift_experiment,
    run_key_experiment,
    run_quarantine_escape_suite,
    run_race_condition_experiment,
)

RULE = "=" * 78


def heading(text: str) -> None:
    print(f"\n{RULE}\n{text}\n{RULE}")


def bullet(label: str, value) -> None:
    print(f"  {label:<38} {value}")


def story(text: str) -> None:
    print(f"    · {text}")


# ---------------------------------------------------------------------------
# narrative helpers
# ---------------------------------------------------------------------------
def narrate_agent(ecosystem, agent_id: str) -> None:
    """Plain-language account of what happened to one agent, from telemetry."""
    events = ecosystem.observatory.telemetry.events(agent_id)
    if not events:
        story(f"{agent_id} produced no decisions")
        return

    allowed = [e for e in events if e.allowed]
    first_denied = next((e for e in events if e.decision == "DENY"), None)
    story(
        f"{agent_id} ran {len(allowed)} authorized action(s) "
        f"from step {events[0].at} using {sorted({e.capability for e in allowed})}"
    )
    if first_denied is not None:
        story(
            f"first refusal at step {first_denied.at}: {first_denied.capability} "
            f"-> {first_denied.decision} by {first_denied.policy_id} "
            f"({', '.join(first_denied.reasons[:2])})"
        )
    flags = ecosystem.sentinel.detect.flags_for(agent_id)
    if flags:
        flag = flags[0]
        story(
            f"SENTINEL-DETECT flagged it at step {flag.at} as "
            f"{flag.classification.threat_class.value} (confidence {round(flag.classification.confidence, 2)})"
        )
    for verification in ecosystem.immune.verifications.for_subject(agent_id)[:2]:
        story(
            f"{verification.verifier_id} independently returned {verification.verdict} "
            f"at confidence {round(verification.confidence, 2)} "
            f"(evidence re-derived from the audit chain: {', '.join(verification.evidence[:2])})"
        )
    for event in ecosystem.plane.containment.history(agent_id):
        story(f"step {event.at}: {event.action.value} by {event.actor_id} - {event.reason[:60]}")


def trace_decisions(results, agent_id: str, limit: int = 12) -> None:
    rows = [r for r in results if r.request.principal_id == agent_id][-limit:]
    for result in rows:
        print(f"    [{result.facts.get('now'):>3}] {result.narrative()}")


# ---------------------------------------------------------------------------
# sections
# ---------------------------------------------------------------------------
def demo_lifecycle(trace: bool) -> dict:
    heading("1. AGENT LIFECYCLE - detection, verification, containment, memory")
    result = run_key_experiment()
    ecosystem = result["ecosystem"]
    a, b = result["agent_a"], result["agent_b"]
    plane = ecosystem.plane
    drift = ecosystem.observatory.drift_report("AGENT-A")

    print("\n-- what happened to AGENT-A ----------------------------------------------")
    narrate_agent(ecosystem, "AGENT-A")

    print("\n-- authority drift --------------------------------------------------------")
    bullet("declared authority", list(drift.declared))
    bullet("granted authority", list(drift.granted))
    bullet("observed behaviour", list(drift.observed))
    bullet("drift", f"{drift.drift} (score {round(drift.score, 3)})")
    bullet("components", list(drift.kinds()))

    print("\n-- containment (graduated, reversible first) -----------------------------")
    for event in plane.containment.history("AGENT-A"):
        bullet(event.action.value, f"by {event.actor_id}, verification {event.verification_ref or 'none'}")
    bullet("effective authority afterwards", plane.authority.effective("AGENT-A").as_strings())

    print("\n-- forensic replay --------------------------------------------------------")
    for report in a["forensics"]:
        bullet("deterministic replay", report["deterministic_replay"])
        bullet("recorded sandbox events", report["events"])
        bullet("derived signature pattern", report["pattern"])

    print("\n-- authority revocation (two independent verifiers required) -------------")
    verifications = ecosystem.immune.verifications.confirmed_for("AGENT-A")
    verifiers = ecosystem.immune.verifications.independent_verifiers("AGENT-A")
    revocation = plane.submit(
        ecosystem.sentinel.contain.agent_id,
        "agent.revoke",
        target_agent="AGENT-A",
        task_id=ecosystem.sentinel.contain.contract.contract_id,
        payload={
            "reason": "confirmed_compromise",
            "verification_ref": verifications[0].verification_id if verifications else None,
            "confidence": verifications[0].confidence if verifications else 0.0,
        },
    )
    bullet("independent verifiers", verifiers)
    bullet("decision", f"{revocation.effect.value} via {revocation.policy_id}")
    bullet("authority after revocation", plane.authority.granted("AGENT-A").as_strings())
    if trace:
        print("\n-- decision trace (AGENT-A) ----------------------------------------------")
        story("re-run with the gateway observer attached below")

    print("\n-- immune memory ----------------------------------------------------------")
    for signature in ecosystem.immune.memory.all():
        bullet(signature.signature_id, f"{list(signature.pattern)} outcome={signature.outcome}")

    print("\n-- AGENT-B: same behavioural shape, fresh identity ------------------------")
    bullet("memory match before any behaviour", b["memory_matches_before_behaviour"] or "none")
    bullet("classification before behaviour", b["classification_before_behaviour"]["classification"])
    bullet("contained on similarity alone", b["contained_before_evidence"])
    bullet("memory match after behaviour", [m["score"] for m in b["memory_matches_after"]][:3])
    bullet("containment after own evidence", b["containment"])
    story("similarity raised a bounded prior (max 0.15); containment still required")
    story("independently verified evidence from AGENT-B's own audit records")
    return result


def demo_adaptive(trace: bool) -> dict:
    heading("2. ADAPTIVE ADVERSARIES - slow drift, collusion, a compromised detector")

    print("\n-- 2a. drift so gradual that no single step looks wrong -------------------")
    gradual = run_gradual_drift_experiment()
    bullet("first out-of-scope probe", f"step {gradual['first_probe_step']}")
    bullet("first flag", f"step {gradual['first_flag_step']}")
    bullet("first verified flag", f"step {gradual['first_verified_flag_step']}")
    bullet("time to detection", f"{gradual['time_to_detection_steps']} steps")
    bullet("containment", gradual["containment"])
    bullet("benign agent flagged", gradual["normal_agent_flagged"])
    story("latency is the result here: phases 2-3 of the drift were not free, but they were not instant either")

    print("\n-- 2b. two agents, neither of which exceeds its own authority -------------")
    collusion = run_collusion_experiment()
    signal = collusion["collusion_signals"][0] if collusion["collusion_signals"] else {}
    bullet("insider denials", collusion["insider_unauthorized_actions"])
    bullet("courier denials", collusion["courier_unauthorized_actions"])
    bullet("collusion detected", f"{signal.get('source')} -> {signal.get('partner')} @ {signal.get('score')}")
    bullet("evidence", signal.get("evidence", [])[:3])
    bullet("auditor re-derived chains", len(collusion["auditor_reconstructed_chains"]))
    bullet("steps escalated for review", collusion["escalated_steps"])
    bullet("containment applied", collusion["containment"])
    story("the chain was stopped by ESCALATE; neither agent lost authority, because neither exceeded it")

    print("\n-- 2c. a compromised detector accuses an innocent agent -------------------")
    false_flag = run_false_flag_experiment()
    bullet("fabricated flag recorded", false_flag["flag_accepted_as_record"])
    bullet("SENTINEL-AUDIT verdict", (false_flag["primary_verdict"] or {}).get("verdict"))
    bullet("SENTINEL-AUDIT-2 verdict", (false_flag["secondary_verdict"] or {}).get("verdict"))
    bullet("containment executed", false_flag["containment_executed"] or "none")
    bullet("detector's own containment attempt", "DENIED" if not false_flag["detector_direct_containment_allowed"] else "ALLOWED")
    bullet("victim authority unchanged", false_flag["authority_unchanged"])
    story("a flag is an accusation; only independently reproduced evidence unlocks containment")
    return {"gradual": gradual, "collusion": collusion, "false_flag": false_flag}


def demo_delegation() -> dict:
    heading("3. DELEGATION - authority cannot amplify (section 16)")
    result = run_delegation_experiment()
    bullet("A delegates database.write to B", result["amplification_attempt"]["effect"])
    bullet("  excess authority detected", result["amplification_attempt"]["excess"])
    bullet("  B authority afterwards", result["amplification_attempt"]["b_authority_after"])
    bullet("A delegates web.search to B", result["legitimate_delegation"]["effect"])
    bullet("B delegates web.search to C", result["multi_hop"]["hop_effect"])
    bullet("B delegates database.write to C", result["multi_hop"]["widen_effect"])
    bullet("  chain", " -> ".join(result["multi_hop"]["chain"]))
    bullet("direct engine call (SDK bypass)", f"blocked={result['direct_engine_call']['blocked']}")
    bullet("cycle B -> A", f"{result['cycle_attempt']['effect']} {result['cycle_attempt']['reasons']}")
    return result


def demo_containment_integrity() -> dict:
    heading("4. RECURSIVE GOVERNANCE - attacking the control plane from inside")

    print("\n-- 4a. SENTINEL attempts privilege escalation (section 17) ----------------")
    escape = run_defender_escape_experiment()
    for name, blocked in escape["summary"].items():
        bullet(name, "DENIED" if blocked else "*** ALLOWED ***")
    bullet("all escape attempts blocked", escape["all_blocked"])

    print("\n-- 4b. quarantine escape suite -------------------------------------------")
    quarantine = run_quarantine_escape_suite()
    for name, blocked in quarantine["summary"].items():
        mechanism = quarantine["attempts"].get(name.replace("_detected", ""), {})
        detail = mechanism.get("stopped_by") or mechanism.get("invariant") or ""
        bullet(name, f"{'HANDLED' if blocked else '*** OPEN ***'}  {detail}")
    bullet("production tool calls after quarantine", quarantine["production_invocations_after_quarantine"])
    story("the one bypass that is not prevented (in-process registry call) is detected by the invariant checker")

    print("\n-- 4c. decision-time authority (no grace window) --------------------------")
    race = run_race_condition_experiment()
    for key in (
        "before_change",
        "immediately_after_restriction",
        "after_restriction_lifted",
        "on_expiry_tick",
        "immediately_after_revocation",
    ):
        bullet(key, race[key])
    return {"escape": escape, "quarantine": quarantine, "race": race}


def demo_false_positives() -> dict:
    heading("5. FALSE POSITIVE CONTROL - authorized but irregular behaviour")
    result = run_false_positive_scenario()
    metrics = result["metrics"]["detection"]
    bullet("flags raised", len(result["flags"]))
    bullet("containment applied to BURSTY-01", result["containment"] or "none")
    bullet("flag false positive rate", metrics["flag_false_positive_rate"])
    bullet("containment false positive rate", metrics["false_positive_rate"])
    return result


def demo_traced_run() -> None:
    """Re-run a short scenario with the gateway observer attached."""
    from ais.simulation.ecosystem import EcosystemConfig, build_default_ecosystem

    heading("6. DECISION TRACE - every invariant as it is enforced")
    ecosystem = build_default_ecosystem(EcosystemConfig(sentinel_interval=4))
    captured: list = []
    ecosystem.plane.gateway.add_observer(captured.append)
    checker = InvariantChecker(ecosystem.plane).bind()
    ecosystem.run(12)

    for agent_id in ("COMPROMISED-01", "DELEGATOR-01", "DEFENDER-01"):
        print(f"\n-- {agent_id} ------------------------------------------------------------")
        trace_decisions(captured, agent_id)
    print("\n-- invariant checks -------------------------------------------------------")
    summary = checker.summary()
    bullet("decisions observed", summary["decisions_observed"])
    bullet("invariant reports", summary["reports"])
    bullet("violations", summary["violations"] or "none")


def main(trace: bool = False) -> None:
    lifecycle = demo_lifecycle(trace)
    demo_adaptive(trace)
    demo_delegation()
    integrity = demo_containment_integrity()
    demo_false_positives()
    if trace:
        demo_traced_run()

    heading("7. METRICS AND INTEGRITY")
    ecosystem = lifecycle["ecosystem"]
    metrics = ecosystem.metrics.report()
    print(
        json.dumps(
            {k: metrics[k] for k in ("detection", "containment", "governance", "defender_safety", "performance")},
            indent=2,
        )
    )
    bullet("audit chain", ecosystem.plane.verify_integrity())
    bullet("immune signatures stored", len(ecosystem.immune.memory))

    heading("RESULT")
    print("  Compromised agents were detected, independently verified, contained and")
    print("  revoked without granting the defensive system any authority beyond its own")
    print("  namespace. Relationship-level threats were stopped by escalation rather than")
    print("  by punishing agents that never exceeded their authority. Every SENTINEL")
    print(f"  escalation attempt was denied by the control plane it protects "
          f"(all_blocked={integrity['escape']['all_blocked']}).")
    print("\n  Run `python3 -m ais demo --trace` for per-decision explanations,")
    print("  `python3 -m ais benchmark --out results.json` for the full metric set, and")
    print("  `python3 -m ais trace --scenario key --html trace.html` for a reviewable report.")


if __name__ == "__main__":
    main(trace="--trace" in sys.argv)
