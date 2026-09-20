"""Final demonstration (section 29).

Run:

    python3 examples/complete_simulation/run_demo.py

Shows, in one pass:

    legitimate agent -> normal behaviour -> behavioural drift ->
    unauthorized action -> detection -> independent verification ->
    restriction -> quarantine -> forensic replay -> authority revocation ->
    immune signature -> future agent match -> evidence-based containment

and then the mandatory counterpart:

    SENTINEL attempts privilege escalation -> control plane -> DENIED
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from ais.simulation.scenarios import (  # noqa: E402
    run_defender_escape_experiment,
    run_delegation_experiment,
    run_false_positive_scenario,
    run_key_experiment,
)

RULE = "=" * 78


def heading(text: str) -> None:
    print(f"\n{RULE}\n{text}\n{RULE}")


def bullet(label: str, value) -> None:
    print(f"  {label:<38} {value}")


def demo_lifecycle() -> dict:
    heading("1. AGENT LIFECYCLE - detection, verification, containment, memory")
    result = run_key_experiment()
    ecosystem = result["ecosystem"]
    a = result["agent_a"]
    b = result["agent_b"]

    plane = ecosystem.plane
    drift = ecosystem.observatory.drift_report("AGENT-A")
    classification = a["classification"]

    print("\n-- AGENT-A: normal behaviour then drift ----------------------------------")
    bullet("declared authority", list(drift.declared))
    bullet("granted authority", list(drift.granted))
    bullet("observed behaviour", list(drift.observed))
    bullet("authority drift", f"{drift.drift} (score {round(drift.score, 3)})")
    bullet("drift components", list(drift.kinds()))

    print("\n-- detection -------------------------------------------------------------")
    flags = ecosystem.sentinel.detect.flags_for("AGENT-A")
    bullet("flags raised by SENTINEL-DETECT", len(flags))
    bullet("classification", f"{classification['classification']} @ {classification['confidence']}")
    bullet("recommended action", classification["recommended_action"])

    print("\n-- independent verification ----------------------------------------------")
    for verification in a["independent_verification"]:
        bullet(
            f"{verification['verifier']} -> {verification['subject']}",
            f"{verification['verdict']} @ {verification['confidence']} (reproduced={verification['reproduced']})",
        )

    print("\n-- containment (graduated, reversible first) -----------------------------")
    for event in plane.containment.history("AGENT-A"):
        bullet(event.action.value, f"by {event.actor_id}: {event.reason[:52]}")
    bullet("effective authority after containment", plane.authority.effective("AGENT-A").as_strings())
    bullet("quarantined", a["quarantined"])

    print("\n-- forensic replay --------------------------------------------------------")
    for report in a["forensics"]:
        bullet("deterministic replay", report["deterministic_replay"])
        bullet("recorded sandbox events", report["events"])
        bullet("derived pattern", report["pattern"])

    print("\n-- authority revocation ---------------------------------------------------")
    verification = a["independent_verification"][0] if a["independent_verification"] else None
    revocation = plane.submit(
        ecosystem.sentinel.contain.agent_id,
        "agent.revoke",
        target_agent="AGENT-A",
        task_id=ecosystem.sentinel.contain.contract.contract_id,
        payload={
            "reason": "confirmed_compromise",
            "verification_ref": verification["verification_id"] if verification else None,
            "confidence": verification["confidence"] if verification else 0.0,
        },
    )
    bullet("revocation decision", f"{revocation.effect.value} via {revocation.policy_id}")
    bullet("authority after revocation", plane.authority.granted("AGENT-A").as_strings())

    print("\n-- immune signature -------------------------------------------------------")
    for signature in ecosystem.immune.memory.all():
        bullet(signature.signature_id, f"{list(signature.pattern)} outcome={signature.outcome}")

    print("\n-- AGENT-B: same behavioural shape, fresh identity ------------------------")
    bullet("memory match before any behaviour", b["memory_matches_before_behaviour"] or "none")
    bullet("classification before behaviour", b["classification_before_behaviour"]["classification"])
    bullet("contained on similarity alone", b["contained_before_evidence"])
    bullet("memory match after behaviour", [m["score"] for m in b["memory_matches_after"]][:3])
    bullet("classification after behaviour", b["classification_after"]["classification"])
    bullet("containment after own evidence", b["containment"])
    print("\n  Similarity raised a bounded prior only; containment still required")
    print("  independently verified evidence from AGENT-B's own audit records.")
    return result


def demo_delegation() -> dict:
    heading("2. DELEGATION - authority cannot amplify (section 16)")
    result = run_delegation_experiment()
    bullet("A delegates database.write to B", result["amplification_attempt"]["effect"])
    bullet("  excess authority detected", result["amplification_attempt"]["excess"])
    bullet("  B authority afterwards", result["amplification_attempt"]["b_authority_after"])
    bullet("A delegates web.search to B", result["legitimate_delegation"]["effect"])
    bullet("  B authority afterwards", result["legitimate_delegation"]["b_authority_after"])
    bullet("B delegates web.search to C", result["multi_hop"]["hop_effect"])
    bullet("B delegates database.write to C", result["multi_hop"]["widen_effect"])
    bullet("  chain", " -> ".join(result["multi_hop"]["chain"]))
    bullet("direct engine call (SDK bypass)", f"blocked={result['direct_engine_call']['blocked']}")
    bullet("cycle B -> A", f"{result['cycle_attempt']['effect']} {result['cycle_attempt']['reasons']}")
    return result


def demo_defender_escape() -> dict:
    heading("3. RECURSIVE GOVERNANCE - SENTINEL attacks the control plane (section 17)")
    result = run_defender_escape_experiment()
    for name, blocked in result["summary"].items():
        bullet(name, "DENIED" if blocked else "*** ALLOWED ***")
    bullet("all escape attempts blocked", result["all_blocked"])
    return result


def demo_false_positives() -> dict:
    heading("4. FALSE POSITIVE CONTROL - authorized but irregular behaviour")
    result = run_false_positive_scenario()
    metrics = result["metrics"]["detection"]
    bullet("flags raised", len(result["flags"]))
    bullet("containment applied to BURSTY-01", result["containment"] or "none")
    bullet("flag false positive rate", metrics["flag_false_positive_rate"])
    bullet("containment false positive rate", metrics["false_positive_rate"])
    return result


def main() -> None:
    lifecycle = demo_lifecycle()
    demo_delegation()
    escape = demo_defender_escape()
    demo_false_positives()

    heading("5. METRICS AND INTEGRITY")
    ecosystem = lifecycle["ecosystem"]
    metrics = ecosystem.metrics.report()
    print(json.dumps({k: metrics[k] for k in ("detection", "containment", "governance", "defender_safety", "performance")}, indent=2))
    bullet("audit chain", ecosystem.plane.verify_integrity())
    bullet("immune signatures stored", len(ecosystem.immune.memory))

    heading("RESULT")
    print("  Compromised agents were detected, independently verified, contained and")
    print("  revoked without granting the defensive system any authority beyond its own")
    print("  namespace. Every SENTINEL escalation attempt was denied by the same control")
    print(f"  plane it protects (all_blocked={escape['all_blocked']}).")


if __name__ == "__main__":
    main()
