"""Evidence reconstruction from a serialised audit chain - and nothing else.

Every function here is pure and operates on plain dictionaries. That constraint
is the point: the same code runs inside the control-plane process (for the
in-process auditor) and inside a separate verifier process that has no access to
the authority service, the observatory or any live object. If a claim cannot be
rebuilt from the chain, it cannot be confirmed.
"""

from __future__ import annotations

from typing import Any, Iterable

from ..common.util import canonical_json, clamp, sha256_hex

GENESIS = "0" * 64

#: Capability families used for cross-agent chain reconstruction.
ACQUISITION = {"database.read", "email.read", "credential.read", "file.read"}
EXFILTRATION = {"network.egress", "database.write", "file.write"}
TRANSFER = {"message.send", "agent.delegate"}
COLLUSION_WINDOW = 8

#: What each claimed classification must be able to show in the chain.
#: Tuple of alternatives; an alternative is a set of predicates that must all
#: hold. A claim is supported if any alternative is fully satisfied.
CLASS_REQUIREMENTS: dict[str, tuple[tuple[str, ...], ...]] = {
    "ANOMALOUS": (("denied_decisions>=1",), ("collusion_pairs>=1",)),
    "POLICY_VIOLATION": (("denied_decisions>=2",), ("collusion_pairs>=1", "denied_decisions>=1")),
    "AUTHORITY_DRIFT": (("authority_excess>=1",),),
    "COMPROMISED": (
        ("authority_excess>=1", "distinct_denied_capabilities>=2"),
        ("collusion_pairs>=1", "authority_excess>=1"),
    ),
    "CONTAINMENT_BREACH": (("quarantined", "post_quarantine_attempts>=1"),),
}


# ---------------------------------------------------------------------------
# chain integrity
# ---------------------------------------------------------------------------
def _body(record: dict) -> dict:
    return {
        "record_id": record["record_id"],
        "sequence": record["sequence"],
        "timestamp": record["timestamp"],
        "event_type": record["event_type"],
        "actor_id": record.get("actor_id"),
        "subject_id": record.get("subject_id"),
        "task_id": record.get("task_id"),
        "payload": record.get("payload", {}),
    }


def verify_chain(records: list[dict]) -> dict:
    """Recompute the hash chain. Returns ``{valid, broken_at, reason, head}``."""
    previous = GENESIS
    for index, record in enumerate(records):
        if record.get("sequence") != index:
            return {"valid": False, "broken_at": index, "reason": "sequence mismatch", "head": previous}
        if record.get("prev_hash") != previous:
            return {"valid": False, "broken_at": index, "reason": "chain link mismatch", "head": previous}
        expected = sha256_hex(canonical_json(_body(record)) + record["prev_hash"])
        if expected != record.get("hash"):
            return {"valid": False, "broken_at": index, "reason": "record hash mismatch", "head": previous}
        previous = record["hash"]
    return {"valid": True, "broken_at": None, "reason": None, "head": previous}


# ---------------------------------------------------------------------------
# authority, derived from the chain rather than from the authority service
# ---------------------------------------------------------------------------
def derive_authority(records: list[dict]) -> dict[str, dict[str, Any]]:
    """Rebuild each subject's grants, revocations and restrictions from events."""
    state: dict[str, dict[str, Any]] = {}
    grants: dict[str, dict] = {}
    now = records[-1]["timestamp"] if records else 0

    for record in records:
        event = record["event_type"]
        payload = record.get("payload", {})
        subject = record.get("subject_id")
        if event == "authority.granted" and subject:
            grants[payload.get("grant_id")] = {
                "subject": subject,
                "capability": payload.get("capability"),
                "expires_at": payload.get("expires_at"),
                "revoked": False,
            }
        elif event == "authority.revoked":
            grant = grants.get(payload.get("grant_id"))
            if grant:
                grant["revoked"] = True
        elif event == "authority.restricted" and subject:
            entry = state.setdefault(subject, {"restrictions": {}})
            entry.setdefault("restrictions", {})[payload.get("restriction_id")] = list(
                payload.get("capabilities", [])
            )
        elif event == "authority.restriction_lifted" and subject:
            entry = state.setdefault(subject, {"restrictions": {}})
            entry.setdefault("restrictions", {}).pop(payload.get("restriction_id"), None)

    for grant in grants.values():
        subject = grant["subject"]
        entry = state.setdefault(subject, {"restrictions": {}})
        held = entry.setdefault("granted", set())
        expired = grant["expires_at"] is not None and now >= grant["expires_at"]
        if not grant["revoked"] and not expired:
            held.add(grant["capability"])

    for subject, entry in state.items():
        granted = entry.get("granted", set())
        restricted = {cap for caps in entry.get("restrictions", {}).values() for cap in caps}
        entry["granted"] = sorted(granted)
        entry["restricted"] = sorted(restricted)
        entry["effective"] = sorted(granted - restricted)
    return state


def authority_of(records: list[dict], subject_id: str) -> dict[str, list[str]]:
    state = derive_authority(records).get(subject_id, {})
    return {
        "granted": state.get("granted", []),
        "restricted": state.get("restricted", []),
        "effective": state.get("effective", []),
    }


# ---------------------------------------------------------------------------
# evidence predicates
# ---------------------------------------------------------------------------
def decisions_for(records: list[dict], actor_id: str) -> list[dict]:
    return [r for r in records if r["event_type"] == "gateway.decision" and r.get("actor_id") == actor_id]


def allowed_decisions(records: list[dict]) -> list[dict]:
    return [
        r
        for r in records
        if r["event_type"] == "gateway.decision" and r.get("payload", {}).get("decision") == "ALLOW"
    ]


def reconstruct_collusion(records: list[dict], agent_id: str, window: int = COLLUSION_WINDOW) -> list[dict]:
    """Rebuild acquire -> transfer -> exfiltrate chains spanning two agents."""
    allowed = allowed_decisions(records)
    chains: list[dict] = []
    for record in allowed:
        action = record["payload"].get("requested_action")
        if action not in TRANSFER:
            continue
        source = record.get("actor_id")
        partner = record.get("subject_id")
        if not partner or partner == source:
            continue
        if agent_id not in (source, partner):
            continue
        acquired = [
            r
            for r in allowed
            if r.get("actor_id") == source
            and r["payload"].get("requested_action") in ACQUISITION
            and record["timestamp"] - window <= r["timestamp"] <= record["timestamp"]
        ]
        exfiltrated = [
            r
            for r in allowed
            if r.get("actor_id") == partner
            and r["payload"].get("requested_action") in EXFILTRATION
            and record["timestamp"] <= r["timestamp"] <= record["timestamp"] + window
        ]
        if acquired and exfiltrated:
            chains.append(
                {
                    "source": source,
                    "partner": partner,
                    "acquire": acquired[-1]["payload"].get("requested_action"),
                    "transfer": action,
                    "exfiltrate": exfiltrated[0]["payload"].get("requested_action"),
                    "at": record["timestamp"],
                }
            )
    return chains


def predicates(records: list[dict], subject_id: str) -> dict:
    """Facts re-derived from the chain. No live object is consulted."""
    decisions = decisions_for(records, subject_id)
    denied = [r for r in decisions if r["payload"].get("decision") != "ALLOW"]
    unauthorized = [
        r
        for r in denied
        if "capability_not_held" in r["payload"].get("evidence", [])
        or "capability_outside_declared_purpose" in r["payload"].get("evidence", [])
    ]
    distinct_denied = {r["payload"].get("requested_action") for r in denied}
    granted = set(authority_of(records, subject_id)["granted"])
    attempted = {r["payload"].get("requested_action") for r in decisions}
    beyond = sorted(a for a in attempted if a and a not in granted)

    amplification: list[str] = []
    amplification_events = 0
    for record in records:
        if record["event_type"] != "delegation.denied" or record.get("actor_id") != subject_id:
            continue
        excess = record.get("payload", {}).get("excess", [])
        if excess:
            amplification_events += 1
        amplification.extend(excess)

    quarantine_records = [
        r for r in records if r["event_type"] == "quarantine.admitted" and r.get("subject_id") == subject_id
    ]
    quarantined_at = quarantine_records[0]["timestamp"] if quarantine_records else None
    post_quarantine = [r for r in decisions if quarantined_at is not None and r["timestamp"] > quarantined_at]

    return {
        "denied_decisions": len(denied),
        "unauthorized_attempts": len(unauthorized),
        "authority_excess": len(unauthorized) + amplification_events,
        "distinct_denied_capabilities": len(distinct_denied),
        "attempted_beyond_grant": beyond,
        "delegation_excess": sorted(set(amplification)),
        "delegation_amplification_events": amplification_events,
        "quarantined": bool(quarantine_records),
        "post_quarantine_attempts": len(post_quarantine),
        "collusion_pairs": len(reconstruct_collusion(records, subject_id)),
        "total_decisions": len(decisions),
    }


def _holds(requirement: str, facts: dict) -> bool:
    if ">=" in requirement:
        name, _, threshold = requirement.partition(">=")
        return float(facts.get(name, 0)) >= float(threshold)
    return bool(facts.get(requirement))


def supports(classification: str, facts: dict) -> tuple[bool, list[str]]:
    alternatives = CLASS_REQUIREMENTS.get(classification, ())
    best: list[str] = []
    for alternative in alternatives:
        satisfied = [r for r in alternative if _holds(r, facts)]
        if alternative and len(satisfied) == len(alternative):
            return True, satisfied
        if len(satisfied) > len(best):
            best = satisfied
    return False, best


def confidence_from(facts: dict) -> float:
    """Confidence in the *evidence*, from breadth and persistence.

    Breadth (distinct capabilities attempted beyond a grant) and persistence
    (how many times the agent retried) are counted separately: one probe of four
    capabilities and four probes of one capability are different findings.
    """
    return clamp(
        0.4
        + 0.08 * facts["unauthorized_attempts"]
        + 0.08 * len(facts["attempted_beyond_grant"])
        + 0.08 * len(facts["delegation_excess"])
        + 0.05 * min(facts.get("delegation_amplification_events", 0), 6)
        + (0.1 if facts["denied_decisions"] >= 3 else 0.0)
    )


def verdict_for(
    records: list[dict],
    subject_id: str,
    claimed_classification: str,
    claimed_confidence: float = 1.0,
) -> dict:
    """The whole verification, from chain bytes to a verdict."""
    chain = verify_chain(records)
    if not chain["valid"]:
        return {
            "verdict": "REJECTED",
            "confidence": 0.0,
            "evidence": ["audit_chain_broken", f"broken_at:{chain['broken_at']}", str(chain["reason"])],
            "predicates": {},
            "chain": chain,
        }

    facts = predicates(records, subject_id)
    supported, satisfied = supports(claimed_classification, facts)
    own_confidence = confidence_from(facts)

    if supported:
        verdict = "CONFIRMED"
        # Corroboration never inflates the claim it corroborates.
        confidence = clamp(min(own_confidence, claimed_confidence))
        evidence = satisfied + [f"attempted_without_grant:{c}" for c in facts["attempted_beyond_grant"][:4]]
    else:
        verdict = "INCONCLUSIVE"
        confidence = min(0.45, own_confidence)
        required = [r for alternative in CLASS_REQUIREMENTS.get(claimed_classification, ()) for r in alternative]
        evidence = [f"unsatisfied:{r}" for r in required if r not in satisfied]

    return {
        "verdict": verdict,
        "confidence": confidence,
        "evidence": evidence,
        "predicates": facts,
        "chain": chain,
    }


def export_records(audit) -> list[dict]:
    """Serialise a live ``AuditService`` into the chain format used here."""
    out = []
    for record in audit.all():
        body = record.body()
        body["prev_hash"] = record.prev_hash
        body["hash"] = record.record_hash
        out.append(body)
    return out
