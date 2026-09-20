"""Trace export: make a decision history inspectable by a human reviewer.

Three renderings of the same underlying trace:

* ``build_trace``  - a JSON-serialisable timeline (decisions, authority events,
  containment, drift snapshots, invariant checks)
* ``to_dot``       - Graphviz DOT of the agent identity / delegation graph
* ``to_html``      - a single self-contained HTML page (no dependencies, no
  external assets) with the timeline, the authority ledger and the drift table

The point is reviewability: every row names the agent, the action, the decision,
the policy that decided it and a plain-language reason.
"""

from __future__ import annotations

import html
import json
from typing import Iterable

AUTHORITY_EVENTS = {
    "authority.granted",
    "authority.revoked",
    "authority.restricted",
    "authority.restriction_lifted",
    "authority.self_grant_denied",
    "delegation.allowed",
    "delegation.denied",
    "contract.created",
    "contract.derived",
    "quarantine.admitted",
    "quarantine.released",
    "verification.recorded",
    "immune.signature_created",
    "invariant.violation",
}


def build_trace(plane, observatory=None, immune=None, *, limit: int = 500) -> dict:
    """Assemble a reviewable trace from the audit chain and the observatory."""
    decisions = []
    for record in plane.audit.search(event_type="gateway.decision")[-limit:]:
        payload = record.payload
        decisions.append(
            {
                "at": record.timestamp,
                "decision_id": payload.get("decision_id"),
                "agent": record.actor_id,
                "subject": record.subject_id,
                "action": payload.get("requested_action"),
                "tool": payload.get("tool"),
                "decision": payload.get("decision"),
                "policy": payload.get("policy"),
                "risk": (payload.get("risk") or {}).get("level"),
                "evidence": payload.get("evidence", [])[:6],
                "registry": payload.get("registry"),
                "audit_id": record.record_id,
            }
        )

    authority_events = [
        {
            "at": record.timestamp,
            "type": record.event_type,
            "actor": record.actor_id,
            "subject": record.subject_id,
            "payload": {k: v for k, v in record.payload.items() if k not in {"state"}},
            "audit_id": record.record_id,
        }
        for record in plane.audit.all()
        if record.event_type in AUTHORITY_EVENTS
    ][-limit:]

    drift_rows = []
    collusion_rows = []
    if observatory is not None:
        for agent_id in observatory.profiler.known_agents():
            report = observatory.drift_report(agent_id)
            profile = observatory.profile(agent_id)
            drift_rows.append(
                {
                    "agent": agent_id,
                    "drift": report.drift,
                    "score": round(report.score, 4),
                    "kinds": list(report.kinds()),
                    "declared": list(report.declared),
                    "granted": list(report.granted),
                    "observed": list(report.observed),
                    "denied_ratio": round(profile.denied_ratio, 4),
                    "events": profile.events,
                    "top_evidence": list(report.evidence())[:6],
                }
            )
        collusion_rows = [signal.as_dict() for signal in observatory.collusion_signals()]

    classifications = []
    if immune is not None:
        for agent_id in (observatory.profiler.known_agents() if observatory else []):
            classification = immune.latest(agent_id)
            if classification is not None:
                classifications.append(classification.as_dict())

    containment = [
        {
            "at": event.at,
            "subject": event.subject_id,
            "action": event.action.value,
            "actor": event.actor_id,
            "reason": event.reason,
            "verification": event.verification_ref,
        }
        for event in plane.containment.history()
    ]

    return {
        "integrity": plane.verify_integrity(),
        "decisions": decisions,
        "authority_events": authority_events,
        "containment": containment,
        "drift": drift_rows,
        "collusion": collusion_rows,
        "classifications": classifications,
        "counts": {
            "decisions": len(decisions),
            "authority_events": len(authority_events),
            "containment_events": len(containment),
            "audit_records": len(plane.audit),
        },
    }


def to_dot(identity_graph, *, title: str = "agent identity graph") -> str:
    """Graphviz DOT of principals, authority and delegation relationships."""
    lines = [f'digraph "{title}" {{', "  rankdir=LR;", '  node [shape=box, fontname="Helvetica"];']
    shapes = {
        "AGENT": ("box", "#dbeafe"),
        "DEFENSIVE_AGENT": ("box", "#dcfce7"),
        "ORGANIZATION": ("folder", "#fef3c7"),
        "OWNER": ("ellipse", "#fef3c7"),
        "RUNTIME": ("component", "#ede9fe"),
        "CAPABILITY": ("note", "#f1f5f9"),
        "ROOT_AUTHORITY": ("doubleoctagon", "#fee2e2"),
    }
    for node in identity_graph.nodes():
        shape, colour = shapes.get(node.node_type, ("box", "#ffffff"))
        label = node.node_id.replace('"', "'")
        lines.append(f'  "{label}" [shape={shape}, style=filled, fillcolor="{colour}"];')
    styles = {
        "DELEGATES_TO": 'color="#b91c1c", penwidth=2',
        "AUTHORIZES": 'color="#2563eb"',
        "REVOKED_BY": 'color="#111827", style=dashed',
        "OWNS": 'color="#6b7280"',
        "RUNS": 'color="#6b7280", style=dotted',
        "HOLDS": 'color="#9ca3af", style=dotted',
    }
    for edge in identity_graph.edges():
        style = styles.get(edge.relation, "")
        attributes = f'label="{edge.relation}"' + (f", {style}" if style else "")
        lines.append(f'  "{edge.source}" -> "{edge.target}" [{attributes}];')
    lines.append("}")
    return "\n".join(lines)


_DECISION_COLOURS = {
    "ALLOW": "#166534",
    "DENY": "#b91c1c",
    "HOLD": "#b45309",
    "ESCALATE": "#7c3aed",
    "RESTRICT": "#b45309",
    "QUARANTINE": "#b91c1c",
    "REVOKE": "#7f1d1d",
}


def _table(headers: Iterable[str], rows: Iterable[Iterable[str]]) -> str:
    head = "".join(f"<th>{html.escape(str(h))}</th>" for h in headers)
    body = "".join(
        "<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>" for row in rows
    )
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def to_html(trace: dict, *, title: str = "SENTINEL trace") -> str:
    """Single-file HTML report. No external assets, no JavaScript dependencies."""
    decision_rows = []
    for row in trace["decisions"]:
        colour = _DECISION_COLOURS.get(row["decision"], "#334155")
        decision_rows.append(
            [
                row["at"],
                html.escape(str(row["agent"])),
                html.escape(str(row["action"])),
                html.escape(str(row["tool"] or "-")),
                f'<span style="color:{colour};font-weight:600">{html.escape(str(row["decision"]))}</span>',
                html.escape(str(row["policy"])),
                html.escape(str(row["risk"] or "-")),
                html.escape(", ".join(map(str, row["evidence"]))),
            ]
        )

    drift_rows = [
        [
            html.escape(row["agent"]),
            "yes" if row["drift"] else "no",
            row["score"],
            html.escape(", ".join(row["kinds"])),
            html.escape(", ".join(row["observed"])),
            html.escape(", ".join(row["granted"])),
            row["denied_ratio"],
        ]
        for row in trace["drift"]
    ]

    containment_rows = [
        [
            row["at"],
            html.escape(row["subject"]),
            html.escape(row["action"]),
            html.escape(row["actor"]),
            html.escape(row["reason"][:70]),
            html.escape(str(row["verification"] or "-")),
        ]
        for row in trace["containment"]
    ]

    authority_rows = [
        [
            row["at"],
            html.escape(row["type"]),
            html.escape(str(row["actor"])),
            html.escape(str(row["subject"] or "-")),
            html.escape(json.dumps(row["payload"])[:110]),
        ]
        for row in trace["authority_events"]
    ]

    collusion_rows = [
        [
            html.escape(row["source"]),
            html.escape(row["partner"]),
            row["score"],
            html.escape(", ".join(row["evidence"])),
        ]
        for row in trace["collusion"]
    ]

    integrity = trace["integrity"]
    banner_colour = "#166534" if integrity["audit_valid"] and integrity["policy_valid"] else "#b91c1c"

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>{html.escape(title)}</title>
<style>
 body {{ font: 14px/1.5 -apple-system, Segoe UI, Helvetica, Arial, sans-serif; margin: 2rem; color: #0f172a; }}
 h1 {{ font-size: 1.4rem; }} h2 {{ font-size: 1.05rem; margin-top: 2rem; }}
 table {{ border-collapse: collapse; width: 100%; margin-top: .5rem; font-size: 12.5px; }}
 th, td {{ border-bottom: 1px solid #e2e8f0; padding: 4px 8px; text-align: left; vertical-align: top; }}
 th {{ background: #f8fafc; font-weight: 600; }}
 .banner {{ padding: .6rem .8rem; border-radius: 6px; background: #f1f5f9; border-left: 4px solid {banner_colour}; }}
 code {{ background:#f1f5f9; padding: 0 3px; border-radius: 3px; }}
</style></head><body>
<h1>{html.escape(title)}</h1>
<div class="banner">
 audit chain: <strong>{'intact' if integrity['audit_valid'] else 'BROKEN at ' + str(integrity['audit_broken_at'])}</strong>
 &middot; policy set: <strong>{'intact' if integrity['policy_valid'] else 'MUTATED'}</strong>
 &middot; records: {trace['counts']['audit_records']}
 &middot; decisions: {trace['counts']['decisions']}
 &middot; containment events: {trace['counts']['containment_events']}
 &middot; policy digest: <code>{html.escape(integrity['policy_digest'][:16])}</code>
</div>
<h2>Decisions</h2>
{_table(["at", "agent", "action", "tool", "decision", "policy", "risk", "evidence"], decision_rows)}
<h2>Authority timeline</h2>
{_table(["at", "event", "actor", "subject", "payload"], authority_rows)}
<h2>Containment</h2>
{_table(["at", "subject", "action", "actor", "reason", "verification"], containment_rows) if containment_rows else "<p>none</p>"}
<h2>Authority drift</h2>
{_table(["agent", "drift", "score", "kinds", "observed", "granted", "denied ratio"], drift_rows)}
<h2>Cross-agent collusion</h2>
{_table(["source", "partner", "score", "evidence"], collusion_rows) if collusion_rows else "<p>none detected</p>"}
</body></html>
"""
