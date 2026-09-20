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


_DECISION_TONE = {
    "ALLOW": ("allow", "#047857", "#ecfdf5", "#a7f3d0"),
    "DENY": ("deny", "#b91c1c", "#fef2f2", "#fecaca"),
    "HOLD": ("hold", "#b45309", "#fffbeb", "#fde68a"),
    "ESCALATE": ("escalate", "#6d28d9", "#f5f3ff", "#ddd6fe"),
    "RESTRICT": ("restrict", "#b45309", "#fffbeb", "#fde68a"),
    "ISOLATE": ("isolate", "#b45309", "#fffbeb", "#fde68a"),
    "QUARANTINE": ("quarantine", "#b91c1c", "#fef2f2", "#fecaca"),
    "REVOKE": ("revoke", "#7f1d1d", "#fef2f2", "#fca5a5"),
    "MONITOR": ("monitor", "#1d4ed8", "#eff6ff", "#bfdbfe"),
}


def _badge(value: str) -> str:
    tone = _DECISION_TONE.get(value, ("neutral", "#334155", "#f8fafc", "#e2e8f0"))
    _, colour, background, border = tone
    return (
        f'<span class="badge" style="color:{colour};background:{background};border-color:{border}">'
        f"{html.escape(value)}</span>"
    )


def _chips(values: list[str], limit: int = 4) -> str:
    shown = [html.escape(str(v)) for v in values[:limit]]
    extra = len(values) - len(shown)
    chips = "".join(f'<span class="chip">{value}</span>' for value in shown)
    if extra > 0:
        chips += f'<span class="chip chip-more">+{extra}</span>'
    return chips or '<span class="muted">—</span>'


def _table(headers, rows, *, table_id: str = "", searchable: bool = False) -> str:
    head = "".join(f"<th>{html.escape(str(h))}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>" for row in rows)
    attributes = f' id="{table_id}"' if table_id else ""
    search = (
        f'<div class="toolbar"><input class="search" type="search" placeholder="Filter rows…" '
        f'data-target="{table_id}" aria-label="Filter rows"></div>'
        if searchable and table_id
        else ""
    )
    if not rows:
        return f'{search}<p class="empty">Nothing recorded.</p>'
    return f'{search}<div class="table-wrap"><table{attributes}><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


#: Rows rendered in the decision table (the newest ones).
DECISION_ROWS = 90


def _policy(policy_id: str) -> str:
    """Short policy id, full name on hover."""
    parts = policy_id.split("-")
    short = "-".join(parts[:2]) if len(parts) > 2 else policy_id
    return f'<span class="mono" title="{html.escape(policy_id)}">{html.escape(short)}</span>'


def _metric(label: str, value, hint: str = "") -> str:
    hint_html = f'<span class="metric-hint">{html.escape(hint)}</span>' if hint else ""
    return (
        f'<div class="metric"><span class="metric-label">{html.escape(label)}</span>'
        f'<span class="metric-value">{html.escape(str(value))}</span>{hint_html}</div>'
    )


STYLE = """
:root {
  --bg: #f6f7f9;
  --surface: #ffffff;
  --ink: #0f172a;
  --ink-soft: #475569;
  --ink-faint: #94a3b8;
  --line: #e5e7eb;
  --line-soft: #f1f5f9;
  --accent: #2563eb;
  --ok: #047857;
  --bad: #b91c1c;
  --radius: 14px;
  --shadow: 0 1px 2px rgba(15,23,42,.04), 0 8px 24px rgba(15,23,42,.06);
}
* { box-sizing: border-box; }
body {
  margin: 0; padding: 0 0 72px; background: var(--bg); color: var(--ink);
  font: 15px/1.55 ui-sans-serif, -apple-system, "Segoe UI", Inter, Helvetica, Arial, sans-serif;
  -webkit-font-smoothing: antialiased;
}
.wrap { max-width: 1180px; margin: 0 auto; padding: 0 24px; }
header.top {
  background: var(--surface); border-bottom: 1px solid var(--line);
  padding: 28px 0 22px; margin-bottom: 28px;
}
.eyebrow { color: var(--ink-faint); font-size: 12px; letter-spacing: .12em; text-transform: uppercase; font-weight: 600; }
h1 { font-size: 26px; line-height: 1.2; margin: 6px 0 4px; letter-spacing: -0.02em; }
.subtitle { color: var(--ink-soft); font-size: 14px; margin: 0; }
.status-row { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 16px; }
.pill {
  display: inline-flex; align-items: center; gap: 7px; font-size: 12.5px; font-weight: 550;
  padding: 5px 11px; border-radius: 999px; border: 1px solid var(--line); background: #fff; color: var(--ink-soft);
}
.pill .dot { width: 7px; height: 7px; border-radius: 50%; background: var(--ok); }
.pill.bad .dot { background: var(--bad); }
.pill.bad { color: var(--bad); border-color: #fecaca; background: #fef2f2; }
.metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(168px, 1fr)); gap: 14px; margin: 0 0 28px; }
.metric {
  background: var(--surface); border: 1px solid var(--line); border-radius: var(--radius);
  padding: 16px 18px; display: flex; flex-direction: column; gap: 4px; box-shadow: var(--shadow);
}
.metric-label { font-size: 12px; color: var(--ink-faint); font-weight: 600; letter-spacing: .04em; text-transform: uppercase; }
.metric-value { font-size: 26px; font-weight: 640; letter-spacing: -0.02em; font-variant-numeric: tabular-nums; }
.metric-hint { font-size: 12.5px; color: var(--ink-soft); }
section.card {
  background: var(--surface); border: 1px solid var(--line); border-radius: var(--radius);
  padding: 20px 22px 8px; margin-bottom: 22px; box-shadow: var(--shadow);
}
section.card > h2 { font-size: 15px; margin: 0 0 2px; letter-spacing: -0.01em; }
section.card > p.note { margin: 0 0 14px; color: var(--ink-soft); font-size: 13px; }
.toolbar { margin: 0 0 12px; }
.search {
  width: 100%; max-width: 320px; padding: 8px 12px; font-size: 13.5px; color: var(--ink);
  border: 1px solid var(--line); border-radius: 9px; background: #fff; outline: none;
}
.search:focus { border-color: var(--accent); box-shadow: 0 0 0 3px rgba(37,99,235,.12); }
.table-wrap { overflow-x: auto; margin: 0 -22px; padding: 0 22px 14px; }
table { border-collapse: collapse; width: 100%; font-size: 13px; }
thead th {
  position: sticky; top: 0; background: var(--surface); z-index: 1; text-align: left;
  font-size: 11.5px; letter-spacing: .06em; text-transform: uppercase; color: var(--ink-faint);
  font-weight: 650; padding: 8px 10px; border-bottom: 1px solid var(--line);
}
tbody td { padding: 9px 10px; border-bottom: 1px solid var(--line-soft); vertical-align: top; white-space: nowrap; }
tbody td:last-child { white-space: normal; }
tbody tr:hover { background: #fafbfc; }
tbody tr:last-child td { border-bottom: none; }
td.num, th.num { font-variant-numeric: tabular-nums; color: var(--ink-faint); width: 54px; }
.mono { font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, monospace; font-size: 12.3px; }
.badge {
  display: inline-block; padding: 2px 9px; border-radius: 999px; font-size: 11.5px;
  font-weight: 650; border: 1px solid; letter-spacing: .02em;
}
.chip {
  display: inline-block; background: var(--line-soft); color: var(--ink-soft); border-radius: 6px;
  padding: 2px 7px; margin: 0 4px 4px 0; font-size: 11.5px;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
}
.chip-more { background: #fff; border: 1px dashed var(--line); }
.muted { color: var(--ink-faint); }
.empty { color: var(--ink-faint); font-size: 13px; padding: 4px 0 18px; }
.legend { display: flex; flex-wrap: wrap; gap: 14px; font-size: 12.5px; color: var(--ink-soft); margin: 6px 0 16px; }
footer { color: var(--ink-faint); font-size: 12.5px; padding-top: 6px; }
@media (max-width: 720px) { h1 { font-size: 22px; } .wrap { padding: 0 16px; } }
"""

SCRIPT = """
document.querySelectorAll('.search').forEach(function (input) {
  input.addEventListener('input', function () {
    var table = document.getElementById(input.dataset.target);
    if (!table) return;
    var term = input.value.toLowerCase();
    table.querySelectorAll('tbody tr').forEach(function (row) {
      row.style.display = row.textContent.toLowerCase().indexOf(term) === -1 ? 'none' : '';
    });
  });
});
"""


def to_html(trace: dict, *, title: str = "SENTINEL trace", subtitle: str = "") -> str:
    """Single-file HTML report: no external assets, no dependencies."""
    integrity = trace["integrity"]
    counts = trace["counts"]
    decisions = trace["decisions"]

    tally: dict[str, int] = {}
    for row in decisions:
        tally[row["decision"]] = tally.get(row["decision"], 0) + 1
    allowed = tally.get("ALLOW", 0)
    refused = sum(count for decision, count in tally.items() if decision not in {"ALLOW"})
    drifting = sum(1 for row in trace["drift"] if row["drift"])

    shown_decisions = decisions[-DECISION_ROWS:]
    decision_rows = [
        [
            f'<span class="num">{row["at"]}</span>',
            f'<span class="mono">{html.escape(str(row["agent"]))}</span>',
            f'<span class="mono">{html.escape(str(row["action"]))}</span>',
            f'<span class="mono muted">{html.escape(str(row["tool"] or "—"))}</span>',
            _badge(str(row["decision"])),
            _policy(str(row["policy"])),
            html.escape(str(row["risk"] or "—")),
            # Evidence is shown where it decides something: a refusal. An ALLOW
            # lists the conditions it satisfied, which is noise at this density.
            _chips([str(item) for item in row["evidence"] if not str(item).endswith(":pass")], limit=2)
            if row["decision"] != "ALLOW"
            else '<span class="muted">conditions met</span>',
        ]
        for row in shown_decisions
    ]
    truncated = len(decisions) - len(shown_decisions)

    drift_rows = [
        [
            f'<span class="mono">{html.escape(row["agent"])}</span>',
            _badge("DENY" if row["drift"] else "ALLOW").replace(">DENY<", ">drift<").replace(">ALLOW<", ">clean<"),
            f'{row["score"]:.3f}',
            _chips([k.replace("_DRIFT", "").lower() for k in row["kinds"]], limit=4),
            _chips(row["observed"], limit=3),
            _chips(row["granted"], limit=3),
            f'{row["denied_ratio"]:.3f}',
        ]
        for row in trace["drift"]
    ]

    containment_rows = [
        [
            f'<span class="num">{row["at"]}</span>',
            f'<span class="mono">{html.escape(row["subject"])}</span>',
            _badge(row["action"]),
            f'<span class="mono">{html.escape(row["actor"])}</span>',
            html.escape(row["reason"][:70]),
            f'<span class="mono">{html.escape(str(row["verification"] or "—"))}</span>',
        ]
        for row in trace["containment"]
    ]

    authority_rows = [
        [
            f'<span class="num">{row["at"]}</span>',
            f'<span class="mono">{html.escape(row["type"])}</span>',
            f'<span class="mono">{html.escape(str(row["actor"]))}</span>',
            f'<span class="mono">{html.escape(str(row["subject"] or "—"))}</span>',
            f'<span class="mono muted">{html.escape(json.dumps(row["payload"])[:96])}</span>',
        ]
        for row in trace["authority_events"]
    ]

    collusion_rows = [
        [
            f'<span class="mono">{html.escape(row["source"])}</span>',
            f'<span class="mono">{html.escape(row["partner"])}</span>',
            f'{row["score"]:.2f}',
            _chips(row["evidence"], limit=5),
        ]
        for row in trace["collusion"]
    ]

    truncation_note = (
        f" Showing the most recent {len(shown_decisions)} of {len(decisions)}." if truncated > 0 else ""
    )
    audit_ok = integrity["audit_valid"]
    policy_ok = integrity["policy_valid"]
    audit_pill = (
        f'<span class="pill"><span class="dot"></span>audit chain intact · {counts["audit_records"]} records</span>'
        if audit_ok
        else f'<span class="pill bad"><span class="dot"></span>audit chain BROKEN at {integrity["audit_broken_at"]}</span>'
    )
    policy_pill = (
        '<span class="pill"><span class="dot"></span>policy set intact</span>'
        if policy_ok
        else '<span class="pill bad"><span class="dot"></span>policy set MUTATED</span>'
    )

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title>
<style>{STYLE}</style></head>
<body>
<header class="top"><div class="wrap">
  <div class="eyebrow">Agent Immune System · SENTINEL</div>
  <h1>{html.escape(title)}</h1>
  <p class="subtitle">{html.escape(subtitle or "Every consequential decision, the policy that made it, and the evidence behind it.")}</p>
  <div class="status-row">
    {audit_pill}
    {policy_pill}
    <span class="pill"><span class="dot"></span>policy digest <span class="mono">{html.escape(integrity["policy_digest"][:12])}</span></span>
  </div>
</div></header>

<div class="wrap">
  <div class="metrics">
    {_metric("Decisions", counts["decisions"], f"{allowed} allowed · {refused} refused")}
    {_metric("Agents observed", len(trace["drift"]), f"{drifting} with authority drift")}
    {_metric("Containment", counts["containment_events"], "graduated, reversible first")}
    {_metric("Authority events", counts["authority_events"], "grants, revocations, delegations")}
    {_metric("Collusion chains", len(trace["collusion"]), "cross-agent relationships")}
  </div>

  <section class="card">
    <h2>Containment</h2>
    <p class="note">Every containment action, its actor, and the verification that unlocked it. Reversible actions first; revocation needs two independent verifiers.</p>
    {_table(["at", "subject", "action", "actor", "reason", "verification"], containment_rows, table_id="containment")}
  </section>

  <section class="card">
    <h2>Authority drift</h2>
    <p class="note">Declared, granted and observed authority compared per agent. Drift is decomposed into typed components, each with its own evidence.</p>
    {_table(["agent", "state", "score", "components", "observed", "granted", "denied ratio"], drift_rows,
            table_id="drift", searchable=True)}
  </section>

  <section class="card">
    <h2>Cross-agent collusion</h2>
    <p class="note">Acquire → transfer → exfiltrate chains spanning two agents, neither of which exceeded its own authority.</p>
    {_table(["source", "partner", "score", "evidence"], collusion_rows, table_id="collusion")}
  </section>

  <section class="card">
    <h2>Decisions</h2>
    <p class="note">Each row is one gateway decision. Nothing reached a tool without appearing here.{truncation_note}</p>
    {_table(["at", "agent", "action", "tool", "decision", "policy", "risk", "evidence"], decision_rows,
            table_id="decisions", searchable=True)}
  </section>

  <section class="card">
    <h2>Authority timeline</h2>
    <p class="note">Grants, revocations, restrictions, delegations, quarantine admissions and verifications.</p>
    {_table(["at", "event", "actor", "subject", "payload"], authority_rows, table_id="authority", searchable=True)}
  </section>

  <footer>Generated by <span class="mono">python3 -m ais trace</span> · deterministic run, no external assets.</footer>
</div>
<script>{SCRIPT}</script>
</body></html>
"""
