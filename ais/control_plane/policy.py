"""Policy engine.

Policies are declarative, machine readable and evaluated deterministically over
a *fact dictionary* assembled by the gateway. The engine never calls a model,
never inspects free text, and never mutates state - it is a pure function from
(facts, policy set) to a decision, which is what makes policy latency and
decision reproducibility measurable (section 22).

Default deny (P7) is structural: if no policy matches, the answer is DENY.
Policy files are themselves protected: the loaded set carries an integrity
digest that the gateway re-checks on every call, so silent policy mutation by
any in-process component is detected.
"""

from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable

from ..common import minyaml
from ..common.errors import PolicyError, PolicyIntegrityError
from ..common.util import digest_of
from .audit import AuditService
from .identity import Principal


class Effect(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    RESTRICT = "RESTRICT"
    HOLD = "HOLD"
    ESCALATE = "ESCALATE"
    QUARANTINE = "QUARANTINE"
    REVOKE = "REVOKE"

    @property
    def permits_execution(self) -> bool:
        return self is Effect.ALLOW

    @property
    def is_containment(self) -> bool:
        return self in (Effect.RESTRICT, Effect.QUARANTINE, Effect.REVOKE)


OPERATORS = {
    "equals": lambda fact, expected: fact == expected,
    "not_equals": lambda fact, expected: fact != expected,
    "lt": lambda fact, expected: _num(fact) < _num(expected),
    "lte": lambda fact, expected: _num(fact) <= _num(expected),
    "gt": lambda fact, expected: _num(fact) > _num(expected),
    "gte": lambda fact, expected: _num(fact) >= _num(expected),
    "in": lambda fact, expected: fact in (expected or []),
    "not_in": lambda fact, expected: fact not in (expected or []),
    "contains": lambda fact, expected: expected in (fact or []),
    "not_contains": lambda fact, expected: expected not in (fact or []),
    "subset_of": lambda fact, expected: set(fact or []).issubset(set(expected or [])),
    "matches": lambda fact, expected: fnmatch.fnmatch(str(fact), str(expected)),
}


def _num(value: Any) -> float:
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    if value is None:
        return 0.0
    return float(value)


@dataclass(frozen=True)
class Condition:
    fact: str
    operator: str
    expected: Any

    def evaluate(self, facts: dict) -> tuple[bool, str]:
        if self.fact not in facts:
            return False, f"missing_fact:{self.fact}"
        checker = OPERATORS.get(self.operator)
        if checker is None:
            raise PolicyError("unknown policy operator", operator=self.operator)
        try:
            ok = bool(checker(facts[self.fact], self.expected))
        except (TypeError, ValueError):
            return False, f"uncomparable:{self.fact}"
        return ok, f"{self.fact}:{self.operator}:{'pass' if ok else 'fail'}"


@dataclass(frozen=True)
class Policy:
    policy_id: str
    description: str
    priority: int
    effect: Effect
    otherwise: Effect
    match_action: str = "*"
    match_subject_kinds: tuple[str, ...] = ()
    match_subject_ids: tuple[str, ...] = ()
    match_tags: tuple[str, ...] = ()
    when: tuple[Condition, ...] = ()
    conditions: tuple[Condition, ...] = ()

    def matches(self, facts: dict) -> bool:
        """``match`` selects on the shape of the request, ``when`` on its facts.

        Separating the two keeps every policy total: a policy only reaches its
        ``conditions``/``otherwise`` branch for requests it actually governs.
        """
        if not fnmatch.fnmatch(str(facts.get("action", "")), self.match_action):
            return False
        if self.match_subject_kinds and facts.get("subject_kind") not in self.match_subject_kinds:
            return False
        if self.match_subject_ids and facts.get("subject_id") not in self.match_subject_ids:
            return False
        if self.match_tags and not set(self.match_tags).issubset(set(facts.get("tags", []))):
            return False
        for gate in self.when:
            ok, _ = gate.evaluate(facts)
            if not ok:
                return False
        return True

    def evaluate(self, facts: dict) -> tuple[Effect, list[str]]:
        reasons: list[str] = []
        for condition in self.conditions:
            ok, reason = condition.evaluate(facts)
            reasons.append(reason)
            if not ok:
                return self.otherwise, reasons
        return self.effect, reasons


@dataclass(frozen=True)
class PolicyDecision:
    effect: Effect
    policy_id: str
    reasons: tuple[str, ...] = ()
    evaluated: tuple[str, ...] = ()

    @property
    def allowed(self) -> bool:
        return self.effect.permits_execution


DEFAULT_DENY = PolicyDecision(
    effect=Effect.DENY,
    policy_id="POL-000-DEFAULT-DENY",
    reasons=("no_policy_matched",),
)


def _parse_policy(raw: dict) -> Policy:
    try:
        match = raw.get("match") or {}

        def parse_conditions(items) -> list[Condition]:
            parsed = []
            for item in items or []:
                fact = item["fact"]
                operators = [k for k in item if k != "fact"]
                if len(operators) != 1:
                    raise PolicyError("each condition needs exactly one operator", condition=item)
                operator = operators[0]
                parsed.append(Condition(fact=fact, operator=operator, expected=item[operator]))
            return parsed

        conditions = parse_conditions(raw.get("conditions"))
        when = parse_conditions(raw.get("when"))
        return Policy(
            policy_id=raw["id"],
            description=raw.get("description", ""),
            priority=int(raw.get("priority", 0)),
            effect=Effect(raw.get("effect", "DENY")),
            otherwise=Effect(raw.get("otherwise", "DENY")),
            match_action=str(match.get("action", "*")),
            match_subject_kinds=tuple(match.get("subject_kind") or ()),
            match_subject_ids=tuple(match.get("subject_id") or ()),
            match_tags=tuple(match.get("tags") or ()),
            when=tuple(when),
            conditions=tuple(conditions),
        )
    except KeyError as exc:  # pragma: no cover - configuration error path
        raise PolicyError("malformed policy document", missing=str(exc), raw=raw) from exc


class PolicyEngine:
    def __init__(self, audit: AuditService) -> None:
        self._audit = audit
        self._policies: list[Policy] = []
        self._digest = digest_of([])

    # -- loading -----------------------------------------------------------
    def load_documents(self, documents: Iterable[dict]) -> None:
        policies: list[Policy] = []
        for document in documents:
            for raw in document.get("policies", []):
                policies.append(_parse_policy(raw))
        self._install(policies)

    def load_directory(self, path: str) -> None:
        documents = []
        for name in sorted(os.listdir(path)):
            if not name.endswith((".yaml", ".yml")):
                continue
            documents.append(minyaml.load_file(os.path.join(path, name)))
        self.load_documents(documents)

    def _install(self, policies: list[Policy]) -> None:
        seen = set()
        for policy in policies:
            if policy.policy_id in seen:
                raise PolicyError("duplicate policy id", policy_id=policy.policy_id)
            seen.add(policy.policy_id)
        self._policies = sorted(policies, key=lambda p: (-p.priority, p.policy_id))
        self._digest = digest_of([p for p in self._policies])
        self._audit.append(
            "policy.loaded",
            actor_id="control-plane",
            payload={"count": len(self._policies), "digest": self._digest},
        )

    def install_policy(self, actor: Principal, raw: dict) -> Policy:
        """Policy authoring is an external-authority operation (never an agent)."""
        if not actor.is_root_authority:
            self._audit.append(
                "policy.mutation_denied",
                actor_id=actor.principal_id,
                payload={"policy_id": raw.get("id")},
            )
            raise PolicyError("only an external root authority may modify policy", actor=actor.principal_id)
        policy = _parse_policy(raw)
        self._install([p for p in self._policies if p.policy_id != policy.policy_id] + [policy])
        return policy

    # -- integrity ---------------------------------------------------------
    @property
    def digest(self) -> str:
        return self._digest

    def verify_integrity(self) -> None:
        current = digest_of([p for p in self._policies])
        if current != self._digest:
            raise PolicyIntegrityError("policy set mutated outside the control plane", expected=self._digest, actual=current)

    # -- evaluation --------------------------------------------------------
    @property
    def policies(self) -> tuple[Policy, ...]:
        return tuple(self._policies)

    def evaluate(self, facts: dict) -> PolicyDecision:
        self.verify_integrity()
        evaluated: list[str] = []
        for policy in self._policies:
            if not policy.matches(facts):
                continue
            evaluated.append(policy.policy_id)
            effect, reasons = policy.evaluate(facts)
            # The first (highest priority) matching policy decides. Containment
            # and denial short circuit; an ALLOW keeps scanning only if the
            # policy declares itself advisory.
            return PolicyDecision(
                effect=effect,
                policy_id=policy.policy_id,
                reasons=tuple(reasons),
                evaluated=tuple(evaluated),
            )
        return PolicyDecision(
            effect=DEFAULT_DENY.effect,
            policy_id=DEFAULT_DENY.policy_id,
            reasons=DEFAULT_DENY.reasons,
            evaluated=tuple(evaluated),
        )
