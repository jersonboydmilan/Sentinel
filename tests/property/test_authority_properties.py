"""Property-based tests for the authority, delegation and revocation invariants.

These complement the example-based tests: instead of asserting one scenario,
they assert that a predicate holds across many generated scenarios, and report a
reproducible seed when it does not.
"""

import random
import unittest

from tests.helpers import build_plane, provision_agent
from tests.property.harness import forall, sample

from ais.common.errors import AuthorityError, ControlPlaneError, SelfGrantDenied
from ais.control_plane.capabilities import (
    DEFENSIVE_CAPABILITIES,
    OPERATIONAL_CAPABILITIES,
    CapabilitySet,
)
from ais.control_plane.invariants import InvariantChecker
from ais.control_plane.policy import Effect

OPERATIONAL = sorted(OPERATIONAL_CAPABILITIES)
DEFENSIVE = sorted(DEFENSIVE_CAPABILITIES)


class DelegationProperties(unittest.TestCase):
    def test_delegation_never_amplifies(self):
        def generate(rng: random.Random) -> dict:
            held = sample(rng, OPERATIONAL, 1, 5)
            delegable = sample(rng, held, 0, len(held))
            requested = sample(rng, OPERATIONAL, 1, 4)
            return {"held": held, "delegable": delegable, "requested": requested}

        def check(case: dict) -> None:
            plane = build_plane()
            provision_agent(
                plane,
                "A",
                tuple(case["held"]) + ("agent.delegate",),
                delegable=tuple(case["delegable"]),
                delegation_allowed=True,
            )
            provision_agent(plane, "B", ())
            a = plane.identity.get("A")
            delegable_before = plane.authority.delegable("A")
            try:
                plane.delegation.delegate(a, "B", case["requested"])
                allowed = True
            except ControlPlaneError:
                allowed = False

            effective_b = plane.authority.effective("B")
            # P3: whatever B ends up with must be inside what A could delegate.
            self.assertTrue(
                effective_b.issubset(delegable_before),
                f"B holds {effective_b.as_strings()} outside A's delegable {delegable_before.as_strings()}",
            )
            if allowed:
                self.assertTrue(CapabilitySet(case["requested"]).issubset(delegable_before))
            else:
                self.assertEqual(effective_b.as_strings(), [])

        forall("delegation never amplifies", generate, check, cases=60, seed="P3-delegation")

    def test_chains_cannot_widen(self):
        def generate(rng: random.Random) -> dict:
            root = sample(rng, OPERATIONAL, 1, 3)
            return {"root": root, "extra": rng.choice(OPERATIONAL)}

        def check(case: dict) -> None:
            plane = build_plane()
            provision_agent(
                plane, "A", tuple(case["root"]) + ("agent.delegate",),
                delegable=tuple(case["root"]), delegation_allowed=True,
            )
            provision_agent(plane, "B", ())
            provision_agent(plane, "C", ())
            a = plane.identity.get("A")
            try:
                plane.delegation.delegate(a, "B", case["root"], delegable_depth=1)
            except ControlPlaneError:
                return
            plane.grant("B", "agent.delegate")
            b = plane.identity.get("B")
            try:
                plane.delegation.delegate(b, "C", case["root"] + [case["extra"]])
            except ControlPlaneError:
                pass
            union = plane.authority.effective("B").union(plane.authority.effective("C"))
            self.assertTrue(
                union.issubset(CapabilitySet(case["root"] + ["agent.delegate"])),
                f"chain widened to {union.as_strings()}",
            )

        forall("chains cannot widen", generate, check, cases=40, seed="P3-chain")


class AuthorityProperties(unittest.TestCase):
    def test_self_grant_always_denied(self):
        def generate(rng: random.Random) -> dict:
            return {
                "capability": rng.choice(OPERATIONAL + DEFENSIVE),
                "held": sample(rng, OPERATIONAL, 0, 3),
                "defensive": rng.random() < 0.5,
            }

        def check(case: dict) -> None:
            plane = build_plane()
            plane.register_agent("X", defensive=case["defensive"])
            for capability in case["held"]:
                plane.grant("X", capability)
            principal = plane.identity.get("X")
            with self.assertRaises(SelfGrantDenied):
                plane.authority.issue(principal, "X", case["capability"])
            self.assertFalse(plane.authority.has("X", case["capability"]) and case["capability"] not in case["held"])

        forall("self-grant always denied", generate, check, cases=80, seed="P2")

    def test_revocation_cascades_and_is_immediate(self):
        # agent.delegate is excluded from the payload capability: the harness has
        # to grant it to each intermediate hop, and a *root-issued* grant is
        # independent authority that correctly survives revocation of A's grant.
        # (This distinction was surfaced by the property test itself.)
        cascade_pool = [c for c in OPERATIONAL if c not in {"agent.delegate", "agent.create"}]

        def generate(rng: random.Random) -> dict:
            return {"capability": rng.choice(cascade_pool), "depth": rng.randint(1, 3)}

        def check(case: dict) -> None:
            plane = build_plane()
            capability = case["capability"]
            provision_agent(
                plane, "A", (capability, "agent.delegate"), delegable=(capability,), delegation_allowed=True
            )
            names = ["A"]
            for index in range(case["depth"]):
                name = f"D{index}"
                provision_agent(plane, name, ())
                names.append(name)
            for index in range(case["depth"]):
                parent, child = names[index], names[index + 1]
                if parent != "A":
                    plane.grant(parent, "agent.delegate")
                try:
                    plane.delegation.delegate(
                        plane.identity.get(parent), child, [capability], delegable_depth=1
                    )
                except ControlPlaneError:
                    break
            plane.authority.revoke_capability(plane.root, "A", capability, "property-test")
            for name in names:
                self.assertFalse(
                    plane.authority.has(name, capability),
                    f"{name} still holds {capability} after root revocation",
                )

        forall("revocation cascades", generate, check, cases=50, seed="P6")

    def test_default_deny_for_ungranted_capabilities(self):
        def generate(rng: random.Random) -> dict:
            granted = sample(rng, OPERATIONAL, 0, 3)
            candidates = [c for c in OPERATIONAL if c not in granted]
            return {"granted": granted, "attempt": rng.choice(candidates)}

        def check(case: dict) -> None:
            plane = build_plane()
            contract = provision_agent(plane, "A", tuple(case["granted"]), tools=tuple(plane.registry.names()))
            result = plane.submit("A", case["attempt"], task_id=contract.contract_id, payload={})
            self.assertNotEqual(result.effect, Effect.ALLOW, f"{case['attempt']} allowed without a grant")

        forall("default deny", generate, check, cases=80, seed="P7")


class DefensiveAuthorityProperties(unittest.TestCase):
    def test_defensive_agents_cannot_reach_operational_capability(self):
        from ais.defensive_agents.sentinel import Sentinel
        from ais.immune_system.immune import ImmuneSystem
        from ais.observatory.observatory import Observatory

        def generate(rng: random.Random) -> dict:
            return {
                "actions": [rng.choice(OPERATIONAL) for _ in range(rng.randint(1, 5))],
                "targets": rng.choice(["SUBJECT-01", None]),
            }

        def check(case: dict) -> None:
            plane = build_plane()
            observatory = Observatory(plane)
            immune = ImmuneSystem(plane, observatory)
            sentinel = Sentinel(plane, observatory, immune)
            checker = InvariantChecker(plane).bind()
            provision_agent(plane, "SUBJECT-01", ("web.search",), tools=("web_search",))

            for agent in sentinel.agents:
                for action in case["actions"]:
                    result = agent.act(action, subject=case["targets"], payload={"rows": 1})
                    self.assertFalse(
                        result.allowed, f"{agent.NAME} executed operational capability {action}"
                    )
                effective = set(plane.authority.effective(agent.agent_id).as_strings())
                self.assertTrue(
                    effective.issubset(set(agent.DECLARED_CAPABILITIES)),
                    f"{agent.NAME} holds {effective} beyond {agent.DECLARED_CAPABILITIES}",
                )
            self.assertTrue(checker.check().ok, checker.summary())

        forall("defensive agents stay in their namespace", generate, check, cases=25, seed="P4-P5")

    def test_containment_requires_verification_for_any_subject(self):
        from ais.defensive_agents.sentinel import Sentinel
        from ais.immune_system.immune import ImmuneSystem
        from ais.observatory.observatory import Observatory

        def generate(rng: random.Random) -> dict:
            return {
                "action": rng.choice(["agent.restrict", "agent.isolate", "agent.quarantine", "agent.revoke"]),
                "confidence": round(rng.uniform(0.0, 1.0), 3),
                "forged_ref": rng.choice(["", "VER-999999", "not-a-ref"]),
            }

        def check(case: dict) -> None:
            plane = build_plane()
            observatory = Observatory(plane)
            immune = ImmuneSystem(plane, observatory)
            sentinel = Sentinel(plane, observatory, immune)
            contract = provision_agent(plane, "SUBJECT-01", ("web.search",), tools=("web_search",))
            del contract
            before = plane.authority.effective("SUBJECT-01").as_strings()
            result = sentinel.contain.act(
                case["action"],
                subject="SUBJECT-01",
                payload={
                    "reason": "property-test",
                    "confidence": case["confidence"],
                    "verification_ref": case["forged_ref"],
                    "capabilities": ["web.search"],
                },
            )
            self.assertFalse(result.allowed, f"{case['action']} allowed without valid verification")
            self.assertEqual(before, plane.authority.effective("SUBJECT-01").as_strings())

        forall("containment needs verification", generate, check, cases=40, seed="verification")


if __name__ == "__main__":
    unittest.main()
