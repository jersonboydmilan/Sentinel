"""Delegation model tests (section 16 and Principle 3)."""

import unittest

from tests.helpers import build_plane, provision_agent

from ais.common.errors import AuthorityAmplification, DelegationError
from ais.control_plane.policy import Effect
from ais.simulation.scenarios import run_delegation_experiment


class DelegationPredicateTests(unittest.TestCase):
    def setUp(self):
        self.plane = build_plane()
        self.contract_a = provision_agent(
            self.plane,
            "A",
            ("web.search", "agent.delegate"),
            tools=("web_search",),
            delegable=("web.search",),
            delegation_allowed=True,
        )
        provision_agent(self.plane, "B", ())
        provision_agent(self.plane, "C", ())
        self.a = self.plane.identity.get("A")

    def test_effective_authority_of_b_is_subset_of_delegable_of_a(self):
        self.plane.delegation.delegate(self.a, "B", ["web.search"])
        self.assertTrue(
            self.plane.authority.effective("B").issubset(self.plane.authority.delegable("A").union(self.plane.authority.effective("B")))
        )
        self.assertTrue(self.plane.authority.delegable("A").holds("web.search"))
        self.assertTrue(self.plane.authority.effective("B").holds("web.search"))

    def test_amplification_is_refused(self):
        with self.assertRaises(AuthorityAmplification) as ctx:
            self.plane.delegation.delegate(self.a, "B", ["database.write"])
        self.assertEqual(ctx.exception.context["excess"], ["database.write"])
        self.assertFalse(self.plane.authority.has("B", "database.write"))

    def test_delegation_requires_agent_delegate_capability(self):
        provision_agent(self.plane, "D", ("web.search",), delegable=("web.search",))
        d = self.plane.identity.get("D")
        with self.assertRaises(DelegationError):
            self.plane.delegation.delegate(d, "B", ["web.search"])

    def test_contract_must_permit_delegation(self):
        provision_agent(
            self.plane, "E", ("web.search", "agent.delegate"), delegable=("web.search",), delegation_allowed=False
        )
        e = self.plane.identity.get("E")
        with self.assertRaises(DelegationError):
            self.plane.delegation.delegate(e, "B", ["web.search"])

    def test_depth_attenuates_along_the_chain(self):
        self.plane.delegation.delegate(self.a, "B", ["web.search"], delegable_depth=1)
        b = self.plane.identity.get("B")
        self.plane.grant("B", "agent.delegate")
        self.plane.delegation.delegate(b, "C", ["web.search"])
        self.assertTrue(self.plane.authority.has("C", "web.search"))
        self.assertFalse(self.plane.authority.delegable("C"))

    def test_cycles_are_refused(self):
        self.plane.delegation.delegate(self.a, "B", ["web.search"], delegable_depth=1)
        self.plane.grant("B", "agent.delegate")
        b = self.plane.identity.get("B")
        with self.assertRaises(DelegationError):
            self.plane.delegation.delegate(b, "A", ["web.search"])

    def test_sub_contract_is_attenuated(self):
        self.plane.delegation.delegate(self.a, "B", ["web.search"])
        sub = self.plane.contracts.active_for("B")
        self.assertEqual(sub.declared_capabilities, ("web.search",))
        self.assertLessEqual(sub.max_tool_calls, self.contract_a.max_tool_calls)
        self.assertTrue(set(sub.allowed_tools).issubset(set(self.contract_a.allowed_tools)))

    def test_revoking_the_parent_revokes_the_child(self):
        self.plane.delegation.delegate(self.a, "B", ["web.search"])
        self.plane.authority.revoke_capability(self.plane.root, "A", "web.search", "test")
        self.assertFalse(self.plane.authority.has("B", "web.search"))

    def test_gateway_path_matches_engine_path(self):
        result = self.plane.submit(
            "A", "agent.delegate", target_agent="B", task_id=self.contract_a.contract_id,
            payload={"capabilities": ["database.write"]},
        )
        self.assertEqual(result.effect, Effect.DENY)
        self.assertEqual(result.facts["delegation_excess"], ["database.write"])


class DelegationExperimentTests(unittest.TestCase):
    def test_section_16_experiment(self):
        result = run_delegation_experiment()
        self.assertEqual(result["amplification_attempt"]["effect"], "DENY")
        self.assertEqual(result["amplification_attempt"]["b_authority_after"], [])
        self.assertEqual(result["legitimate_delegation"]["effect"], "ALLOW")
        self.assertEqual(result["multi_hop"]["hop_effect"], "ALLOW")
        self.assertEqual(result["multi_hop"]["widen_effect"], "DENY")
        self.assertEqual(result["multi_hop"]["c_authority"], ["web.search"])
        self.assertTrue(result["direct_engine_call"]["blocked"])
        self.assertIn("delegation_cycle", result["cycle_attempt"]["reasons"])


if __name__ == "__main__":
    unittest.main()
