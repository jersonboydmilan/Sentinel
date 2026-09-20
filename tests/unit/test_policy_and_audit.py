import unittest

from tests.helpers import build_plane

from ais.common import minyaml
from ais.common.errors import PolicyError, PolicyIntegrityError
from ais.control_plane.audit import AuditService
from ais.control_plane.policy import Effect, PolicyEngine
from ais.common.util import IdFactory, LogicalClock


class PolicyEngineTests(unittest.TestCase):
    def setUp(self):
        self.audit = AuditService(LogicalClock(), IdFactory())
        self.engine = PolicyEngine(self.audit)
        self.engine.load_documents(
            [
                {
                    "policies": [
                        {
                            "id": "POL-TEST-WRITE",
                            "priority": 10,
                            "match": {"action": "database.write"},
                            "conditions": [{"fact": "capability_held", "equals": True}],
                            "effect": "ALLOW",
                            "otherwise": "DENY",
                        }
                    ]
                }
            ]
        )

    def test_default_deny_when_no_policy_matches(self):
        decision = self.engine.evaluate({"action": "file.write", "capability_held": True})
        self.assertEqual(decision.effect, Effect.DENY)
        self.assertEqual(decision.policy_id, "POL-000-DEFAULT-DENY")

    def test_conditions_decide_effect(self):
        allow = self.engine.evaluate({"action": "database.write", "capability_held": True})
        deny = self.engine.evaluate({"action": "database.write", "capability_held": False})
        self.assertEqual(allow.effect, Effect.ALLOW)
        self.assertEqual(deny.effect, Effect.DENY)

    def test_missing_fact_fails_closed(self):
        decision = self.engine.evaluate({"action": "database.write"})
        self.assertEqual(decision.effect, Effect.DENY)
        self.assertIn("missing_fact:capability_held", decision.reasons)

    def test_when_gate_scopes_a_policy(self):
        self.engine.load_documents(
            [
                {
                    "policies": [
                        {
                            "id": "POL-QUARANTINE",
                            "priority": 100,
                            "match": {"action": "*"},
                            "when": [{"fact": "quarantined", "equals": True}],
                            "conditions": [{"fact": "sandboxed", "equals": True}],
                            "effect": "ALLOW",
                            "otherwise": "DENY",
                        }
                    ]
                }
            ]
        )
        self.assertEqual(self.engine.evaluate({"action": "x.y", "quarantined": False}).policy_id, "POL-000-DEFAULT-DENY")
        self.assertEqual(
            self.engine.evaluate({"action": "x.y", "quarantined": True, "sandboxed": False}).effect, Effect.DENY
        )

    def test_integrity_digest_detects_mutation(self):
        self.engine.verify_integrity()
        self.engine._policies = []
        with self.assertRaises(PolicyIntegrityError):
            self.engine.verify_integrity()

    def test_only_root_may_install_policy(self):
        plane = build_plane()
        agent = plane.register_agent("AGENT-X")
        with self.assertRaises(PolicyError):
            plane.policy.install_policy(agent, {"id": "POL-EVIL", "effect": "ALLOW", "otherwise": "ALLOW"})


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.clock = LogicalClock()
        self.audit = AuditService(self.clock, IdFactory())
        for index in range(5):
            self.clock.tick()
            self.audit.append("test.event", actor_id=f"agent-{index % 2}", task_id="T1", payload={"i": index})

    def test_chain_verifies(self):
        self.assertTrue(self.audit.verify().valid)

    def test_mutation_is_detected(self):
        victim = self.audit._records[2]
        self.audit._records[2] = type(victim)(**{**victim.__dict__, "payload": {"i": 99}})
        report = self.audit.verify()
        self.assertFalse(report.valid)
        self.assertEqual(report.broken_at, 2)

    def test_reordering_is_detected(self):
        self.audit._records[1], self.audit._records[3] = self.audit._records[3], self.audit._records[1]
        self.assertFalse(self.audit.verify().valid)

    def test_search_and_correlate(self):
        self.assertEqual(len(self.audit.search(actor_id="agent-0")), 3)
        self.assertEqual(len(self.audit.correlate("T1")), 5)

    def test_replay_yields_bodies(self):
        bodies = list(self.audit.replay())
        self.assertEqual(len(bodies), 5)
        self.assertEqual(bodies[0]["event_type"], "test.event")


class MinYamlTests(unittest.TestCase):
    def test_nested_structures(self):
        document = minyaml.loads(
            """
policies:
  - id: A
    priority: 3
    match: {action: "db.*"}
    conditions:
      - fact: x
        equals: true
    tags: [a, b]
"""
        )
        policy = document["policies"][0]
        self.assertEqual(policy["priority"], 3)
        self.assertEqual(policy["match"]["action"], "db.*")
        self.assertEqual(policy["conditions"][0]["equals"], True)
        self.assertEqual(policy["tags"], ["a", "b"])

    def test_unsupported_syntax_raises(self):
        with self.assertRaises(minyaml.YamlSubsetError):
            minyaml.loads("key:\n\tvalue: 1")


if __name__ == "__main__":
    unittest.main()
