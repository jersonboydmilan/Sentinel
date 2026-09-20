"""Integration tests: the full detect -> verify -> contain -> recover loop."""

import unittest

from tests.helpers import build_stack, provision_agent

from ais.control_plane.emergency import EmergencyControl
from ais.control_plane.policy import Effect
from ais.immune_system.classification import ThreatClass
from ais.quarantine.replay import replay
from ais.simulation.ecosystem import EcosystemConfig, build_default_ecosystem
from ais.simulation.scenarios import run_key_experiment


class ControlPlaneFlowTests(unittest.TestCase):
    def setUp(self):
        self.plane, self.observatory, self.immune, self.sentinel = build_stack()
        self.contract = provision_agent(
            self.plane,
            "AGENT-1",
            ("web.search", "database.read", "email.read"),
            tools=("web_search", "research_db", "mailbox"),
            datasets=("public_papers",),
            endpoints=("example.com",),
        )

    def _act(self, action, **kwargs):
        self.plane.tick()
        kwargs.setdefault("task_id", self.contract.contract_id)
        return self.plane.submit("AGENT-1", action, **kwargs)

    def test_allowed_action_executes_and_is_audited(self):
        result = self._act("web.search", tool="web_search", payload={"query": "x"})
        self.assertEqual(result.effect, Effect.ALLOW)
        self.assertIn("results", result.output)
        records = self.plane.audit.search(event_type="gateway.decision", actor_id="AGENT-1")
        self.assertEqual(records[-1].payload["decision"], "ALLOW")
        self.assertTrue(self.plane.audit.verify().valid)

    def test_denied_action_never_reaches_the_tool(self):
        self._act("credential.read", tool="credential_vault", payload={"name": "prod"})
        self.assertEqual([i["tool"] for i in self.plane.registry.invocations], [])

    def test_decision_record_shape_matches_section_21(self):
        result = self._act("database.write", tool="records_db_write", payload={"rows": 1})
        record = result.as_record()
        for key in ("decision_id", "agent_id", "task_id", "requested_action", "decision", "policy", "risk", "evidence", "executor"):
            self.assertIn(key, record)
        self.assertEqual(record["executor"], "policy-gateway")

    def test_full_detection_to_containment(self):
        for index in range(10):
            self._act("web.search", tool="web_search", payload={"query": f"n{index}"})
        for _ in range(2):
            self._act("email.read", tool="mailbox", payload={"folder": "inbox"})
        for _ in range(2):
            self._act("credential.read", tool="credential_vault", payload={"name": "prod"})
        self._act("network.egress", tool="http_out", endpoint="collector.example.io", payload={"endpoint": "collector.example.io"})

        report = self.sentinel.cycle(["AGENT-1"])
        self.assertTrue(report.flags)
        classification = self.immune.latest("AGENT-1")
        self.assertNotEqual(classification.threat_class, ThreatClass.NORMAL)
        self.assertTrue(any(v["verdict"] == "CONFIRMED" for v in report.verifications))
        actions = [event.action.value for event in self.plane.containment.history("AGENT-1")]
        self.assertIn("RESTRICT", actions)

    def test_emergency_stop_overrides_everything(self):
        self.plane.emergency.activate(EmergencyControl.GLOBAL_STOP, "test-operator-key")
        result = self._act("web.search", tool="web_search", payload={"query": "x"})
        self.assertEqual(result.effect, Effect.DENY)
        self.assertEqual(result.policy_id, "EMERGENCY-CONTROL")
        self.plane.emergency.deactivate(EmergencyControl.GLOBAL_STOP, "test-operator-key")
        self.assertTrue(self._act("web.search", tool="web_search", payload={"query": "x"}).allowed)

    def test_delegation_freeze(self):
        self.plane.grant("AGENT-1", "agent.delegate")
        self.plane.emergency.activate(EmergencyControl.DELEGATION_FREEZE, "test-operator-key")
        result = self._act("agent.delegate", target_agent="AGENT-1", payload={"capabilities": []})
        self.assertEqual(result.policy_id, "EMERGENCY-CONTROL")


class QuarantineTests(unittest.TestCase):
    def setUp(self):
        self.plane, self.observatory, self.immune, self.sentinel = build_stack()
        self.contract = provision_agent(
            self.plane, "AGENT-1", ("web.search", "database.read"), tools=("web_search", "research_db")
        )

    def test_quarantine_routes_to_sandbox_and_blocks_network(self):
        self.plane.containment.quarantine(self.plane.root, "AGENT-1", "test", verification_ref="root")
        search = self.plane.submit("AGENT-1", "web.search", tool="web_search", task_id=self.contract.contract_id, payload={"query": "x"})
        self.assertTrue(search.output["synthetic"])
        egress = self.plane.submit(
            "AGENT-1", "network.egress", tool="http_out", task_id=self.contract.contract_id,
            endpoint="collector.example.io", payload={"endpoint": "collector.example.io"},
        )
        self.assertTrue(egress.output["blocked"])
        self.assertEqual(self.plane.registry.invocations, [])

    def test_replay_is_deterministic(self):
        self.plane.containment.quarantine(self.plane.root, "AGENT-1", "test", verification_ref="root")
        for index in range(4):
            self.plane.submit("AGENT-1", "web.search", tool="web_search", task_id=self.contract.contract_id, payload={"query": f"q{index}"})
        environment = self.plane.quarantine.environment_for("AGENT-1")
        first = replay(environment)
        second = replay(environment)
        self.assertTrue(first.deterministic)
        self.assertEqual(first.replay_digest, second.replay_digest)

    def test_release_requires_authorization_and_restores_authority(self):
        self.plane.containment.quarantine(self.plane.root, "AGENT-1", "test", verification_ref="root")
        self.assertFalse(self.plane.authority.has("AGENT-1", "web.search"))
        reference = self.immune.authorizations.authorize("human-operator", "AGENT-1", "restore")
        self.plane.containment.release(self.plane.root, "AGENT-1", authorization_ref=reference)
        self.assertTrue(self.plane.authority.has("AGENT-1", "web.search"))
        self.assertFalse(self.plane.containment.is_quarantined("AGENT-1"))


class KeyExperimentTests(unittest.TestCase):
    def test_section_15_lifecycle_and_memory(self):
        result = run_key_experiment()
        agent_a = result["agent_a"]
        agent_b = result["agent_b"]

        self.assertTrue(agent_a["detection"])
        self.assertTrue(any(v["verdict"] == "CONFIRMED" for v in agent_a["independent_verification"]))
        self.assertIn("RESTRICT", agent_a["containment"])
        self.assertIn("QUARANTINE", agent_a["containment"])
        self.assertTrue(agent_a["quarantined"])
        self.assertTrue(all(report["deterministic_replay"] for report in agent_a["forensics"]))
        self.assertTrue(agent_a["signatures"])

        # Memory is evidence, not guilt: B is not contained on similarity alone.
        self.assertFalse(agent_b["contained_before_evidence"])
        self.assertEqual(agent_b["classification_before_behaviour"]["classification"], "NORMAL")
        self.assertTrue(agent_b["memory_matches_after"])
        self.assertIn("RESTRICT", agent_b["containment"])
        self.assertTrue(result["integrity"]["audit_valid"])
        self.assertTrue(result["integrity"]["policy_valid"])


class EcosystemTests(unittest.TestCase):
    def test_population_run_is_reproducible_and_contains_attackers(self):
        first = build_default_ecosystem(EcosystemConfig(sentinel_interval=4))
        metrics = first.run(20).report()
        second = build_default_ecosystem(EcosystemConfig(sentinel_interval=4))
        second.run(20)
        self.assertEqual(first.plane.audit.head_hash(), second.plane.audit.head_hash())
        self.assertEqual(metrics["detection"]["detection_rate"], 1.0)
        self.assertEqual(metrics["detection"]["false_positive_rate"], 0.0)
        self.assertEqual(metrics["governance"]["unauthorized_prevention_rate"], 1.0)
        self.assertEqual(metrics["defender_safety"]["defensive_agent_policy_violations"], 0)
        self.assertTrue(first.plane.verify_integrity()["audit_valid"])


if __name__ == "__main__":
    unittest.main()
