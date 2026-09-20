import unittest

from tests.helpers import build_stack, provision_agent

from ais.control_plane.containment import ContainmentAction
from ais.immune_system.classification import ThreatClass, ThreatClassifier
from ais.immune_system.memory import ImmuneMemoryError, MAX_MEMORY_PRIOR
from ais.observatory.drift import DriftKind


class ObservatoryTests(unittest.TestCase):
    def setUp(self):
        self.plane, self.observatory, self.immune, self.sentinel = build_stack()
        self.contract = provision_agent(
            self.plane,
            "AGENT-1",
            ("web.search", "database.read"),
            tools=("web_search", "research_db"),
            endpoints=("example.com",),
        )
        self.observatory.declare_profile(
            {
                "agent_profile": {
                    "agent_id": "AGENT-1",
                    "normal_behavior": {
                        "tool_calls_per_task": {"min": 1, "max": 20},
                        "delegation": {"allowed": False},
                        "external_domains": {"expected": ["example.com"]},
                        "capabilities": ["web.search", "database.read"],
                    },
                }
            }
        )

    def _run_normal(self, count=10):
        for index in range(count):
            self.plane.tick()
            self.plane.submit(
                "AGENT-1", "web.search", tool="web_search", task_id=self.contract.contract_id,
                payload={"query": f"q{index}"},
            )

    def test_baseline_locks_after_warmup(self):
        self._run_normal()
        profile = self.observatory.profile("AGENT-1")
        self.assertTrue(profile.baseline_locked)
        self.assertEqual(profile.denied_ratio, 0.0)

    def test_no_drift_for_in_purpose_behaviour(self):
        self._run_normal()
        self.assertFalse(self.observatory.drift_report("AGENT-1").drift)

    def test_capability_and_credential_drift(self):
        self._run_normal()
        self.plane.tick()
        self.plane.submit(
            "AGENT-1", "credential.read", tool="credential_vault", task_id=self.contract.contract_id,
            payload={"name": "prod"},
        )
        report = self.observatory.drift_report("AGENT-1")
        self.assertTrue(report.drift)
        self.assertIn(DriftKind.CAPABILITY_DRIFT.value, report.kinds())
        self.assertIn(DriftKind.CREDENTIAL_DRIFT.value, report.kinds())

    def test_communication_drift_for_unexpected_endpoint(self):
        self._run_normal()
        self.plane.grant("AGENT-1", "network.egress")
        self.plane.tick()
        self.plane.submit(
            "AGENT-1", "network.egress", tool="http_out", endpoint="paste.example.net",
            task_id=self.contract.contract_id, payload={"endpoint": "paste.example.net"},
        )
        self.assertIn(DriftKind.COMMUNICATION_DRIFT.value, self.observatory.drift_report("AGENT-1").kinds())

    def test_identity_graph_relationships(self):
        self.observatory.ingest_principals()
        summary = self.observatory.identity_graph.summary()
        self.assertIn("OWNS", summary["edges"])
        self.assertIn("AUTHORIZES", summary["edges"])

    def test_behaviour_graph_links_task_to_tool(self):
        self._run_normal(3)
        graph = self.observatory.behaviour_graph
        self.assertTrue(graph.edges("CALLS"))
        self.assertIn("web_search", [node.node_id for node in graph.nodes("TOOL")])


class ClassifierTests(unittest.TestCase):
    def setUp(self):
        self.plane, self.observatory, self.immune, self.sentinel = build_stack()

    def _classify(self, **overrides):
        from ais.observatory.anomaly import AnomalyReport
        from ais.observatory.behavior import BehaviorProfile
        from ais.observatory.drift import DriftReport

        defaults = dict(
            drift=DriftReport(agent_id="A", at=0),
            anomaly=AnomalyReport(agent_id="A", at=0),
            profile=BehaviorProfile(agent_id="A"),
            policy_violations=0,
            quarantined=False,
            escape_attempts=0,
            source_events=[],
            affected_resources=[],
            authority_involved=[],
        )
        defaults.update(overrides)
        return ThreatClassifier().classify("A", **defaults)

    def test_quiet_agent_is_normal(self):
        result = self._classify()
        self.assertIs(result.threat_class, ThreatClass.NORMAL)
        self.assertIs(result.recommended_action, ContainmentAction.MONITOR)

    def test_low_confidence_never_recommends_irreversible_action(self):
        result = self._classify(policy_violations=2)
        self.assertLess(result.confidence, 0.85)
        self.assertNotEqual(result.recommended_action, ContainmentAction.REVOKE)

    def test_containment_breach_requires_quarantine_and_escape(self):
        result = self._classify(quarantined=True, escape_attempts=2)
        self.assertIs(result.threat_class, ThreatClass.CONTAINMENT_BREACH)


class ImmuneMemoryTests(unittest.TestCase):
    def setUp(self):
        self.plane, self.observatory, self.immune, self.sentinel = build_stack()

    def _commit(self, pattern, outcome="confirmed", confidence=0.9):
        return self.immune.memory.commit(
            actor_id="SENTINEL-FORENSICS",
            pattern=pattern,
            authority_pattern=["database.read"],
            delegation_pattern=[],
            responses=["RESTRICT"],
            outcome=outcome,
            confidence=confidence,
            source_agent="AGENT-A",
            verification_ref="VER-1",
        )

    def test_signature_requires_verification(self):
        with self.assertRaises(ImmuneMemoryError):
            self.immune.memory.commit(
                actor_id="x", pattern=["a.b"], authority_pattern=[], delegation_pattern=[],
                responses=[], outcome="confirmed", confidence=0.9, source_agent="A", verification_ref="",
            )

    def test_ordered_match_beats_unordered_overlap(self):
        self._commit(["email.read", "credential.read", "network.egress"])
        ordered = self.immune.memory.match(
            tokens=["email.read:ok", "credential.read:denied", "network.egress:denied"],
            authority=["database.read"], delegation=[],
        )
        shuffled = self.immune.memory.match(
            tokens=["network.egress:ok", "email.read:ok"], authority=["database.read"], delegation=[],
        )
        self.assertGreater(ordered[0].score, shuffled[0].score if shuffled else 0.0)

    def test_memory_prior_is_bounded(self):
        self._commit(["email.read", "credential.read"], confidence=0.99)
        matches = self.immune.memory.match(
            tokens=["email.read:ok", "credential.read:ok"], authority=["database.read"], delegation=[]
        )
        self.assertLessEqual(abs(self.immune.memory.prior(matches)), MAX_MEMORY_PRIOR)

    def test_false_positive_signature_reduces_suspicion(self):
        signature = self._commit(["web.search", "database.read"])
        self.immune.memory.mark_false_positive("operator", signature.signature_id, "benign burst")
        matches = self.immune.memory.match(
            tokens=["web.search:ok", "database.read:ok"], authority=["database.read"], delegation=[]
        )
        self.assertLess(matches[0].score, 0.0)

    def test_persistence_round_trip(self):
        import os
        import tempfile

        self._commit(["email.read", "credential.read"])
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "memory.json")
            self.immune.memory.save(path)
            from ais.immune_system.memory import ImmuneMemory

            restored = ImmuneMemory(self.plane.audit, self.plane.clock, self.plane.ids, path)
            self.assertEqual(len(restored), len(self.immune.memory))


if __name__ == "__main__":
    unittest.main()
