"""Tests for the runtime invariant checker."""

import unittest

from tests.helpers import build_plane, build_stack, provision_agent

from ais.control_plane.invariants import InvariantChecker, InvariantViolation


class InvariantCheckerTests(unittest.TestCase):
    def setUp(self):
        self.plane = build_plane()
        self.checker = InvariantChecker(self.plane).bind()
        self.contract = provision_agent(
            self.plane, "AGENT-1", ("web.search",), tools=("web_search",)
        )

    def test_clean_run_has_no_violations(self):
        for index in range(5):
            self.plane.tick()
            self.plane.submit(
                "AGENT-1", "web.search", tool="web_search", task_id=self.contract.contract_id,
                payload={"query": index},
            )
        report = self.checker.check()
        self.assertTrue(report.ok, report.as_dict())
        self.assertEqual(report.checked, 8)

    def test_gateway_bypass_is_detected(self):
        self.assertTrue(self.checker.check().ok)
        self.plane.registry.invoke("web_search", "web.search", {"query": "direct"})
        report = self.checker.check()
        self.assertFalse(report.ok)
        self.assertEqual({v.invariant for v in report.violations}, {"P1", "P8"})

    def test_defensive_agent_holding_operational_capability_is_detected(self):
        plane, observatory, immune, sentinel = build_stack()
        checker = InvariantChecker(plane)
        self.assertTrue(checker.check().ok)
        # Simulate a provisioning mistake: root grants an operational capability
        # to a defensive principal. Nothing in the request path did this, which
        # is exactly why a state-level invariant is needed.
        plane.grant(sentinel.contain.agent_id, "database.write")
        report = checker.check()
        self.assertFalse(report.ok)
        self.assertIn("P4", {v.invariant for v in report.violations})

    def test_strict_mode_raises_on_violation(self):
        checker = InvariantChecker(self.plane, strict=True)
        self.plane.registry.invoke("web_search", "web.search", {"query": "direct"})
        with self.assertRaises(InvariantViolation):
            checker._on_decision(type("R", (), {"allowed": False})())

    def test_violations_are_audited(self):
        self.plane.registry.invoke("web_search", "web.search", {"query": "direct"})
        self.checker.check()
        self.assertTrue(self.plane.audit.search(event_type="invariant.violation"))


class ContextBoundGrantTests(unittest.TestCase):
    def setUp(self):
        self.plane = build_plane()
        self.contract_a = provision_agent(
            self.plane, "AGENT-1", ("web.search",), tools=("web_search", "file_writer")
        )
        self.contract_b = self.plane.commission(
            "AGENT-1", "second task", ["web.search", "file.write"],
            allowed_tools=["web_search", "file_writer"], max_duration=10_000,
        )

    def test_grant_bound_to_one_contract_is_unusable_elsewhere(self):
        self.plane.authority.issue(
            self.plane.root, "AGENT-1", "file.write", scope={"task_id": self.contract_b.contract_id}
        )
        allowed = self.plane.submit(
            "AGENT-1", "file.write", tool="file_writer", task_id=self.contract_b.contract_id,
            payload={"path": "a", "content": "b"},
        )
        denied = self.plane.submit(
            "AGENT-1", "file.write", tool="file_writer", task_id=self.contract_a.contract_id,
            payload={"path": "a", "content": "b"},
        )
        self.assertTrue(allowed.allowed)
        self.assertFalse(denied.allowed)
        self.assertIn("capability_not_held", denied.reasons)

    def test_context_bound_grants_are_excluded_without_a_task(self):
        self.plane.authority.issue(
            self.plane.root, "AGENT-1", "file.write", scope={"task_id": self.contract_b.contract_id}
        )
        self.assertFalse(self.plane.authority.has("AGENT-1", "file.write"))
        self.assertTrue(
            self.plane.authority.has("AGENT-1", "file.write", task_id=self.contract_b.contract_id)
        )

    def test_explain_reports_context_binding(self):
        self.plane.authority.issue(
            self.plane.root, "AGENT-1", "file.write", scope={"task_id": self.contract_b.contract_id}
        )
        detail = self.plane.authority.explain("AGENT-1", "file.write", task_id=self.contract_a.contract_id)
        self.assertTrue(detail["context_bound_elsewhere"])
        self.assertFalse(detail["effective"])


if __name__ == "__main__":
    unittest.main()
