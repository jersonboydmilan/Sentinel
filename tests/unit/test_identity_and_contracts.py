import unittest

from tests.helpers import build_plane, provision_agent

from ais.common.errors import (
    AuthenticationFailed,
    ContractError,
    ContractIntegrityError,
    ImpersonationDetected,
)
from ais.control_plane.identity import PrincipalKind


class IdentityTests(unittest.TestCase):
    def setUp(self):
        self.plane = build_plane()
        provision_agent(self.plane, "AGENT-1", ("database.read",))
        provision_agent(self.plane, "AGENT-2", ("database.read",))

    def test_valid_credential_authenticates(self):
        token = self.plane.credential("AGENT-1")
        principal = self.plane.identity.authenticate("AGENT-1", token)
        self.assertEqual(principal.principal_id, "AGENT-1")

    def test_missing_credential_is_refused(self):
        with self.assertRaises(AuthenticationFailed):
            self.plane.identity.authenticate("AGENT-1", None)

    def test_impersonation_is_named_as_such(self):
        other = self.plane.credential("AGENT-2")
        with self.assertRaises(ImpersonationDetected) as ctx:
            self.plane.identity.authenticate("AGENT-1", other)
        self.assertEqual(ctx.exception.context["actual"], "AGENT-2")


class ContractTests(unittest.TestCase):
    def setUp(self):
        self.plane = build_plane()
        self.contract = provision_agent(
            self.plane, "AGENT-1", ("database.read",), tools=("research_db",), datasets=("public_papers",)
        )

    def test_agents_cannot_issue_contracts(self):
        agent = self.plane.identity.get("AGENT-1")
        with self.assertRaises(ContractError):
            self.plane.contracts.create(agent, "AGENT-1", "self-authored", ["database.write"])

    def test_seal_detects_mutation(self):
        self.contract.declared_capabilities = ("database.read", "database.write")
        with self.assertRaises(ContractIntegrityError):
            self.contract.verify_integrity()

    def test_scope_check(self):
        ok = self.plane.contracts.check(
            self.contract, agent_id="AGENT-1", capability="database.read", tool="research_db", data="public_papers"
        )
        self.assertTrue(ok.ok)
        bad = self.plane.contracts.check(
            self.contract, agent_id="AGENT-1", capability="database.write", tool="records_db_write"
        )
        self.assertFalse(bad.ok)
        self.assertIn("capability_outside_declared_purpose", bad.reasons)

    def test_budget_exhaustion(self):
        contract = provision_agent(self.plane, "AGENT-2", ("database.read",), max_tool_calls=1)
        self.plane.contracts.consume(contract)
        check = self.plane.contracts.check(contract, agent_id="AGENT-2", capability="database.read")
        self.assertIn("tool_call_budget_exhausted", check.reasons)

    def test_only_issuer_may_amend(self):
        agent = self.plane.identity.get("AGENT-1")
        with self.assertRaises(ContractError):
            self.plane.contracts.amend(agent, self.contract.contract_id, purpose="widened")
        amended = self.plane.contracts.amend(self.plane.root, self.contract.contract_id, purpose="widened")
        amended.verify_integrity()


if __name__ == "__main__":
    unittest.main()
