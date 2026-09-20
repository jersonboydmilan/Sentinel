import unittest

from tests.helpers import build_plane, provision_agent

from ais.common.errors import AuthorityError, AuthorityRevoked, SelfGrantDenied


class AuthorityServiceTests(unittest.TestCase):
    def setUp(self):
        self.plane = build_plane()
        provision_agent(self.plane, "AGENT-1", ("database.read",))
        self.agent = self.plane.identity.get("AGENT-1")

    def test_default_deny(self):
        self.assertFalse(self.plane.authority.has("AGENT-1", "database.write"))

    def test_self_grant_is_refused(self):
        with self.assertRaises(SelfGrantDenied):
            self.plane.authority.issue(self.agent, "AGENT-1", "database.write")

    def test_non_root_cannot_grant_without_delegable_source(self):
        provision_agent(self.plane, "AGENT-2", ())
        with self.assertRaises(AuthorityError):
            self.plane.authority.issue(self.agent, "AGENT-2", "database.read")

    def test_revocation_is_immediate(self):
        self.assertTrue(self.plane.authority.has("AGENT-1", "database.read"))
        self.plane.authority.revoke_capability(self.plane.root, "AGENT-1", "database.read", "test")
        self.assertFalse(self.plane.authority.has("AGENT-1", "database.read"))
        with self.assertRaises(AuthorityRevoked):
            self.plane.authority.assert_usable("AGENT-1", "database.read")

    def test_expiry_is_enforced(self):
        self.plane.grant("AGENT-1", "file.read", expires_at=self.plane.clock.now + 2)
        self.assertTrue(self.plane.authority.has("AGENT-1", "file.read"))
        self.plane.tick(5)
        self.assertFalse(self.plane.authority.has("AGENT-1", "file.read"))

    def test_restriction_is_reversible_and_externally_authorized(self):
        restriction = self.plane.authority.restrict(self.plane.root, "AGENT-1", ["database.read"], "test")
        self.assertFalse(self.plane.authority.has("AGENT-1", "database.read"))
        self.assertTrue(self.plane.authority.granted("AGENT-1").holds("database.read"))
        with self.assertRaises(AuthorityError):
            self.plane.authority.lift_restriction(self.agent, restriction.restriction_id, authorization_ref="self")
        self.plane.authority.lift_restriction(self.plane.root, restriction.restriction_id, authorization_ref="AUTH-1")
        self.assertTrue(self.plane.authority.has("AGENT-1", "database.read"))

    def test_revocation_cascades_to_derived_grants(self):
        provision_agent(self.plane, "AGENT-3", ())
        parent = self.plane.grant("AGENT-1", "web.search", delegable=True, delegation_depth=2)
        self.plane.grant("AGENT-1", "agent.delegate")
        child = self.plane.authority.issue(self.agent, "AGENT-3", "web.search")
        self.plane.authority.revoke_grant(self.plane.root, parent.grant_id, "test")
        self.assertTrue(self.plane.authority.is_revoked(child.grant_id))
        self.assertFalse(self.plane.authority.has("AGENT-3", "web.search"))

    def test_explain_reports_why(self):
        detail = self.plane.authority.explain("AGENT-1", "database.write")
        self.assertFalse(detail["granted"])
        self.assertFalse(detail["effective"])


if __name__ == "__main__":
    unittest.main()
