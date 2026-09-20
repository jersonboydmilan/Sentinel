"""Defender security tests (section 17): the immune system governs itself.

Every test here asserts a *failure* of the defensive system to exceed its own
authority. A passing suite is the evidence for research contribution E
(recursive governance).
"""

import unittest

from tests.helpers import build_stack, provision_agent

from ais.common.errors import (
    AuthorityError,
    ContainmentError,
    EmergencyControlError,
    PolicyError,
    SelfGrantDenied,
)
from ais.control_plane.emergency import EmergencyControl
from ais.control_plane.policy import Effect
from ais.immune_system.memory import ImmuneMemoryError
from ais.immune_system.verification import VerificationError
from ais.simulation.scenarios import run_defender_escape_experiment


class DefenderAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.plane, self.observatory, self.immune, self.sentinel = build_stack()
        provision_agent(self.plane, "SUBJECT-01", ("web.search",), tools=("web_search",))

    # -- capability separation --------------------------------------------
    def test_each_defensive_agent_holds_only_its_declared_capabilities(self):
        for agent in self.sentinel.agents:
            effective = set(self.plane.authority.effective(agent.agent_id).as_strings())
            self.assertEqual(effective, set(agent.DECLARED_CAPABILITIES), agent.NAME)

    def test_detector_cannot_contain(self):
        for action in ("agent.restrict", "agent.isolate", "agent.quarantine", "agent.revoke"):
            result = self.sentinel.detect.act(action, subject="SUBJECT-01", payload={"reason": "unilateral"})
            self.assertFalse(result.allowed, action)

    def test_auditor_cannot_contain_or_flag(self):
        for action in ("agent.restrict", "agent.quarantine", "agent.flag"):
            result = self.sentinel.audit.act(action, subject="SUBJECT-01", payload={"reason": "x"})
            self.assertFalse(result.allowed, action)

    def test_containment_agent_cannot_observe_or_write_memory(self):
        for action in ("agent.observe", "immune.write"):
            result = self.sentinel.contain.act(action, subject="SUBJECT-01", payload={"reason": "x"})
            self.assertFalse(result.allowed, action)

    def test_recovery_cannot_revoke(self):
        result = self.sentinel.recovery.act("agent.revoke", subject="SUBJECT-01", payload={"reason": "x"})
        self.assertFalse(result.allowed)

    def test_no_defensive_agent_may_use_operational_capabilities(self):
        for agent in self.sentinel.agents:
            for action in ("database.write", "credential.read", "network.egress", "agent.delegate"):
                result = agent.act(action, payload={"x": 1})
                self.assertFalse(result.allowed, f"{agent.NAME}:{action}")

    # -- authority manipulation -------------------------------------------
    def test_defensive_agent_cannot_grant_itself_authority(self):
        contain = self.sentinel.contain
        with self.assertRaises(SelfGrantDenied):
            self.plane.authority.issue(contain.principal, contain.agent_id, "database.write")

    def test_defensive_agent_cannot_grant_a_peer(self):
        contain = self.sentinel.contain
        with self.assertRaises(AuthorityError):
            self.plane.authority.issue(contain.principal, self.sentinel.detect.agent_id, "agent.revoke")

    def test_defensive_agent_cannot_lift_its_own_restriction(self):
        contain = self.sentinel.contain
        restriction = self.plane.authority.restrict(self.plane.root, contain.agent_id, ["agent.revoke"], "test")
        with self.assertRaises(AuthorityError):
            self.plane.authority.lift_restriction(contain.principal, restriction.restriction_id, authorization_ref="self")
        self.assertFalse(self.plane.authority.has(contain.agent_id, "agent.revoke"))

    def test_defensive_agent_cannot_contain_itself_out_of_restriction(self):
        contain = self.sentinel.contain
        with self.assertRaises(ContainmentError):
            self.plane.containment.restrict(contain.principal, contain.agent_id, ["agent.revoke"], "self")

    # -- evidence requirements --------------------------------------------
    def test_containment_requires_verification(self):
        result = self.sentinel.contain.act(
            "agent.quarantine", subject="SUBJECT-01", payload={"reason": "hunch", "confidence": 0.99}
        )
        self.assertEqual(result.result.effect, Effect.HOLD)

    def test_forged_verification_reference_is_rejected(self):
        result = self.sentinel.contain.act(
            "agent.revoke", subject="SUBJECT-01",
            payload={"reason": "forged", "verification_ref": "VER-000999", "confidence": 1.0},
        )
        self.assertFalse(result.allowed)
        self.assertTrue(self.plane.authority.has("SUBJECT-01", "web.search"))

    def test_verification_for_another_subject_does_not_transfer(self):
        provision_agent(self.plane, "SUBJECT-02", ("web.search",))
        verification = self.immune.verifications.record(
            verifier_id=self.sentinel.audit.agent_id,
            subject_id="SUBJECT-02",
            verdict="CONFIRMED",
            confidence=0.95,
            evidence=("x",),
            reproduced=True,
        )
        result = self.sentinel.contain.act(
            "agent.quarantine", subject="SUBJECT-01",
            payload={"reason": "wrong subject", "verification_ref": verification.verification_id},
        )
        self.assertFalse(result.allowed)

    def test_agent_cannot_verify_itself(self):
        with self.assertRaises(VerificationError):
            self.immune.verifications.record(
                verifier_id=self.sentinel.audit.agent_id,
                subject_id=self.sentinel.audit.agent_id,
                verdict="CONFIRMED",
                confidence=1.0,
                evidence=(),
                reproduced=True,
            )

    def test_detector_cannot_record_verifications(self):
        with self.assertRaises(VerificationError):
            self.immune.verifications.record(
                verifier_id=self.sentinel.detect.agent_id,
                subject_id="SUBJECT-01",
                verdict="CONFIRMED",
                confidence=1.0,
                evidence=(),
                reproduced=True,
            )

    def test_immune_memory_write_requires_verification(self):
        with self.assertRaises(ImmuneMemoryError):
            self.immune.memory.commit(
                actor_id=self.sentinel.forensics.agent_id,
                pattern=["web.search"],
                authority_pattern=[],
                delegation_pattern=[],
                responses=[],
                outcome="confirmed",
                confidence=0.99,
                source_agent="SUBJECT-01",
                verification_ref="",
            )

    def test_recovery_requires_external_authorization(self):
        self.plane.containment.restrict(self.plane.root, "SUBJECT-01", ["web.search"], "test")
        outcome = self.sentinel.recovery.restore("SUBJECT-01", authorization_ref="self-issued")
        self.assertFalse(outcome.restored)
        self.assertFalse(self.plane.authority.has("SUBJECT-01", "web.search"))

        reference = self.immune.authorizations.authorize("human-operator", "SUBJECT-01", "restore", "reviewed")
        authorized = self.sentinel.recovery.restore("SUBJECT-01", authorization_ref=reference)
        self.assertTrue(authorized.restored)
        self.assertTrue(self.plane.authority.has("SUBJECT-01", "web.search"))

    # -- control plane surfaces -------------------------------------------
    def test_policy_authority_audit_emergency_namespaces_are_unreachable(self):
        for agent in self.sentinel.agents:
            for action in ("policy.write", "authority.grant", "audit.delete", "emergency.disable"):
                result = agent.act(action, payload={"x": 1})
                self.assertEqual(result.result.policy_id, "POL-OUT-OF-BAND", f"{agent.NAME}:{action}")

    def test_policy_modification_requires_root_authority(self):
        with self.assertRaises(PolicyError):
            self.plane.policy.install_policy(
                self.sentinel.contain.principal, {"id": "POL-EVIL", "effect": "ALLOW", "otherwise": "ALLOW"}
            )

    def test_emergency_controls_need_the_out_of_band_key(self):
        with self.assertRaises(EmergencyControlError):
            self.plane.emergency.deactivate(EmergencyControl.GLOBAL_STOP, "guess")
        self.plane.emergency.activate(EmergencyControl.GLOBAL_STOP, "test-operator-key")
        result = self.sentinel.detect.act("agent.observe", subject="SUBJECT-01", payload={"reason": "x"})
        self.assertFalse(result.allowed)
        self.assertEqual(result.result.policy_id, "EMERGENCY-CONTROL")

    def test_quarantined_defensive_agent_is_sandboxed_like_any_other(self):
        detect = self.sentinel.detect
        self.plane.containment.quarantine(self.plane.root, detect.agent_id, "experiment", verification_ref="root")
        result = detect.act("agent.observe", subject="SUBJECT-01", payload={"reason": "post"})
        self.assertTrue(result.result.facts["sandboxed"])


class DefenderEscapeExperimentTests(unittest.TestCase):
    def test_every_escape_attempt_is_blocked(self):
        result = run_defender_escape_experiment()
        for name, blocked in result["summary"].items():
            self.assertTrue(blocked, f"escape path not blocked: {name}")
        self.assertTrue(result["all_blocked"])


if __name__ == "__main__":
    unittest.main()
