"""The learning adversary: what adaptation buys, and what it costs.

These tests deliberately do **not** assert that the adaptive adversary is caught
as fast as the naive one. It is not, and pretending otherwise would be the kind
of claim this project exists to avoid. What they assert is the part that must
hold regardless of how clever the adversary is: it never obtains a real effect
it was not authorised for, the invariants stay clean, and when it converges to
acting inside its authority, the relationship layer - not containment - is what
picks it up.
"""

import unittest

from ais.simulation.scenarios import run_learning_adversary_experiment


class LearningAdversaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = run_learning_adversary_experiment(steps=40, undefended_steps=90)

    # -- adaptation --------------------------------------------------------
    def test_learner_does_not_retry_denied_capabilities(self):
        retries = self.result["adaptation"]["retries_of_denied_capabilities"]
        self.assertEqual(retries["learner"], 0)
        self.assertGreater(retries["naive"], 0)

    def test_learner_keeps_its_denial_ratio_low(self):
        ratios = self.result["adaptation"]["denial_ratio"]
        self.assertLess(ratios["learner"], ratios["naive"])

    def test_adaptation_delays_verified_detection(self):
        naive = self.result["naive"]["time_to_detection_steps"]
        learner = self.result["learner_defended"]["time_to_detection_steps"]
        self.assertIsNotNone(naive)
        self.assertIsNotNone(learner)
        # The finding is the delay itself; it must be reported, not assumed away.
        self.assertGreaterEqual(learner, naive)
        self.assertEqual(self.result["adaptation"]["evasion_gain_steps"], learner - naive)

    def test_learner_converges_to_acting_inside_its_authority(self):
        state = self.result["learner_undefended"]["agent_state"]
        self.assertEqual(state["strategy"], "blend")
        self.assertEqual(len(state["denied_capabilities"]), 4)
        self.assertGreater(state["briefings"], 0)

    def test_relationship_layer_catches_the_converged_strategy(self):
        signals = self.result["adaptation"]["collusion_signals_after_convergence"]
        self.assertTrue(signals, "converged learner produced no collusion signal")
        best = signals[0]
        self.assertEqual({best["source"], best["partner"]}, {"LEARNER-01", "COURIER-01"})
        self.assertIn("capability_complementarity:True", best["evidence"])

    # -- enforcement -------------------------------------------------------
    def test_no_arm_produces_a_real_unauthorized_effect(self):
        enforcement = self.result["enforcement"]
        self.assertEqual(enforcement["naive_real_effects"], [])
        self.assertEqual(enforcement["learner_real_effects"], [])
        self.assertEqual(enforcement["learner_real_effects_undefended"], [])

    def test_prevention_and_invariants_are_unaffected_by_adaptation(self):
        enforcement = self.result["enforcement"]
        for arm, rate in enforcement["prevention_rate"].items():
            self.assertEqual(rate, 1.0, arm)
        for arm, ok in enforcement["invariants_ok"].items():
            self.assertTrue(ok, arm)

    def test_quarantine_deceives_the_adversary_about_its_own_success(self):
        believed = self.result["enforcement"]["believed_success_vs_real"]
        self.assertTrue(believed["believes_goal_achieved"])
        self.assertEqual(believed["real_effects"], 0)

    def test_escalation_does_not_depend_on_the_defensive_cycle(self):
        # Arm C runs with the defensive cycle effectively disabled, yet the
        # collusion chain is still held at the gateway by POL-060.
        ecosystem = self.result["ecosystems"]["undefended"]
        events = ecosystem.observatory.telemetry.events("COURIER-01")
        self.assertTrue(any(event.decision == "ESCALATE" for event in events))
        self.assertEqual(ecosystem.plane.containment.history("COURIER-01"), [])


if __name__ == "__main__":
    unittest.main()
