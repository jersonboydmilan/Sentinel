"""Cross-process verification: the two-party property made physical.

The in-process auditor is logically independent (it reads only the audit chain)
but shares address space with what it audits. These tests exercise a verifier
that runs as a separate OS process and receives nothing but the serialised
chain.
"""

import io
import os
import unittest

from tests.helpers import build_stack, provision_agent

from ais.control_plane.policy import Effect
from ais.defensive_agents.remote_auditor import SentinelAuditRemote
from ais.simulation.scenarios import run_cross_process_verification_experiment
from ais.verifier import protocol, reconstruction, service
from ais.verifier.client import RemoteVerifier


def drive_agent(plane, agent_id, contract, *, clean=6, unauthorized=(("credential.read", "credential_vault"),)):
    for index in range(clean):
        plane.tick()
        plane.submit(agent_id, "web.search", tool="web_search", task_id=contract.contract_id, payload={"q": index})
    for action, tool in unauthorized:
        plane.tick()
        plane.submit(agent_id, action, tool=tool, task_id=contract.contract_id, payload={})


class ReconstructionTests(unittest.TestCase):
    """The pure module the verifier process runs, tested without a process."""

    def setUp(self):
        self.plane, self.observatory, self.immune, self.sentinel = build_stack()
        contract = provision_agent(self.plane, "SUBJ-01", ("web.search",), tools=("web_search",))
        drive_agent(
            self.plane, "SUBJ-01", contract,
            unauthorized=(("credential.read", "credential_vault"), ("network.egress", "http_out")),
        )
        self.records = reconstruction.export_records(self.plane.audit)

    def test_chain_verifies_and_head_matches(self):
        chain = reconstruction.verify_chain(self.records)
        self.assertTrue(chain["valid"])
        self.assertEqual(chain["head"], self.plane.audit.head_hash())

    def test_authority_derived_from_chain_matches_the_authority_service(self):
        derived = reconstruction.authority_of(self.records, "SUBJ-01")
        self.assertEqual(derived["granted"], self.plane.authority.granted("SUBJ-01").as_strings())
        self.assertEqual(derived["effective"], self.plane.authority.effective("SUBJ-01").as_strings())

    def test_revocation_and_restriction_are_reflected(self):
        self.plane.authority.restrict(self.plane.root, "SUBJ-01", ["web.search"], "test")
        records = reconstruction.export_records(self.plane.audit)
        self.assertEqual(reconstruction.authority_of(records, "SUBJ-01")["effective"], [])
        self.plane.authority.revoke_capability(self.plane.root, "SUBJ-01", "web.search", "test")
        records = reconstruction.export_records(self.plane.audit)
        self.assertEqual(reconstruction.authority_of(records, "SUBJ-01")["granted"], [])

    def test_tampered_record_breaks_the_chain(self):
        doctored = [dict(record) for record in self.records]
        doctored[3]["payload"] = {"forged": True}
        chain = reconstruction.verify_chain(doctored)
        self.assertFalse(chain["valid"])
        self.assertEqual(chain["broken_at"], 3)

    def test_verdict_requires_supporting_predicates(self):
        supported = reconstruction.verdict_for(self.records, "SUBJ-01", "COMPROMISED", 1.0)
        self.assertEqual(supported["verdict"], "CONFIRMED")
        unsupported = reconstruction.verdict_for(self.records, "SENTINEL-DETECT", "COMPROMISED", 1.0)
        self.assertEqual(unsupported["verdict"], "INCONCLUSIVE")

    def test_broken_chain_is_rejected_not_merely_inconclusive(self):
        doctored = [dict(record) for record in self.records]
        doctored[2]["payload"] = {"forged": True}
        result = reconstruction.verdict_for(doctored, "SUBJ-01", "COMPROMISED", 1.0)
        self.assertEqual(result["verdict"], "REJECTED")
        self.assertIn("audit_chain_broken", result["evidence"])


class ProtocolTests(unittest.TestCase):
    def test_signature_covers_the_payload(self):
        payload = {"op": "verify", "subject_id": "A"}
        wrapped = protocol.signed("key", payload)
        self.assertTrue(protocol.verify_signature("key", wrapped))
        self.assertFalse(protocol.verify_signature("other-key", wrapped))
        tampered = {**wrapped, "subject_id": "B"}
        self.assertFalse(protocol.verify_signature("key", tampered))

    def test_service_refuses_unsigned_requests(self):
        out = io.StringIO()
        request = {"op": "ping", "version": protocol.PROTOCOL_VERSION, "request_id": "1", "nonce": "n"}
        service.serve("key", stdin=io.StringIO(protocol.encode(request) + "\n"), stdout=out)
        response = protocol.decode(out.getvalue().strip())
        self.assertEqual(response["reason"], "bad_request_signature")

    def test_service_refuses_a_protocol_version_mismatch(self):
        out = io.StringIO()
        request = protocol.signed("key", {"op": "ping", "version": "other/9", "request_id": "1", "nonce": "n"})
        service.serve("key", stdin=io.StringIO(protocol.encode(request) + "\n"), stdout=out)
        self.assertEqual(protocol.decode(out.getvalue().strip())["reason"], "protocol_version_mismatch")


class RemoteVerifierProcessTests(unittest.TestCase):
    def setUp(self):
        self.plane, self.observatory, self.immune, self.sentinel = build_stack()
        self.contract = provision_agent(self.plane, "SUBJ-01", ("web.search",), tools=("web_search",))
        drive_agent(
            self.plane, "SUBJ-01", self.contract,
            unauthorized=(("credential.read", "credential_vault"), ("network.egress", "http_out")),
        )
        self.verifier = RemoteVerifier(timeout=20.0)
        self.verifier.start()

    def tearDown(self):
        self.verifier.close()

    def test_runs_in_a_separate_process(self):
        pong = self.verifier.ping()
        self.assertEqual(pong["op"], "pong")
        self.assertNotEqual(pong["pid"], os.getpid())
        self.assertEqual(pong["pid"], self.verifier.pid)

    def test_confirms_a_supported_claim(self):
        response = self.verifier.verify(
            audit=self.plane.audit, subject_id="SUBJ-01",
            claimed_classification="COMPROMISED", claimed_confidence=1.0,
        )
        self.assertEqual(response["verdict"], "CONFIRMED")
        self.assertTrue(response["chain_valid"])
        self.assertEqual(response["chain_head"], self.plane.audit.head_hash())

    def test_refuses_an_unsupported_claim(self):
        response = self.verifier.verify(
            audit=self.plane.audit, subject_id="SENTINEL-DETECT",
            claimed_classification="COMPROMISED", claimed_confidence=1.0,
        )
        self.assertEqual(response["verdict"], "INCONCLUSIVE")

    def test_rejects_a_doctored_chain(self):
        records = reconstruction.export_records(self.plane.audit)
        records[4] = {**records[4], "payload": {"decision": "ALLOW", "forged": True}}
        response = self.verifier.verify(
            audit=self.plane.audit, subject_id="SUBJ-01",
            claimed_classification="COMPROMISED", claimed_confidence=1.0,
            records=records, expected_head=self.plane.audit.head_hash(),
        )
        self.assertEqual(response["verdict"], "REJECTED")
        self.assertFalse(response["chain_valid"])

    def test_rejects_a_head_hash_the_records_do_not_produce(self):
        response = self.verifier.verify(
            audit=self.plane.audit, subject_id="SUBJ-01",
            claimed_classification="COMPROMISED", claimed_confidence=1.0,
            expected_head="f" * 64,
        )
        self.assertEqual(response["verdict"], "REJECTED")
        self.assertIn("chain_head_mismatch", response["evidence"])

    def test_cannot_confirm_without_evidence(self):
        response = self.verifier.verify(
            audit=self.plane.audit, subject_id="SUBJ-01",
            claimed_classification="COMPROMISED", claimed_confidence=1.0,
            records=[], expected_head="",
        )
        self.assertNotEqual(response["verdict"], "CONFIRMED")

    def test_verdict_signed_with_another_key_is_not_accepted(self):
        out = io.StringIO()
        request = protocol.signed(
            "attacker-key",
            protocol.VerifyRequest(
                request_id="X", nonce="n", subject_id="SUBJ-01",
                claimed_classification="COMPROMISED", claimed_confidence=1.0,
                expected_head="", records=[],
            ).as_payload(),
        )
        service.serve("attacker-key", stdin=io.StringIO(protocol.encode(request) + "\n"), stdout=out)
        forged = protocol.decode(out.getvalue().strip())
        self.assertFalse(protocol.verify_signature(self.verifier._key, forged))

    def test_outage_fails_closed(self):
        self.verifier.disable("test outage")
        response = self.verifier.verify(
            audit=self.plane.audit, subject_id="SUBJ-01",
            claimed_classification="COMPROMISED", claimed_confidence=1.0,
        )
        self.assertIsNone(response)
        self.assertEqual(self.verifier.stats.last_error, "test outage")
        self.verifier.enable()

    def test_crash_is_survivable_but_not_a_laundering_route(self):
        original = self.verifier.pid
        self.verifier._process.kill()
        self.verifier._process.wait(timeout=5)
        response = self.verifier.verify(
            audit=self.plane.audit, subject_id="SENTINEL-DETECT",
            claimed_classification="COMPROMISED", claimed_confidence=1.0,
        )
        self.assertIsNotNone(response)
        self.assertNotEqual(self.verifier.pid, original)
        self.assertNotEqual(response["verdict"], "CONFIRMED")


class RemoteAuditorTests(unittest.TestCase):
    def setUp(self):
        self.plane, self.observatory, self.immune, self.sentinel = build_stack()
        self.contract = provision_agent(self.plane, "SUBJ-01", ("web.search",), tools=("web_search",))
        drive_agent(
            self.plane, "SUBJ-01", self.contract,
            unauthorized=(("credential.read", "credential_vault"), ("network.egress", "http_out")),
        )
        self.remote = SentinelAuditRemote(self.plane, self.observatory, self.immune, timeout=20.0)

    def tearDown(self):
        self.remote.close()

    def test_holds_only_analysis_authority(self):
        effective = set(self.plane.authority.effective(self.remote.agent_id).as_strings())
        self.assertEqual(effective, set(SentinelAuditRemote.DECLARED_CAPABILITIES))
        for action in ("agent.restrict", "agent.quarantine", "agent.revoke", "database.write"):
            self.assertFalse(self.remote.act(action, subject="SUBJ-01", payload={}).allowed, action)

    def test_records_a_cross_process_verification(self):
        flag = self.sentinel.detect.scan(["SUBJ-01"])[0]
        verification = self.remote.verify(flag)
        self.assertIsNotNone(verification)
        self.assertEqual(verification.transport, "cross-process")
        self.assertEqual(verification.verifier_id, self.remote.agent_id)
        # The recorded head must be a real prefix of this chain: verifying and
        # recording both append records, so it is not the current head, but it
        # must be one the chain actually produced.
        prefixes = {record.record_hash for record in self.plane.audit.all()}
        self.assertIn(verification.chain_head, prefixes)

    def test_remote_verifier_counts_as_an_independent_verifier(self):
        flag = self.sentinel.detect.scan(["SUBJ-01"])[0]
        self.sentinel.audit.verify(flag)
        self.remote.verify(flag)
        verifiers = self.immune.verifications.independent_verifiers("SUBJ-01")
        self.assertIn(self.remote.agent_id, verifiers)
        self.assertGreaterEqual(len(verifiers), 2)

    def test_outage_records_unavailability_and_blocks_containment(self):
        flag = self.sentinel.detect.scan(["SUBJ-01"])[0]
        self.remote.verifier.disable("outage")
        self.assertIsNone(self.remote.verify(flag))
        self.assertTrue(self.plane.audit.search(event_type="verification.unavailable"))
        result = self.sentinel.contain.act(
            "agent.quarantine", subject="SUBJ-01", payload={"reason": "no verifier", "confidence": 0.99}
        )
        self.assertEqual(result.result.effect, Effect.HOLD)
        self.remote.verifier.enable()


class CrossProcessExperimentTests(unittest.TestCase):
    def test_experiment_passes_every_check(self):
        result = run_cross_process_verification_experiment(steps=16)
        for name, passed in result["summary"].items():
            self.assertTrue(passed, f"cross-process check failed: {name}")
        self.assertTrue(result["all_passed"])
        self.assertTrue(result["independent_agreement"]["distinct_processes"])
        self.assertGreater(result["latency"]["mean_round_trip_ms"], 0.0)


if __name__ == "__main__":
    unittest.main()
