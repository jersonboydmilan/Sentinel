import unittest

from tests.helpers import build_plane  # noqa: F401  (path setup)

from ais.common.errors import ForbiddenCapability
from ais.control_plane.capabilities import Capability, CapabilitySet


class CapabilityAlgebraTests(unittest.TestCase):
    def test_parse_and_render(self):
        cap = Capability.parse("database.write")
        self.assertEqual((cap.namespace, cap.action), ("database", "write"))
        self.assertEqual(str(cap), "database.write")

    def test_offensive_capabilities_are_not_representable(self):
        for name in ("agent.attack_anything", "agent.exploit_anything", "agent.destroy_target", "network.penetrate"):
            with self.assertRaises(ForbiddenCapability):
                Capability.parse(name)

    def test_wildcard_containment(self):
        wide = CapabilitySet.of("database.*")
        self.assertTrue(wide.holds("database.read"))
        self.assertFalse(wide.holds("file.read"))

    def test_subset_is_the_delegation_predicate(self):
        delegable = CapabilitySet.of("web.search", "database.read")
        requested = CapabilitySet.of("web.search")
        self.assertTrue(requested.issubset(delegable))
        self.assertFalse(CapabilitySet.of("database.write").issubset(delegable))

    def test_defensive_and_operational_partition(self):
        mixed = CapabilitySet.of("agent.restrict", "database.read")
        self.assertEqual(mixed.defensive().as_strings(), ["agent.restrict"])
        self.assertEqual(mixed.operational().as_strings(), ["database.read"])

    def test_difference_models_restriction(self):
        granted = CapabilitySet.of("database.read", "network.egress")
        restricted = CapabilitySet.of("network.egress")
        self.assertEqual(granted.difference(restricted).as_strings(), ["database.read"])


if __name__ == "__main__":
    unittest.main()
