from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from sdnsec.config import load_inventory_file, load_policy_file
from sdnsec.controller import SDNSecurityController


ROOT = Path(__file__).resolve().parents[1]


class SDNSecurityControllerTests(unittest.TestCase):
    def setUp(self) -> None:
        devices = load_inventory_file(ROOT / "examples" / "inventory.json")
        policy = load_policy_file(ROOT / "examples" / "security_policy.json")
        self.controller = SDNSecurityController(devices, policy)

    def test_build_plan_generates_all_devices(self) -> None:
        plans = self.controller.build_plan()

        self.assertEqual(len(plans), 3)
        self.assertEqual({plan.device.name for plan in plans}, {"edge-rtr-01", "core-sw-01", "branch-sw-01"})

    def test_router_plan_contains_segmentation_acl(self) -> None:
        router_plan = next(plan for plan in self.controller.build_plan() if plan.device.name == "edge-rtr-01")
        rendered = "\n".join(router_plan.commands)

        self.assertIn("ip access-list extended SDN_CORP_IN", rendered)
        self.assertIn("permit tcp 10.20.20.0 0.0.0.255 10.20.50.0 0.0.0.255 eq 443", rendered)
        self.assertIn("deny ip any any log", rendered)
        self.assertIn("ip ssh version 2", rendered)

    def test_apply_and_audit_are_compliant(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.controller.apply(tmp)
            findings = self.controller.audit(tmp)

        self.assertTrue(all(finding["status"] == "compliant" for finding in findings))

    def test_audit_detects_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.controller.apply(tmp)
            target = Path(tmp) / "core-sw-01.json"
            state = json.loads(target.read_text(encoding="utf-8"))
            state["fingerprint"] = "manual-change"
            target.write_text(json.dumps(state), encoding="utf-8")

            findings = self.controller.audit(tmp)

        drift = next(finding for finding in findings if finding["device"] == "core-sw-01")
        self.assertEqual(drift["status"], "drift")


if __name__ == "__main__":
    unittest.main()
