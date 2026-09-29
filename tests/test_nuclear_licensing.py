"""许可与流转授权链服务的核心规则测试。"""

from __future__ import annotations

import sqlite3
import unittest
from datetime import datetime, timezone

from nuclear_licensing.clock import FrozenClock
from nuclear_licensing.errors import (
    AuthorizationBlocked,
    Conflict,
    Forbidden,
    InvalidState,
    NotFound,
    ValidationFailed,
)
from nuclear_licensing.service import LicensingService


class LicensingTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.clock = FrozenClock(datetime(2026, 3, 1, 8, 0, tzinfo=timezone.utc))
        self.service = LicensingService(self.connection, self.clock)
        for user_id, role in (
            ("reg", "registry"),
            ("disp", "dispatcher"),
            ("comp", "compliance"),
            ("aud", "auditor"),
        ):
            self.service.create_user(user_id, user_id, role)
        self._seed()

    def tearDown(self) -> None:
        self.connection.close()

    def _seed(self) -> None:
        s = self.service
        for org_id, name, kind in (
            ("nuc-src", "源生产单位", "enterprise"),
            ("med-a", "医院甲", "medical"),
            ("med-b", "医院乙", "medical"),
            ("trans-co", "运输公司", "carrier"),
        ):
            s.register_org("reg", {"org_id": org_id, "name": name, "kind": kind})
        s.register_site("reg", "site-a", "med-a", "医院甲场所", "2025-01-01T00:00:00Z", "2028-01-01T00:00:00Z")
        s.register_site("reg", "site-b", "med-b", "医院乙场所", "2025-01-01T00:00:00Z", "2028-01-01T00:00:00Z")
        s.record_license("reg", {"license_id": "L-SRC", "license_no": "证-源", "holder_org_id": "nuc-src",
                                 "valid_from": "2025-01-01T00:00:00Z", "valid_to": "2029-01-01T00:00:00Z",
                                 "document_ref": "批文-源"})
        s.add_license_scope("reg", "L-SRC", "transfer", "IR-192-SEALED", "批文-源/范围")
        s.record_license("reg", {"license_id": "L-CAR", "license_no": "证-运", "holder_org_id": "trans-co",
                                 "valid_from": "2025-01-01T00:00:00Z", "valid_to": "2029-01-01T00:00:00Z",
                                 "document_ref": "批文-运"})
        s.add_license_scope("reg", "L-CAR", "transport", "IR-192-SEALED", "批文-运/范围")
        s.record_license("reg", {"license_id": "L-A", "license_no": "证-甲", "holder_org_id": "med-a",
                                 "valid_from": "2025-06-01T00:00:00Z", "valid_to": "2028-06-01T00:00:00Z",
                                 "document_ref": "批文-甲"})
        s.add_license_scope("reg", "L-A", "use", "IR-192-SEALED", "批文-甲/场所", site_id="site-a")
        s.record_license("reg", {"license_id": "L-B", "license_no": "证-乙", "holder_org_id": "med-b",
                                 "valid_from": "2025-03-01T00:00:00Z", "valid_to": "2028-03-01T00:00:00Z",
                                 "document_ref": "批文-乙"})
        s.add_license_scope("reg", "L-B", "transfer", "IR-192-SEALED", "批文-乙/范围")
        s.add_license_scope("reg", "L-B", "use", "IR-192-SEALED", "批文-乙/场所", site_id="site-b")
        s.register_batch("reg", {"batch_id": "B1", "item_code": "IR-192-SEALED", "product_name": "铱-192 源",
                                 "nuclide": "Ir-192", "origin_org_id": "nuc-src",
                                 "produced_at": "2026-02-20T00:00:00Z"})

    def _handoff_to_a(self, handoff_id: str = "H1", occurred: str = "2026-03-02T10:00:00Z",
                      **overrides) -> dict:
        payload = {
            "handoff_id": handoff_id, "batch_id": "B1",
            "from_org_id": "nuc-src", "to_org_id": "med-a", "carrier_org_id": "trans-co",
            "site_id": "site-a", "occurred_at": occurred,
            "evidence_doc": f"交接单 {handoff_id}", "idempotency_key": f"key-{handoff_id}",
        }
        payload.update(overrides)
        return self.service.record_handoff("disp", payload)


class ChainRuleTests(LicensingTestBase):
    def test_missing_scope_is_recorded_but_not_hard_blocked(self) -> None:
        # med-a 没有 transfer 范围：事实可登记，状态 incomplete 并指出缺口。
        result = self._handoff_to_a()
        self.assertEqual(result["status"], "incomplete")
        codes = {item["code"] for item in result["findings"]}
        self.assertIn("license.transfer.missing", codes)
        self.assertNotIn("license.revoked", codes)

    def test_complete_chain_is_authorized(self) -> None:
        self.service.add_license_scope("reg", "L-A", "transfer", "IR-192-SEALED", "批文-甲/转让")
        result = self._handoff_to_a()
        self.assertEqual(result["status"], "authorized")
        chain = self.service.chain("aud", "B1", "2026-03-03T00:00:00Z")
        self.assertEqual(chain["status"], "authorized")
        self.assertEqual(chain["holder_org_id"], "med-a")

    def test_late_handoff_is_flagged(self) -> None:
        self.clock.current = datetime(2026, 3, 10, 8, 0, tzinfo=timezone.utc)
        result = self._handoff_to_a(occurred="2026-03-02T10:00:00Z")
        self.assertTrue(result["late_evidence"])

    def test_expired_license_is_missing_basis(self) -> None:
        answer = self.service.authorize(
            "aud", "B1", "med-a", "use", "2029-01-01T00:00:00Z", site_id="site-a")
        self.assertFalse(answer["authorized"])
        self.assertTrue(any(item["code"] == "license.use.missing" for item in answer["findings"]))

    def test_wrong_site_owner_blocks(self) -> None:
        with self.assertRaises(ValidationFailed):
            self.service.add_license_scope(
                "reg", "L-A", "use", "IR-192-SEALED", "批文", site_id="site-b")


class RevocationTests(LicensingTestBase):
    def test_revocation_blocks_future_handoff_but_keeps_history(self) -> None:
        self.service.add_license_scope("reg", "L-A", "transfer", "IR-192-SEALED", "批文-甲/转让")
        self.clock.current = datetime(2026, 3, 3, 9, 0, tzinfo=timezone.utc)
        first = self._handoff_to_a()
        self.assertEqual(first["status"], "authorized")

        self.clock.current = datetime(2026, 3, 10, 9, 0, tzinfo=timezone.utc)
        self.service.revoke_license("reg", "L-A", "2026-03-11T00:00:00Z", "安全隐患")

        self.clock.current = datetime(2026, 3, 12, 9, 0, tzinfo=timezone.utc)
        with self.assertRaises(AuthorizationBlocked) as ctx:
            self._handoff_to_a(
                handoff_id="H2", occurred="2026-03-12T08:00:00Z",
                from_org_id="med-a", to_org_id="med-b", site_id="site-b",
                evidence_doc="交接单 H2", idempotency_key="key-H2")
        self.assertTrue(any(f["code"] == "license.revoked" for f in ctx.exception.details["findings"]))

        chain = self.service.chain("aud", "B1", "2026-03-13T00:00:00Z")
        self.assertEqual(len(chain["handoffs"]), 1)
        self.assertEqual(chain["handoffs"][0]["status"], "authorized")
        self.assertEqual(chain["holder_org_id"], "med-a")

        # 撤销生效日之前的使用仍然可以。
        before = self.service.authorize("aud", "B1", "med-a", "use", "2026-03-10T00:00:00Z", site_id="site-a")
        self.assertTrue(before["authorized"])
        after = self.service.authorize("aud", "B1", "med-a", "use", "2026-03-12T00:00:00Z", site_id="site-a")
        self.assertFalse(after["authorized"])

    def test_double_revocation_conflicts(self) -> None:
        self.service.revoke_license("reg", "L-A", "2026-03-11T00:00:00Z", "原因")
        with self.assertRaises(Conflict):
            self.service.revoke_license("reg", "L-A", "2026-03-12T00:00:00Z", "再撤")

    def test_site_suspension_blocks_use(self) -> None:
        self.clock.current = datetime(2026, 3, 4, 9, 0, tzinfo=timezone.utc)
        self.service.suspend_site("reg", "site-a", "2026-03-05T00:00:00Z", "场所整改",
                                  ends_at="2026-03-20T00:00:00Z")
        answer = self.service.authorize("aud", "B1", "med-a", "use", "2026-03-10T00:00:00Z", site_id="site-a")
        self.assertFalse(answer["authorized"])
        self.assertTrue(any(f["code"] == "site.suspended" for f in answer["findings"]))


class CustodyIntegrityTests(LicensingTestBase):
    def test_handoff_must_start_from_chain_holder(self) -> None:
        # 批次起源 nuc-src，med-a 直接转手不成立。
        with self.assertRaises(AuthorizationBlocked):
            self._handoff_to_a(
                handoff_id="HX", from_org_id="med-a", to_org_id="med-b", site_id="site-b",
                occurred="2026-03-02T10:00:00Z", idempotency_key="key-HX")

    def test_landing_site_must_belong_to_receiver(self) -> None:
        with self.assertRaises(ValidationFailed):
            self._handoff_to_a(site_id="site-b")

    def test_idempotent_replay(self) -> None:
        payload = {
            "handoff_id": "H1", "batch_id": "B1",
            "from_org_id": "nuc-src", "to_org_id": "med-a", "carrier_org_id": "trans-co",
            "site_id": "site-a", "occurred_at": "2026-03-02T10:00:00Z",
            "evidence_doc": "交接单 H1", "idempotency_key": "key-H1",
        }
        first = self.service.record_handoff("disp", payload)
        second = self.service.record_handoff("disp", payload)
        self.assertEqual(first["handoff_id"], second["handoff_id"])
        changed = dict(payload, evidence_doc="被篡改的交接单")
        with self.assertRaises(Conflict):
            self.service.record_handoff("disp", changed)


class ReviewFreezeTests(LicensingTestBase):
    def _close_review(self) -> dict:
        self._handoff_to_a()  # med-a 缺 transfer 范围 → incomplete
        self.clock.current = datetime(2026, 3, 6, 14, 0, tzinfo=timezone.utc)
        self.service.open_review("comp", "R1", "B1", "2026-03-05T00:00:00Z")
        return self.service.close_review("comp", "R1")

    def test_backfilled_scope_does_not_rewrite_frozen_review(self) -> None:
        closed = self._close_review()
        self.assertEqual(closed["frozen_result"]["status"], "incomplete")
        cutoff = closed["knowledge_cutoff"]

        self.clock.current = datetime(2026, 3, 8, 10, 0, tzinfo=timezone.utc)
        self.service.add_license_scope(
            "reg", "L-A", "transfer", "IR-192-SEALED", "批文-甲/补录", backfilled=True)

        view = self.service.get_review("aud", "R1")
        self.assertEqual(view["frozen_result"]["status"], "incomplete")
        self.assertEqual(view["current_view"]["status"], "authorized")
        self.assertEqual(len(view["late_evidence"]), 1)
        self.assertEqual(view["late_evidence"][0]["kind"], "license_scope.backfilled")
        self.assertGreater(view["late_evidence"][0]["recorded_at"], cutoff)

    def test_late_revocation_is_flagged_not_silently_applied(self) -> None:
        self._close_review()
        self.clock.current = datetime(2026, 3, 9, 10, 0, tzinfo=timezone.utc)
        self.service.revoke_license("reg", "L-A", "2026-03-04T00:00:00Z", "追溯撤销")
        view = self.service.get_review("aud", "R1")
        # 结案时点该撤销尚未登记，冻结结论保持原样；迟到撤销单独列出。
        self.assertEqual(view["frozen_result"]["status"], "incomplete")
        self.assertTrue(any(item["kind"] == "license.revoked" for item in view["late_evidence"]))
        historical = self.service.chain(
            "aud", "B1", "2026-03-05T00:00:00Z", view["knowledge_cutoff"])
        self.assertEqual(historical["status"], "incomplete")

    def test_reopen_required_before_new_conclusion(self) -> None:
        self._close_review()
        with self.assertRaises(InvalidState):
            self.service.close_review("comp", "R1")
        self.service.reopen_review("comp", "R1")
        again = self.service.close_review("comp", "R1")
        self.assertEqual(again["state"], "closed")

    def test_historical_reconstruction_respects_knowledge_cutoff(self) -> None:
        self._close_review()
        self.clock.current = datetime(2026, 3, 8, 10, 0, tzinfo=timezone.utc)
        self.service.add_license_scope(
            "reg", "L-A", "transfer", "IR-192-SEALED", "批文-甲/补录", backfilled=True)
        cutoff = datetime(2026, 3, 6, 14, 0, tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
        old_view = self.service.chain("aud", "B1", "2026-03-05T00:00:00Z", cutoff)
        new_view = self.service.chain("aud", "B1", "2026-03-05T00:00:00Z")
        self.assertEqual(old_view["status"], "incomplete")
        self.assertEqual(new_view["status"], "authorized")


class PermissionAndAuditTests(LicensingTestBase):
    def test_roles_are_enforced(self) -> None:
        with self.assertRaises(Forbidden):
            self.service.record_license("disp", {"license_id": "X", "license_no": "x",
                                                 "holder_org_id": "nuc-src",
                                                 "valid_from": "2025-01-01T00:00:00Z",
                                                 "valid_to": "2029-01-01T00:00:00Z", "document_ref": "d"})
        with self.assertRaises(Forbidden):
            self.service.record_handoff("reg", {
                "handoff_id": "H9", "batch_id": "B1", "from_org_id": "nuc-src", "to_org_id": "med-a",
                "carrier_org_id": "trans-co", "site_id": "site-a",
                "occurred_at": "2026-03-02T10:00:00Z", "evidence_doc": "e", "idempotency_key": "k9"})

    def test_not_found_boundaries(self) -> None:
        with self.assertRaises(NotFound):
            self.service.license("NOPE")
        with self.assertRaises(NotFound):
            self.service.chain("aud", "NO-BATCH")

    def test_audit_chain_detects_tampering(self) -> None:
        self._handoff_to_a()
        self.assertTrue(self.service.audit_chain("aud")["valid"])
        self.connection.execute("UPDATE nuc_audit_events SET payload_json='{}' WHERE event_id=1")
        self.assertFalse(self.service.audit_chain("aud")["valid"])

    def test_audit_records_backfill_and_revocation_event_types(self) -> None:
        self.service.add_license_scope(
            "reg", "L-A", "transfer", "IR-192-SEALED", "补录", backfilled=True)
        self.service.revoke_license("reg", "L-A", "2026-03-11T00:00:00Z", "原因")
        kinds = {row["event_type"] for row in self.connection.execute(
            "SELECT event_type FROM nuc_audit_events").fetchall()}
        self.assertIn("scope.added.backfilled", kinds)
        self.assertIn("license.revoked", kinds)


if __name__ == "__main__":
    unittest.main()
