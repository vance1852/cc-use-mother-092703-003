from __future__ import annotations

import sqlite3
import unittest
from datetime import datetime, timezone

from license_chain.clock import FrozenClock
from license_chain.errors import Conflict, Forbidden, InvalidState, NotFound, ValidationFailed
from license_chain.service import LicenseChainService


class ServiceTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.clock = FrozenClock(datetime(2026, 9, 1, 9, 0, tzinfo=timezone.utc))
        self.service = LicenseChainService(self.connection, self.clock)
        for user_id, role in (
            ("admin", "licensor"),
            ("ops", "operator"),
            ("comp", "compliance"),
            ("auditor", "auditor"),
        ):
            self.service.create_user(user_id, user_id, role)

    def tearDown(self) -> None:
        self.connection.close()

    def seed_licenses(self) -> None:
        self.service.register_license("admin", {"license_id": "lic-sale", "holder_id": "seller", "kind": "sale", "authority": "厅", "document_no": "销证", "valid_from": "2026-01-01", "valid_to": "2026-12-31"})
        self.service.add_license_scope("admin", "lic-sale", {"scope_code": "I-131", "activity": "碘131销售"})
        self.service.register_license("admin", {"license_id": "lic-truck", "holder_id": "carrier", "kind": "transport", "authority": "厅", "document_no": "运证", "valid_from": "2026-01-01", "valid_to": "2026-12-31"})
        self.service.add_license_scope("admin", "lic-truck", {"scope_code": "I-131", "activity": "碘131运输"})
        self.service.register_license("admin", {"license_id": "lic-med", "holder_id": "hospital", "kind": "medical_use", "authority": "委", "document_no": "医证", "valid_from": "2026-01-01", "valid_to": "2026-12-31"})
        self.service.add_license_scope("admin", "lic-med", {"scope_code": "I-131", "activity": "碘131诊疗"})
        self.service.register_site("admin", {"site_id": "site-s", "operator_id": "seller", "name": "车间", "purpose": "sale", "document_no": "场所1", "qualified_on": "2025-01-01", "valid_to": "2027-01-01"})
        self.service.register_site("admin", {"site_id": "site-h", "operator_id": "hospital", "name": "核医学科", "purpose": "medical_use", "document_no": "场所2", "qualified_on": "2025-01-01", "valid_to": "2027-01-01"})
        self.service.register_batch("ops", {"batch_id": "b1", "product_code": "I-131", "category": "药品", "owner_id": "seller", "site_id": "site-s", "produced_on": "2026-09-01"})

    def transport(self, handover_id: str = "h1", occurred_on: str = "2026-09-05"):
        return self.service.record_handover("ops", {"handover_id": handover_id, "batch_id": "b1", "kind": "transport", "actor_id": "carrier", "shipper_id": "seller", "receiver_id": "hospital", "site_id": "site-h", "occurred_on": occurred_on, "document_no": "运单"})

    def use(self, handover_id: str = "h2", occurred_on: str = "2026-09-06"):
        return self.service.record_handover("ops", {"handover_id": handover_id, "batch_id": "b1", "kind": "use", "actor_id": "hospital", "receiver_id": "hospital", "site_id": "site-h", "occurred_on": occurred_on, "document_no": "领用"})


class HappyPathTests(ServiceTestBase):
    def test_transport_then_use_authorized_with_bases(self) -> None:
        self.seed_licenses()
        moved = self.transport()
        self.assertEqual(moved["decision"], "recorded")
        basis_types = {base["type"] for base in moved["bases"]}
        self.assertEqual(basis_types, {"batch", "license", "site"})
        used = self.use()
        self.assertTrue(used["authorized"])
        trace = self.service.chain_trace("auditor", "b1")
        self.assertEqual(trace["current_custodian"], "hospital")
        self.assertEqual(len(trace["events"]), 2)

    def test_rejected_handover_does_not_move_custody(self) -> None:
        self.seed_licenses()
        # 无运输许可的单位承运 → 拒绝
        bad = self.service.record_handover("ops", {"handover_id": "bad", "batch_id": "b1", "kind": "transport", "actor_id": "seller", "shipper_id": "seller", "receiver_id": "hospital", "site_id": "site-h", "occurred_on": "2026-09-05", "document_no": "无资质运单"})
        self.assertEqual(bad["decision"], "rejected")
        self.assertIn("actor.license_missing", {g["code"] for g in bad["gaps"]})
        # 后续合法交接仍以 seller 为保管方
        ok = self.transport()
        self.assertEqual(ok["decision"], "recorded")

    def test_non_custodian_cannot_use(self) -> None:
        self.seed_licenses()
        self.transport()
        # seller 已不再持有，却尝试使用
        result = self.service.record_handover("ops", {"handover_id": "x", "batch_id": "b1", "kind": "use", "actor_id": "seller", "receiver_id": "seller", "site_id": "site-s", "occurred_on": "2026-09-07", "document_no": "越权"})
        self.assertEqual(result["decision"], "rejected")
        self.assertIn("chain.custody", {g["code"] for g in result["gaps"]})

    def test_scope_not_covered_is_reported(self) -> None:
        self.seed_licenses()
        self.service.register_batch("ops", {"batch_id": "b2", "product_code": "Co-60", "category": "放射源", "owner_id": "seller", "site_id": "site-s", "produced_on": "2026-09-01"})
        result = self.service.record_handover("ops", {"handover_id": "h", "batch_id": "b2", "kind": "transport", "actor_id": "carrier", "shipper_id": "seller", "receiver_id": "hospital", "site_id": "site-h", "occurred_on": "2026-09-05", "document_no": "单"})
        self.assertFalse(result["authorized"])
        codes = {g["code"] for g in result["gaps"]}
        self.assertIn("scope.not_covered", codes)


class RevocationTests(ServiceTestBase):
    def test_revocation_blocks_future_but_keeps_past(self) -> None:
        self.seed_licenses()
        self.transport(occurred_on="2026-09-05")
        used = self.use(occurred_on="2026-09-06")
        self.assertTrue(used["authorized"])
        self.service.revoke_license("admin", "lic-med", "2026-09-10", "隐患")
        # 撤销生效日当天及之后使用被阻断
        after = self.service.authorization_at("auditor", "b1", "hospital", "use", "2026-09-10")
        self.assertFalse(after["authorized"])
        self.assertEqual(after["gaps"][0]["code"], "actor.license_revoked")
        # 历史时点重放：09-09 仍然有效
        before = self.service.authorization_at("auditor", "b1", "hospital", "use", "2026-09-09")
        self.assertTrue(before["authorized"])
        # 已完成的交接仍在链上、决策不变
        trace = self.service.chain_trace("auditor", "b1")
        self.assertEqual([e["decision"] for e in trace["events"]], ["recorded", "recorded"])

    def test_revocation_with_effective_day_conflicting_past_handover_is_refused(self) -> None:
        self.seed_licenses()
        self.transport(occurred_on="2026-09-05")
        self.use(occurred_on="2026-09-06")
        with self.assertRaises(Conflict):
            self.service.revoke_license("admin", "lic-med", "2026-09-01", "追溯撤销")

    def test_expired_license_gap_code(self) -> None:
        self.seed_licenses()
        self.transport(occurred_on="2026-09-05")
        # 医院许可有效期到 2026-12-31，构造一张更早过期的使用证
        self.service.register_license("admin", {"license_id": "lic-old", "holder_id": "hospital2", "kind": "medical_use", "authority": "委", "document_no": "旧证", "valid_from": "2025-01-01", "valid_to": "2026-08-31"})
        self.service.add_license_scope("admin", "lic-old", {"scope_code": "I-131", "activity": "诊疗"})
        self.service.register_site("admin", {"site_id": "site-2", "operator_id": "hospital2", "name": "旧科", "purpose": "medical_use", "document_no": "场所", "qualified_on": "2025-01-01", "valid_to": "2027-01-01"})
        result = self.service.record_handover("ops", {"handover_id": "old", "batch_id": "b1", "kind": "transport", "actor_id": "carrier", "shipper_id": "seller", "receiver_id": "hospital2", "site_id": "site-2", "occurred_on": "2026-09-05", "document_no": "单"})
        self.assertIn("actor.license_expired", {g["code"] for g in result["gaps"]})

    def test_site_revocation_blocks_receipt(self) -> None:
        self.seed_licenses()
        self.service.revoke_site("admin", "site-h", "2026-09-04", "场所整改")
        result = self.transport(occurred_on="2026-09-05")
        self.assertEqual(result["decision"], "rejected")
        self.assertIn("site.qualification_revoked", {g["code"] for g in result["gaps"]})

    def test_scope_added_later_does_not_authorize_history(self) -> None:
        self.seed_licenses()
        self.service.register_batch("ops", {"batch_id": "b3", "product_code": "Mo-99", "category": "同位素", "owner_id": "seller", "site_id": "site-s", "produced_on": "2026-09-01"})
        result = self.service.record_handover("ops", {"handover_id": "early", "batch_id": "b3", "kind": "transport", "actor_id": "carrier", "shipper_id": "seller", "receiver_id": "hospital", "site_id": "site-h", "occurred_on": "2026-09-05", "document_no": "单"})
        self.assertIn("scope.not_covered", {g["code"] for g in result["gaps"]})
        # 09-20 才补登范围
        self.clock.advance(days=19)
        self.service.add_license_scope("admin", "lic-truck", {"scope_code": "Mo-99", "activity": "钼99运输"})
        # 历史时点 09-05 重放仍然缺范围
        again = self.service.record_handover  # 已拒绝记录不重录；直接用查询确认
        review = self.service.authorization_at("auditor", "b3", "carrier", "transport", "2026-09-05")
        self.assertIn("scope.not_covered", {g["code"] for g in review["gaps"]})
        # 09-21 起运输获授权
        later = self.service.authorization_at("auditor", "b3", "carrier", "transport", "2026-09-21")
        self.assertTrue(later["authorized"])


class ReviewTests(ServiceTestBase):
    def _close_review(self) -> dict:
        self.seed_licenses()
        self.transport(occurred_on="2026-09-05")
        self.use(occurred_on="2026-09-07")
        self.service.open_review("comp", "r1", "b1", "2026-09-10")
        self.service.close_review("comp", "r1")
        return self.service.review("auditor", "r1")

    def test_review_records_bases_and_conclusion(self) -> None:
        review = self._close_review()
        self.assertEqual(review["state"], "closed")
        self.assertEqual(review["conclusion"], "compliant")
        self.assertTrue(review["snapshot_intact"])
        self.assertEqual(review["finding"]["checked_handovers"], 2)

    def test_late_evidence_flags_but_never_rewrites_closed_review(self) -> None:
        review = self._close_review()
        self.assertFalse(review["evidence_changed"])
        # 09-25 补录一张业务日 09-08 的迟到使用单
        self.clock.current = datetime(2026, 9, 25, 8, 0, tzinfo=timezone.utc)
        late = self.service.record_handover("ops", {"handover_id": "late", "batch_id": "b1", "kind": "use", "actor_id": "hospital", "receiver_id": "hospital", "site_id": "site-h", "occurred_on": "2026-09-08", "document_no": "迟到单"})
        self.assertTrue(late["late_entry"])
        updated = self.service.review("auditor", "r1")
        self.assertEqual(updated["state"], "closed")
        self.assertEqual(updated["conclusion"], "compliant")
        self.assertTrue(updated["evidence_changed"])
        self.assertTrue(updated["snapshot_intact"])
        self.assertEqual(updated["new_evidence"][0]["handover_id"], "late")
        # 结案后不能再次结案
        with self.assertRaises(InvalidState):
            self.service.close_review("comp", "r1")

    def test_non_compliant_review_lists_gaps(self) -> None:
        self.seed_licenses()
        self.transport(occurred_on="2026-09-05")
        # 09-20 撤销后 09-21 的非法使用尝试被记录为 rejected
        self.service.revoke_license("admin", "lic-med", "2026-09-20", "x")
        self.clock.current = datetime(2026, 9, 21, 8, 0, tzinfo=timezone.utc)
        self.service.record_handover("ops", {"handover_id": "bad", "batch_id": "b1", "kind": "use", "actor_id": "hospital", "receiver_id": "hospital", "site_id": "site-h", "occurred_on": "2026-09-21", "document_no": "单"})
        self.service.open_review("comp", "r2", "b1", "2026-09-22")
        review = self.service.review("auditor", "r2")
        self.assertEqual(review["conclusion"], "non_compliant")
        gap_codes = {g["code"] for item in review["finding"]["items"] for g in item["gaps"]}
        self.assertIn("actor.license_revoked", gap_codes)


class TransferAndRefreshTests(ServiceTestBase):
    def test_transfer_between_licensees(self) -> None:
        self.seed_licenses()
        self.transport(occurred_on="2026-09-05")
        self.use(occurred_on="2026-09-06")
        # 第二家医院持使用证、有场所
        self.service.register_license("admin", {"license_id": "lic-med-2", "holder_id": "hospital2", "kind": "medical_use", "authority": "委", "document_no": "医证2", "valid_from": "2026-01-01", "valid_to": "2026-12-31"})
        self.service.add_license_scope("admin", "lic-med-2", {"scope_code": "I-131", "activity": "诊疗", "added_on": "2026-01-01"})
        self.service.register_site("admin", {"site_id": "site-h2", "operator_id": "hospital2", "name": "二院核医学科", "purpose": "medical_use", "document_no": "场所3", "qualified_on": "2025-01-01", "valid_to": "2027-01-01"})
        moved = self.service.record_handover("ops", {"handover_id": "t1", "batch_id": "b1", "kind": "transfer", "actor_id": "hospital", "receiver_id": "hospital2", "site_id": "site-h2", "occurred_on": "2026-09-08", "document_no": "移交单"})
        self.assertEqual(moved["decision"], "recorded")
        self.assertEqual(self.service.chain_trace("auditor", "b1")["current_custodian"], "hospital2")

    def test_open_review_refreshes_but_closed_review_does_not(self) -> None:
        self.seed_licenses()
        self.transport(occurred_on="2026-09-05")
        self.service.open_review("comp", "open1", "b1", "2026-09-10")
        # 新证据到达：open 审查可刷新
        self.use(occurred_on="2026-09-06")
        refreshed = self.service.refresh_review("comp", "open1")
        self.assertEqual(refreshed["finding"]["checked_handovers"], 2)
        self.assertFalse(refreshed["evidence_changed"])
        self.service.close_review("comp", "open1")
        with self.assertRaises(InvalidState):
            self.service.refresh_review("comp", "open1")


class GuardTests(ServiceTestBase):
    def test_role_separation(self) -> None:
        with self.assertRaises(Forbidden):
            self.service.register_license("ops", {"license_id": "l", "holder_id": "s", "kind": "sale", "authority": "a", "document_no": "d", "valid_from": "2026-01-01", "valid_to": None})
        with self.assertRaises(Forbidden):
            self.service.revoke_license("ops", "l", "2026-02-01", "r")

    def test_validation(self) -> None:
        with self.assertRaises(ValidationFailed):
            self.service.register_license("admin", {"license_id": "l", "holder_id": "s", "kind": "unknown", "authority": "a", "document_no": "d", "valid_from": "2026-01-01", "valid_to": None})
        with self.assertRaises(ValidationFailed):
            self.service.register_license("admin", {"license_id": "l", "holder_id": "s", "kind": "sale", "authority": "a", "document_no": "d", "valid_from": "2026-12-31", "valid_to": "2026-01-01"})

    def test_transport_requires_shipper(self) -> None:
        self.seed_licenses()
        with self.assertRaises(ValidationFailed):
            self.service.record_handover("ops", {"handover_id": "h", "batch_id": "b1", "kind": "transport", "actor_id": "carrier", "receiver_id": "hospital", "site_id": "site-h", "occurred_on": "2026-09-05", "document_no": "单"})

    def test_duplicate_handover_conflicts(self) -> None:
        self.seed_licenses()
        self.transport()
        with self.assertRaises(Conflict):
            self.transport()

    def test_not_found(self) -> None:
        with self.assertRaises(NotFound):
            self.service.license("missing")
        with self.assertRaises(NotFound):
            self.service.authorization_at("auditor", "missing", "u", "use", "2026-09-01")

    def test_batch_site_must_belong_to_owner(self) -> None:
        self.service.register_site("admin", {"site_id": "site-x", "operator_id": "someone", "name": "x", "purpose": "storage", "document_no": "d", "qualified_on": "2025-01-01", "valid_to": None})
        with self.assertRaises(ValidationFailed):
            self.service.register_batch("ops", {"batch_id": "b", "product_code": "I-131", "category": "c", "owner_id": "seller", "site_id": "site-x", "produced_on": "2026-09-01"})


class AuditTests(ServiceTestBase):
    def test_audit_chain_valid_after_full_lifecycle(self) -> None:
        self.seed_licenses()
        self.transport()
        self.use()
        self.service.open_review("comp", "r", "b1", "2026-09-10")
        self.service.revoke_license("admin", "lic-med", "2026-09-20", "r")
        chain = self.service.audit_chain("auditor")
        self.assertTrue(chain["valid"])
        self.assertGreater(chain["events"], 5)

    def test_auditor_cannot_mutate(self) -> None:
        with self.assertRaises(Forbidden):
            self.service.register_batch("auditor", {"batch_id": "b", "product_code": "I-131", "category": "c", "owner_id": "x", "site_id": "y", "produced_on": "2026-09-01"})


if __name__ == "__main__":
    unittest.main()
