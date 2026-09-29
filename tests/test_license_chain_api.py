from __future__ import annotations

import json
import sqlite3
import unittest

from license_chain.api import JsonApplication
from license_chain.service import LicenseChainService


class ApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.app = JsonApplication(LicenseChainService(self.connection))
        self.post("/users", {"user_id": "admin", "display_name": "a", "role": "licensor"})
        self.post("/users", {"user_id": "ops", "display_name": "o", "role": "operator"})
        self.post("/users", {"user_id": "comp", "display_name": "c", "role": "compliance"})
        self.post("/users", {"user_id": "auditor", "display_name": "r", "role": "auditor"})

    def tearDown(self) -> None:
        self.connection.close()

    def request(self, method: str, path: str, payload=None, actor: str = "admin", query=""):
        target = path + (("?" + query) if query else "")
        body = json.dumps(payload).encode() if payload is not None else b""
        return self.app.handle(method, target, {"X-Actor-Id": actor}, body)

    def post(self, path: str, payload=None, actor: str = "admin"):
        return self.request("POST", path, payload if payload is not None else {}, actor)

    def get(self, path: str, actor: str = "auditor", query=""):
        return self.request("GET", path, None, actor, query)

    def test_health(self) -> None:
        response = self.app.handle("GET", "/health")
        self.assertEqual(response.status, 200)
        self.assertEqual(response.body["status"], "ok")

    def test_actor_required(self) -> None:
        response = self.app.handle("GET", "/licenses/x")
        self.assertEqual(response.status, 422)
        self.assertEqual(response.body["error"]["code"], "validation_failed")

    def test_full_chain_over_http(self) -> None:
        license_payload = {"license_id": "lic", "holder_id": "seller", "kind": "sale", "authority": "厅", "document_no": "证", "valid_from": "2026-01-01", "valid_to": "2026-12-31"}
        self.assertEqual(self.post("/licenses", license_payload).status, 201)
        self.assertEqual(self.post("/licenses/lic/scopes", {"scope_code": "I-131", "activity": "销售", "added_on": "2026-01-01"}).status, 201)
        carrier = {"license_id": "lic-t", "holder_id": "carrier", "kind": "transport", "authority": "厅", "document_no": "运", "valid_from": "2026-01-01", "valid_to": "2026-12-31"}
        self.post("/licenses", carrier)
        self.post("/licenses/lic-t/scopes", {"scope_code": "I-131", "activity": "运输", "added_on": "2026-01-01"})
        hospital = {"license_id": "lic-h", "holder_id": "hospital", "kind": "medical_use", "authority": "委", "document_no": "医", "valid_from": "2026-01-01", "valid_to": "2026-12-31"}
        self.post("/licenses", hospital)
        self.post("/licenses/lic-h/scopes", {"scope_code": "I-131", "activity": "诊疗", "added_on": "2026-01-01"})
        self.post("/sites", {"site_id": "s1", "operator_id": "seller", "name": "车间", "purpose": "sale", "document_no": "p1", "qualified_on": "2025-01-01", "valid_to": "2027-01-01"})
        self.post("/sites", {"site_id": "h1", "operator_id": "hospital", "name": "核医学科", "purpose": "medical_use", "document_no": "p2", "qualified_on": "2025-01-01", "valid_to": "2027-01-01"})
        self.assertEqual(
            self.post("/batches", {"batch_id": "b1", "product_code": "I-131", "category": "药", "owner_id": "seller", "site_id": "s1", "produced_on": "2026-09-01"}, actor="ops").status,
            201,
        )
        moved = self.post("/handovers", {"handover_id": "ho1", "batch_id": "b1", "kind": "transport", "actor_id": "carrier", "shipper_id": "seller", "receiver_id": "hospital", "site_id": "h1", "occurred_on": "2026-09-05", "document_no": "运单"}, actor="ops")
        self.assertEqual(moved.status, 201)
        self.assertTrue(moved.body["authorized"])
        used = self.post("/handovers", {"handover_id": "ho2", "batch_id": "b1", "kind": "use", "actor_id": "hospital", "receiver_id": "hospital", "site_id": "h1", "occurred_on": "2026-09-06", "document_no": "领用"}, actor="ops")
        self.assertTrue(used.body["authorized"])

        query = "batch_id=b1&unit_id=hospital&action=use&on=2026-09-06"
        answer = self.get("/authorization", query=query)
        self.assertEqual(answer.status, 200)
        self.assertTrue(answer.body["authorized"])
        self.assertTrue(answer.body["bases"])

        revoked = self.post("/licenses/lic-h/revoke", {"effective_on": "2026-09-20", "reason": "整改"})
        self.assertEqual(revoked.status, 200)
        blocked = self.get("/authorization", query="batch_id=b1&unit_id=hospital&action=use&on=2026-09-21")
        self.assertFalse(blocked.body["authorized"])
        self.assertEqual(blocked.body["gaps"][0]["code"], "actor.license_revoked")

        chain = self.get("/batches/b1/chain")
        self.assertEqual(chain.body["current_custodian"], "hospital")
        audit = self.get("/audit/chain")
        self.assertTrue(audit.body["valid"])

    def test_unknown_route_and_forbidden(self) -> None:
        self.assertEqual(self.app.handle("GET", "/nope").status, 422)
        response = self.post("/batches", {"x": 1}, actor="auditor")
        self.assertEqual(response.status, 403)


if __name__ == "__main__":
    unittest.main()
