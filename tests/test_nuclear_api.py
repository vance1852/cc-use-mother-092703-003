"""许可与流转 HTTP 接口边界测试。"""

from __future__ import annotations

import json
import sqlite3
import unittest
from datetime import datetime, timezone

from nuclear_licensing.api import JsonApplication
from nuclear_licensing.clock import FrozenClock
from nuclear_licensing.service import LicensingService


class LicensingApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.clock = FrozenClock(datetime(2026, 3, 1, 8, 0, tzinfo=timezone.utc))
        self.service = LicensingService(self.connection, self.clock)
        self.app = JsonApplication(self.service)
        self.service.create_user("reg", "登记员", "registry")
        self.service.create_user("aud", "审计员", "auditor")

    def tearDown(self) -> None:
        self.connection.close()

    def _post(self, path: str, payload: dict, actor: str = "reg"):
        return self.app.handle(
            "POST", path, {"X-Actor-Id": actor},
            json.dumps(payload, ensure_ascii=False).encode("utf-8"))

    def test_health(self) -> None:
        response = self.app.handle("GET", "/health")
        self.assertEqual(response.status, 200)
        self.assertEqual(response.body["status"], "ok")

    def test_actor_required(self) -> None:
        response = self.app.handle("POST", "/orgs", body=b"{}")
        self.assertEqual(response.status, 422)
        self.assertEqual(response.body["error"]["code"], "validation_failed")

    def test_org_and_authorization_query_roundtrip(self) -> None:
        response = self._post("/orgs", {"org_id": "o1", "name": "医院甲", "kind": "medical"})
        self.assertEqual(response.status, 201)
        # 审计员查询不存在批次 → 404 稳定错误形状。
        missing = self.app.handle(
            "POST", "/batches/NOPE/authorize", {"X-Actor-Id": "aud"},
            json.dumps({"org_id": "o1", "activity": "use", "as_of": "2026-03-01T00:00:00Z",
                        "site_id": "s1"}).encode("utf-8"))
        self.assertEqual(missing.status, 404)
        self.assertEqual(missing.body["error"]["code"], "not_found")

    def test_authorization_blocked_carries_findings(self) -> None:
        self._post("/orgs", {"org_id": "nuc-src", "name": "源单位", "kind": "enterprise"})
        self._post("/orgs", {"org_id": "med-a", "name": "医院甲", "kind": "medical"})
        self._post("/orgs", {"org_id": "trans-co", "name": "运输公司", "kind": "carrier"})
        self._post("/sites", {"site_id": "site-a", "org_id": "med-a", "name": "场所",
                              "valid_from": "2025-01-01T00:00:00Z", "valid_to": "2028-01-01T00:00:00Z"})
        self._post("/licenses", {"license_id": "L-A", "license_no": "证-甲", "holder_org_id": "med-a",
                                 "valid_from": "2025-01-01T00:00:00Z", "valid_to": "2028-01-01T00:00:00Z",
                                 "document_ref": "批文"})
        self._post("/licenses/L-A/scopes", {"activity": "use", "item_code": "IR-192",
                                            "document_ref": "范围", "site_id": "site-a"})
        self._post("/batches", {"batch_id": "B1", "item_code": "IR-192", "product_name": "源",
                                "nuclide": "Ir-192", "origin_org_id": "nuc-src",
                                "produced_at": "2026-02-01T00:00:00Z"})
        self._post("/licenses/L-A/revoke", {"effective_at": "2026-02-10T00:00:00Z", "reason": "整改"})
        response = self.app.handle(
            "POST", "/batches/B1/authorize", {"X-Actor-Id": "aud"},
            json.dumps({"org_id": "med-a", "activity": "use", "as_of": "2026-03-01T00:00:00Z",
                        "site_id": "site-a"}).encode("utf-8"))
        self.assertEqual(response.status, 200)
        self.assertFalse(response.body["authorized"])
        self.assertTrue(any(f["code"] == "license.revoked" for f in response.body["findings"]))


if __name__ == "__main__":
    unittest.main()
