"""许可与流转授权链离线验收。

剧本覆盖：正常交接 → 缺失环节审查结案 → 迟到补录不改变冻结结论 →
许可撤销阻断后续流转但不抹除历史合法交接 → 历史时点重建。
"""

from __future__ import annotations

import argparse
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from .clock import FrozenClock
from .errors import AuthorizationBlocked
from .service import LicensingService


def run(workspace: Path) -> dict[str, object]:
    connection = sqlite3.connect(":memory:", isolation_level=None)
    connection.row_factory = sqlite3.Row
    clock = FrozenClock(datetime(2026, 3, 1, 8, 0, tzinfo=timezone.utc))
    service = LicensingService(connection, clock)
    for user_id, role in (
        ("reg", "registry"),
        ("disp", "dispatcher"),
        ("comp", "compliance"),
        ("aud", "auditor"),
    ):
        service.create_user(user_id, user_id, role)

    # 单位：源生产单位、医院甲、医院乙、运输单位。
    service.register_org("reg", {"org_id": "nuc-src", "name": "同位素源生产单位", "kind": "enterprise"})
    service.register_org("reg", {"org_id": "med-a", "name": "医院甲核医学科", "kind": "medical"})
    service.register_org("reg", {"org_id": "med-b", "name": "医院乙放疗中心", "kind": "medical"})
    service.register_org("reg", {"org_id": "trans-co", "name": "核品运输公司", "kind": "carrier"})
    service.register_site("reg", "site-a", "med-a", "医院甲乙级非密封源工作场所", "2025-01-01T00:00:00Z", "2028-01-01T00:00:00Z")
    service.register_site("reg", "site-b", "med-b", "医院乙辐照加工场所", "2025-01-01T00:00:00Z", "2028-01-01T00:00:00Z")

    # 许可：注意医院甲最初只有“使用”范围，没有“转让/接收”范围——凭证缺失。
    service.record_license("reg", {
        "license_id": "L-SRC", "license_no": "国环辐证[源]0001", "holder_org_id": "nuc-src",
        "valid_from": "2025-01-01T00:00:00Z", "valid_to": "2029-01-01T00:00:00Z",
        "document_ref": "批文-SRC-2025-01",
    })
    service.add_license_scope("reg", "L-SRC", "transfer", "IR-192-SEALED", "批文-SRC-2025-01/范围")
    service.record_license("reg", {
        "license_id": "L-CAR", "license_no": "危货运输证 0007", "holder_org_id": "trans-co",
        "valid_from": "2025-01-01T00:00:00Z", "valid_to": "2029-01-01T00:00:00Z",
        "document_ref": "批文-CAR-2025-09",
    })
    service.add_license_scope("reg", "L-CAR", "transport", "IR-192-SEALED", "批文-CAR-2025-09/范围")
    service.record_license("reg", {
        "license_id": "L-A", "license_no": "国环辐证[甲]0042", "holder_org_id": "med-a",
        "valid_from": "2025-06-01T00:00:00Z", "valid_to": "2028-06-01T00:00:00Z",
        "document_ref": "批文-MEDA-2025-06",
    })
    service.add_license_scope("reg", "L-A", "use", "IR-192-SEALED", "批文-MEDA-2025-06/场所", site_id="site-a")
    service.record_license("reg", {
        "license_id": "L-B", "license_no": "国环辐证[乙]0108", "holder_org_id": "med-b",
        "valid_from": "2025-03-01T00:00:00Z", "valid_to": "2028-03-01T00:00:00Z",
        "document_ref": "批文-MEDB-2025-03",
    })
    service.add_license_scope("reg", "L-B", "transfer", "IR-192-SEALED", "批文-MEDB-2025-03/范围")
    service.add_license_scope("reg", "L-B", "use", "IR-192-SEALED", "批文-MEDB-2025-03/场所", site_id="site-b")

    service.register_batch("reg", {
        "batch_id": "B-IR192-01", "item_code": "IR-192-SEALED", "product_name": "铱-192 密封源",
        "nuclide": "Ir-192", "origin_org_id": "nuc-src", "produced_at": "2026-02-20T00:00:00Z",
    })

    # 3 月 2 日交接，3 月 3 日交接单才送达登记（迟到凭证）；医院甲缺转让范围 → 缺口被记录但不阻断事实登记。
    clock.current = datetime(2026, 3, 3, 9, 30, tzinfo=timezone.utc)
    handoff = service.record_handoff("disp", {
        "handoff_id": "H-0001", "batch_id": "B-IR192-01",
        "from_org_id": "nuc-src", "to_org_id": "med-a", "carrier_org_id": "trans-co",
        "site_id": "site-a", "occurred_at": "2026-03-02T10:00:00Z",
        "evidence_doc": "交接单 H-0001", "idempotency_key": "handoff-0001",
    })
    assert handoff["status"] == "incomplete"
    assert handoff["late_evidence"] is True
    assert any(item["code"] == "license.transfer.missing" for item in handoff["findings"])

    # 3 月 6 日合规审查按 3 月 5 日时点结案：结论冻结为“不完整”。
    clock.current = datetime(2026, 3, 6, 14, 0, tzinfo=timezone.utc)
    service.open_review("comp", "R-2026-009", "B-IR192-01", "2026-03-05T00:00:00Z")
    closed = service.close_review("comp", "R-2026-009")
    assert closed["state"] == "closed"
    assert closed["frozen_result"]["status"] == "incomplete"
    frozen_cutoff = closed["knowledge_cutoff"]

    # 3 月 8 日补录医院甲的转让范围（批文 1 月已签发，纸面文件迟到）。
    clock.current = datetime(2026, 3, 8, 10, 0, tzinfo=timezone.utc)
    service.add_license_scope("reg", "L-A", "transfer", "IR-192-SEALED", "批文-MEDA-2025-01/补录", backfilled=True)
    review_after_backfill = service.get_review("aud", "R-2026-009")
    # 冻结结论不被补录静默改写，但迟到凭证被明确指出。
    assert review_after_backfill["frozen_result"]["status"] == "incomplete"
    assert review_after_backfill["current_view"]["status"] == "authorized"
    assert [item["kind"] for item in review_after_backfill["late_evidence"]] == ["license_scope.backfilled"]

    # 3 月 10 日登记：医院甲许可自 3 月 11 日起撤销。
    clock.current = datetime(2026, 3, 10, 11, 0, tzinfo=timezone.utc)
    service.revoke_license("reg", "L-A", "2026-03-11T00:00:00Z", "监督检查发现辐射安全隐患")

    # 3 月 12 日医院甲试图把批次转交医院乙：撤销阻断后续流转。
    clock.current = datetime(2026, 3, 12, 9, 0, tzinfo=timezone.utc)
    blocked = False
    try:
        service.record_handoff("disp", {
            "handoff_id": "H-0002", "batch_id": "B-IR192-01",
            "from_org_id": "med-a", "to_org_id": "med-b", "carrier_org_id": "trans-co",
            "site_id": "site-b", "occurred_at": "2026-03-12T08:00:00Z",
            "evidence_doc": "交接单 H-0002", "idempotency_key": "handoff-0002",
        })
    except AuthorizationBlocked as exc:
        blocked = True
        assert any(item["code"] == "license.revoked" for item in exc.details["findings"])
    assert blocked

    # 当前视角：3 月 2 日的历史交接仍然合法；链停在医院甲。
    current = service.chain("aud", "B-IR192-01", "2026-03-13T00:00:00Z")
    assert current["handoffs"][0]["status"] == "authorized"
    assert current["holder_org_id"] == "med-a"

    # 历史时点重建：审查结案时点（3 月 6 日知识截止）看到的仍是不完整链。
    historical = service.chain("aud", "B-IR192-01", "2026-03-05T00:00:00Z", frozen_cutoff)
    assert historical["status"] == "incomplete"

    # 审计问答：3 月 5 日能否由运输公司运输？依据齐备 → 可以，并给出具体批文。
    can_transport = service.authorize(
        "aud", "B-IR192-01", "trans-co", "transport", "2026-03-05T12:00:00Z",
        knowledge_cutoff=frozen_cutoff,
    )
    assert can_transport["authorized"] is True
    assert can_transport["findings"][0]["basis"]["license_no"] == "危货运输证 0007"
    # 撤销后医院甲在 site-a 的使用授权被否，且指出依据。
    cannot_use = service.authorize("aud", "B-IR192-01", "med-a", "use", "2026-03-12T00:00:00Z", site_id="site-a")
    assert cannot_use["authorized"] is False
    assert any(item["code"] == "license.revoked" for item in cannot_use["findings"])

    audit = service.audit_chain("aud")
    assert audit["valid"] is True

    connection.close()
    return {
        "status": "ok",
        "workspace": workspace.name,
        "handoff_status": handoff["status"],
        "frozen_review": closed["frozen_result"]["status"],
        "current_view": current["status"],
        "historical_view": historical["status"],
        "late_evidence": review_after_backfill["late_evidence"],
        "revocation_blocked_handoff": blocked,
        "transport_authorized_at_review_time": can_transport["authorized"],
        "use_denied_after_revocation": not cannot_use["authorized"],
        "audit_events": audit["events"],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="运行核技术应用许可与流转服务离线验收")
    parser.add_argument("--workspace", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    print(json.dumps(run(args.workspace), ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
