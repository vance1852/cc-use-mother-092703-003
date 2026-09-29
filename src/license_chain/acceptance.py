"""贯通许可范围、场所资质、产品批次、交接与合规审查的离线验收。"""

from __future__ import annotations

import argparse
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from .clock import FrozenClock
from .service import LicenseChainService


def run(workspace: Path) -> dict[str, object]:
    connection = sqlite3.connect(":memory:", isolation_level=None)
    connection.row_factory = sqlite3.Row
    clock = FrozenClock(datetime(2026, 8, 20, 9, 0, tzinfo=timezone.utc))
    service = LicenseChainService(connection, clock)

    for user_id, role in (
        ("admin", "licensor"),
        ("ops", "operator"),
        ("comp", "compliance"),
        ("auditor", "auditor"),
    ):
        service.create_user(user_id, user_id, role)

    # 许可批文：销售方、承运人、医院各自持证
    service.register_license("admin", {"license_id": "lic-sale-01", "holder_id": "isotope-co", "kind": "sale", "authority": "省生态环境厅", "document_no": "环许销〔2026〕01号", "valid_from": "2026-01-01", "valid_to": "2026-12-31"})
    service.add_license_scope("admin", "lic-sale-01", {"scope_code": "I-131", "activity": "碘-131 销售", "note": "口服液级别"})
    service.register_license("admin", {"license_id": "lic-truck-01", "holder_id": "carrier-co", "kind": "transport", "authority": "省生态环境厅", "document_no": "环许运〔2026〕07号", "valid_from": "2026-01-01", "valid_to": "2026-12-31"})
    service.add_license_scope("admin", "lic-truck-01", {"scope_code": "I-131", "activity": "碘-131 运输", "note": "B 型货包"})
    service.register_license("admin", {"license_id": "lic-med-01", "holder_id": "hospital-a", "kind": "medical_use", "authority": "省卫健委与生态环境厅", "document_no": "辐证医〔2026〕03号", "valid_from": "2026-01-01", "valid_to": "2026-12-31"})
    service.add_license_scope("admin", "lic-med-01", {"scope_code": "I-131", "activity": "碘-131 核素诊疗", "note": "甲状腺疾病"})

    # 场所资质
    service.register_site("admin", {"site_id": "site-prod", "operator_id": "isotope-co", "name": "同位素制药车间", "purpose": "sale", "document_no": "场所验〔2025〕11号", "qualified_on": "2025-06-01", "valid_to": "2027-06-01"})
    service.register_site("admin", {"site_id": "site-hosp", "operator_id": "hospital-a", "name": "核医学科场所", "purpose": "medical_use", "document_no": "场所验〔2025〕18号", "qualified_on": "2025-08-01", "valid_to": "2027-08-01"})

    # 产品批次
    clock.current = datetime(2026, 9, 1, 9, 0, tzinfo=timezone.utc)
    service.register_batch("ops", {"batch_id": "batch-i131-0901", "product_code": "I-131", "category": "放射性药品", "owner_id": "isotope-co", "site_id": "site-prod", "produced_on": "2026-09-01"})

    # 2026-09-10 承运人受托把批次运至医院核医学科
    clock.current = datetime(2026, 9, 10, 8, 0, tzinfo=timezone.utc)
    transport = service.record_handover("ops", {"handover_id": "ho-001", "batch_id": "batch-i131-0901", "kind": "transport", "actor_id": "carrier-co", "shipper_id": "isotope-co", "receiver_id": "hospital-a", "site_id": "site-hosp", "occurred_on": "2026-09-10", "document_no": "运单 YD-20260910-01"})

    # 2026-09-12 医院投入临床使用
    clock.current = datetime(2026, 9, 12, 8, 0, tzinfo=timezone.utc)
    use = service.record_handover("ops", {"handover_id": "ho-002", "batch_id": "batch-i131-0901", "kind": "use", "actor_id": "hospital-a", "receiver_id": "hospital-a", "site_id": "site-hosp", "occurred_on": "2026-09-12", "document_no": "领用单 LY-0912"})

    # 合规审查：截至 09-15 全部交接合法，结案
    clock.current = datetime(2026, 9, 15, 10, 0, tzinfo=timezone.utc)
    service.open_review("comp", "rev-0901", "batch-i131-0901", "2026-09-15")
    service.close_review("comp", "rev-0901")
    closed_review = service.review("auditor", "rev-0901")

    # 09-19 宣告医院许可 09-20 起撤销
    clock.current = datetime(2026, 9, 19, 14, 0, tzinfo=timezone.utc)
    service.revoke_license("admin", "lic-med-01", "2026-09-20", "监督检查发现辐射安全隐患")

    before_revoke = service.authorization_at("auditor", "batch-i131-0901", "hospital-a", "use", "2026-09-19")
    after_revoke = service.authorization_at("auditor", "batch-i131-0901", "hospital-a", "use", "2026-09-21")

    # 撤销后尝试继续使用：被阻止，并指出缺失环节
    clock.current = datetime(2026, 9, 25, 8, 0, tzinfo=timezone.utc)
    blocked = service.record_handover("ops", {"handover_id": "ho-003", "batch_id": "batch-i131-0901", "kind": "use", "actor_id": "hospital-a", "receiver_id": "hospital-a", "site_id": "site-hosp", "occurred_on": "2026-09-25", "document_no": "补录申请单 BL-0925"})

    # 09-29 补录一张 09-14 的迟到使用凭证：已结案审查被标记证据变化，但结论不被改写
    clock.current = datetime(2026, 9, 29, 16, 0, tzinfo=timezone.utc)
    late = service.record_handover("ops", {"handover_id": "ho-004", "batch_id": "batch-i131-0901", "kind": "use", "actor_id": "hospital-a", "receiver_id": "hospital-a", "site_id": "site-hosp", "occurred_on": "2026-09-14", "document_no": "迟到交接单 D-0914"})
    review_after_late = service.review("auditor", "rev-0901")

    trace = service.chain_trace("auditor", "batch-i131-0901")
    result = {
        "status": "ok",
        "workspace": workspace.name,
        "transport": {"decision": transport["decision"], "bases": len(transport["bases"])},
        "use": {"decision": use["decision"], "first_gap": None if use["authorized"] else use["gaps"][0]["code"]},
        "closed_review": {"state": closed_review["state"], "conclusion": closed_review["conclusion"], "evidence_changed": closed_review["evidence_changed"]},
        "authorization_before_revocation": before_revoke["authorized"],
        "authorization_after_revocation": {"authorized": after_revoke["authorized"], "gap": after_revoke["gaps"][0]["code"]},
        "blocked_handover": {"decision": blocked["decision"], "gap": blocked["gaps"][0]["code"]},
        "late_entry": {"late": late["late_entry"], "decision": late["decision"]},
        "review_after_late_evidence": {"state": review_after_late["state"], "conclusion": review_after_late["conclusion"], "evidence_changed": review_after_late["evidence_changed"], "snapshot_intact": review_after_late["snapshot_intact"], "new_evidence": review_after_late["new_evidence"]},
        "chain": {"events": len(trace["events"]), "current_custodian": trace["current_custodian"]},
        "audit": service.audit_chain("auditor"),
    }
    connection.close()
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="运行核技术应用许可与流转服务离线验收")
    parser.add_argument("--workspace", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    print(json.dumps(run(args.workspace), ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
