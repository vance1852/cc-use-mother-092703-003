"""授权链重建。

一个批次的授权链由四类事实拼成：

1. 许可批文（持有人、活动范围、产品、场所、有效期）；
2. 场所资质（启用区间、停用区间）；
3. 撤销事实（独立追加，不删除原批文行）；
4. 交接单（谁在何时把批次交给谁、由谁承运、落在哪个场所）。

所有查询都接受两个时刻：

- ``as_of``：业务时点，回答“那一天这件产品处于什么状态”；
- ``knowledge_cutoff``：登记知识截止时点，回答“在那个登记时点，系统已知
  哪些凭证”。结案的合规审查冻结自己的截止时点，因此之后补录的撤销或迟到
  交接单不会静默改变历史结论。
"""

from __future__ import annotations

import sqlite3
from typing import Any, Iterable

from .clock import parse_utc, utc_text


def _norm(value: str) -> str:
    return utc_text(parse_utc(value))


def _finding(code: str, status: str, message: str, basis: dict[str, Any] | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"code": code, "status": status, "message": message}
    if basis is not None:
        result["basis"] = basis
    return result


def _license_rows(
    connection: sqlite3.Connection,
    org_id: str,
    activity: str,
    item_code: str,
    at: str,
    knowledge_cutoff: str,
) -> list[sqlite3.Row]:
    """返回在业务时点 at 有效、且在 knowledge_cutoff 前已登记的许可范围行。"""
    return connection.execute(
        """
        SELECT l.license_id, l.license_no, l.holder_org_id, l.valid_from, l.valid_to,
               l.document_ref AS license_document, l.created_at AS license_recorded_at,
               s.scope_id, s.site_id AS scope_site_id, s.document_ref AS scope_document,
               s.recorded_at AS scope_recorded_at,
               r.revocation_id, r.effective_at AS revoked_at, r.recorded_at AS revocation_recorded_at
        FROM license_scopes s
        JOIN licenses l ON l.license_id = s.license_id
        LEFT JOIN license_revocations r ON r.license_id = l.license_id
        WHERE l.holder_org_id = ?
          AND s.activity = ?
          AND s.item_code = ?
          AND l.valid_from <= ? AND l.valid_to > ?
          AND l.created_at <= ?
          AND s.recorded_at <= ?
        ORDER BY l.license_id, s.scope_id
        """,
        (org_id, activity, item_code, at, at, knowledge_cutoff, knowledge_cutoff),
    ).fetchall()


def _site_ok(
    connection: sqlite3.Connection,
    site_id: str | None,
    org_id: str,
    at: str,
    knowledge_cutoff: str,
) -> dict[str, Any] | None:
    """使用类范围要求接收场所属于该单位、在业务时点启用且未被停用。"""
    if site_id is None:
        return None
    site = connection.execute(
        "SELECT * FROM sites WHERE site_id=? AND created_at<=?",
        (site_id, knowledge_cutoff),
    ).fetchone()
    if site is None:
        return _finding("site.unknown", "missing", f"场所 {site_id} 在知识截止时点尚未登记")
    if site["org_id"] != org_id:
        return _finding(
            "site.owner_mismatch",
            "blocked",
            f"场所 {site_id} 不属于接收单位 {org_id}",
            {"site_id": site_id, "site_owner": site["org_id"]},
        )
    if not (_norm(site["valid_from"]) <= at and (site["valid_to"] is None or _norm(site["valid_to"]) > at)):
        return _finding(
            "site.expired",
            "missing",
            f"场所 {site_id} 在 {at} 不在资质有效期内",
            {"site_id": site_id, "valid_from": site["valid_from"], "valid_to": site["valid_to"]},
        )
    suspension = connection.execute(
        "SELECT * FROM site_suspensions WHERE site_id=? AND recorded_at<=? AND effective_at<=? "
        "AND (ends_at IS NULL OR ends_at>?) ORDER BY suspension_id",
        (site_id, knowledge_cutoff, at, at),
    ).fetchone()
    if suspension is not None:
        return _finding(
            "site.suspended",
            "blocked",
            f"场所 {site_id} 在 {at} 处于停用状态：{suspension['reason']}",
            {
                "site_id": site_id,
                "effective_at": suspension["effective_at"],
                "ends_at": suspension["ends_at"],
                "reason": suspension["reason"],
            },
        )
    return _finding(
        "site.ok",
        "ok",
        f"场所 {site_id} 在 {at} 具备有效资质",
        {"site_id": site_id, "valid_from": site["valid_from"], "valid_to": site["valid_to"]},
    )


def _pick_basis(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "license_id": row["license_id"],
        "license_no": row["license_no"],
        "scope_id": row["scope_id"],
        "holder_org_id": row["holder_org_id"],
        "valid_from": row["valid_from"],
        "valid_to": row["valid_to"],
        "license_document": row["license_document"],
        "scope_document": row["scope_document"],
        "recorded_at": row["scope_recorded_at"],
    }


def authorize_party(
    connection: sqlite3.Connection,
    org_id: str,
    activity: str,
    item_code: str,
    at: str,
    knowledge_cutoff: str,
    site_id: str | None = None,
) -> list[dict[str, Any]]:
    """检查单个单位在 at 时点从事某活动的许可依据，返回细目列表。"""
    at = _norm(at)
    knowledge_cutoff = _norm(knowledge_cutoff)
    findings: list[dict[str, Any]] = []
    rows = _license_rows(connection, org_id, activity, item_code, at, knowledge_cutoff)

    if activity == "use":
        site_finding = _site_ok(connection, site_id, org_id, at, knowledge_cutoff)
        if site_finding is not None:
            findings.append(site_finding)
        rows = [row for row in rows if site_id is None or row["scope_site_id"] == site_id]

    def still_live(row: sqlite3.Row) -> bool:
        return (
            row["revocation_id"] is None
            or _norm(row["revocation_recorded_at"]) > knowledge_cutoff
            or _norm(row["revoked_at"]) > at
        )

    live_scope_ids = {row["scope_id"] for row in rows if still_live(row)}
    # 被撤销的许可也要作为“阻断依据”显式列出，而不是静默丢弃。
    for row in rows:
        if row["scope_id"] not in live_scope_ids:
            findings.append(
                _finding(
                    "license.revoked",
                    "blocked",
                    f"许可 {row['license_no']} 已于 {row['revoked_at']} 撤销：不可作为 {at} 的依据",
                    {
                        "license_id": row["license_id"],
                        "license_no": row["license_no"],
                        "revoked_at": row["revoked_at"],
                    },
                )
            )

    if live_scope_ids:
        findings.append(
            _finding(
                f"license.{activity}",
                "ok",
                f"单位 {org_id} 持有覆盖 {item_code} 的{_ACTIVITY_LABEL[activity]}许可",
                _pick_basis(next(row for row in rows if row["scope_id"] in live_scope_ids)),
            )
        )
    elif not any(item["status"] == "blocked" for item in findings):
        findings.append(
            _finding(
                f"license.{activity}.missing",
                "missing",
                f"单位 {org_id} 在 {at} 没有覆盖 {item_code} 的有效{_ACTIVITY_LABEL[activity]}许可"
                + (f"（场所 {site_id}）" if activity == "use" and site_id else ""),
            )
        )
    return findings


_ACTIVITY_LABEL = {"transport": "运输", "use": "使用", "transfer": "转让"}


def handoff_findings(
    connection: sqlite3.Connection,
    handoff: sqlite3.Row,
    knowledge_cutoff: str,
    expected_from_org: str | None,
) -> list[dict[str, Any]]:
    """评估单笔交接在其发生时点的全部授权依据。"""
    at = _norm(handoff["occurred_at"])
    batch = connection.execute("SELECT * FROM product_batches WHERE batch_id=?", (handoff["batch_id"],)).fetchone()
    findings: list[dict[str, Any]] = []

    if expected_from_org is not None and handoff["from_org_id"] != expected_from_org:
        findings.append(
            _finding(
                "custody.break",
                "blocked",
                f"交接由 {handoff['from_org_id']} 发起，但链上当前持有人为 {expected_from_org}",
                {"expected_from": expected_from_org, "actual_from": handoff["from_org_id"]},
            )
        )

    findings.extend(authorize_party(connection, handoff["from_org_id"], "transfer", batch["item_code"], at, knowledge_cutoff))
    findings.extend(authorize_party(connection, handoff["carrier_org_id"], "transport", batch["item_code"], at, knowledge_cutoff))
    findings.extend(authorize_party(connection, handoff["to_org_id"], "transfer", batch["item_code"], at, knowledge_cutoff))
    if handoff["site_id"] is not None:
        findings.extend(
            authorize_party(
                connection, handoff["to_org_id"], "use", batch["item_code"], at, knowledge_cutoff, handoff["site_id"]
            )
        )
    else:
        findings.append(
            _finding(
                "site.none",
                "ok",
                "本笔为运输中转，未落地到使用场所",
            )
        )
    return findings


def _status(findings: Iterable[dict[str, Any]]) -> str:
    statuses = {item["status"] for item in findings}
    if "blocked" in statuses:
        return "blocked"
    if "missing" in statuses:
        return "incomplete"
    return "authorized"


def build_chain(
    connection: sqlite3.Connection,
    batch_id: str,
    as_of: str | None = None,
    knowledge_cutoff: str | None = None,
) -> dict[str, Any]:
    """重建批次在 as_of 业务时点、knowledge_cutoff 知识时点下的授权链。"""
    batch = connection.execute("SELECT * FROM product_batches WHERE batch_id=?", (batch_id,)).fetchone()
    if batch is None:
        raise LookupError(batch_id)

    cutoff = _norm(knowledge_cutoff) if knowledge_cutoff else _norm("9999-12-31T23:59:59+00:00")
    business_as_of = _norm(as_of) if as_of else cutoff

    handoffs = connection.execute(
        "SELECT * FROM custody_handoffs WHERE batch_id=? AND recorded_at<=? AND occurred_at<=? "
        "ORDER BY occurred_at,handoff_id",
        (batch_id, cutoff, business_as_of),
    ).fetchall()

    segments: list[dict[str, Any]] = []
    current_holder = batch["origin_org_id"]
    chain_blocked = False
    for handoff in handoffs:
        findings = handoff_findings(connection, handoff, cutoff, current_holder)
        segment_status = _status(findings)
        if segment_status == "blocked":
            chain_blocked = True
        segments.append(
            {
                "handoff_id": handoff["handoff_id"],
                "occurred_at": handoff["occurred_at"],
                "recorded_at": handoff["recorded_at"],
                "late_evidence": _norm(handoff["recorded_at"]) > _norm(handoff["occurred_at"]),
                "from_org_id": handoff["from_org_id"],
                "to_org_id": handoff["to_org_id"],
                "carrier_org_id": handoff["carrier_org_id"],
                "site_id": handoff["site_id"],
                "evidence_doc": handoff["evidence_doc"],
                "status": segment_status,
                "findings": findings,
            }
        )
        # 链断裂后不推进持有人，便于指出缺口位置；未阻断但缺依据时仍推进事实链。
        if segment_status != "blocked":
            current_holder = handoff["to_org_id"]

    missing = [
        {"segment": segment["handoff_id"], **item}
        for segment in segments
        for item in segment["findings"]
        if item["status"] in ("missing", "blocked")
    ]
    return {
        "batch_id": batch_id,
        "item_code": batch["item_code"],
        "product_name": batch["product_name"],
        "as_of": business_as_of,
        "knowledge_cutoff": cutoff,
        "origin_org_id": batch["origin_org_id"],
        "holder_org_id": current_holder,
        "site_id": segments[-1]["site_id"] if segments else None,
        "status": "blocked" if chain_blocked else ("incomplete" if missing else "authorized"),
        "handoffs": segments,
        "missing": missing,
    }


def can_authorize(
    connection: sqlite3.Connection,
    batch_id: str,
    org_id: str,
    activity: str,
    as_of: str,
    knowledge_cutoff: str | None = None,
    site_id: str | None = None,
) -> dict[str, Any]:
    """回答“某批次在某日能否由指定单位运输/使用/转让”。"""
    batch = connection.execute("SELECT * FROM product_batches WHERE batch_id=?", (batch_id,)).fetchone()
    if batch is None:
        raise LookupError(batch_id)
    cutoff = _norm(knowledge_cutoff) if knowledge_cutoff else _norm("9999-12-31T23:59:59+00:00")
    at = _norm(as_of)

    findings = authorize_party(connection, org_id, activity, batch["item_code"], at, cutoff, site_id)
    chain = build_chain(connection, batch_id, at, cutoff)

    custody: list[dict[str, Any]] = []
    if activity in ("use", "transfer"):
        if chain["holder_org_id"] != org_id:
            custody.append(
                _finding(
                    "custody.not_holder",
                    "missing",
                    f"{org_id} 在 {at} 不是批次持有人（链上持有人为 {chain['holder_org_id']}）",
                    {"holder_org_id": chain["holder_org_id"]},
                )
            )
        else:
            custody.append(_finding("custody.holder", "ok", f"{org_id} 在 {at} 持有该批次"))
    if activity == "use" and chain["site_id"] is not None and site_id is not None and chain["site_id"] != site_id:
        custody.append(
            _finding(
                "custody.site_mismatch",
                "missing",
                f"批次实际位于场所 {chain['site_id']}，与申请场所 {site_id} 不一致",
                {"actual_site": chain["site_id"], "requested_site": site_id},
            )
        )

    all_findings = findings + custody
    return {
        "batch_id": batch_id,
        "org_id": org_id,
        "activity": activity,
        "as_of": at,
        "knowledge_cutoff": cutoff,
        "authorized": _status(all_findings) == "authorized",
        "status": _status(all_findings),
        "findings": all_findings,
        "chain_status": chain["status"],
    }
