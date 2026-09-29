"""许可与流转的事务用例和授权链评估引擎。

授权链由四类凭证拼成：

    许可证（含许可范围） ─┐
    场所资质 ────────────┼─► 交接单（运输 / 使用 / 转交）─► 批次保管链
    产品批次 ────────────┘

评估一律按业务日期重放：许可在 d 日有效，当且仅当 valid_from ≤ d ≤ valid_to
且未在 d 日之前（含当日）撤销。登记时刻只用于判定凭证是否迟到补录。
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import date
from typing import Any, Iterable, Mapping

from .clock import SystemClock, utc_text
from .errors import Conflict, Forbidden, InvalidState, NotFound, ValidationFailed
from .models import (
    HandoverDraft,
    LicenseDraft,
    ProductBatchDraft,
    SiteQualificationDraft,
    ScopeItemDraft,
)
from .storage import initialize, transaction

ROLE_PERMISSIONS = {
    "licensor": {"license.write", "license.revoke", "site.write"},
    "operator": {"batch.write", "handover.write"},
    "compliance": {"review.write", "review.close", "report.read", "audit.read"},
    "auditor": {"report.read", "audit.read"},
}

# 交接动作对应的许可类别与场所用途
ACTION_LICENSE_KINDS = {
    "transport": ("transport",),
    "use": ("medical_use", "irradiation"),
    "transfer": ("sale", "medical_use", "irradiation"),
}
ACTION_SITE_PURPOSES = {
    "transport": ("storage", "medical_use", "irradiation", "sale"),
    "use": ("medical_use", "irradiation"),
    "transfer": ("storage", "sale", "medical_use", "irradiation"),
}


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def gap(code: str, message: str) -> dict[str, str]:
    return {"code": code, "message": message}


class LicenseChainService:
    def __init__(self, connection: sqlite3.Connection, clock=None) -> None:
        self.connection = connection
        self.clock = clock or SystemClock()
        initialize(connection)

    # ── 基础设施工具 ──────────────────────────────────────────────

    def _now(self) -> str:
        return utc_text(self.clock.now())

    def _today(self) -> str:
        return self.clock.now().date().isoformat()

    def _user(self, user_id: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM chain_users WHERE user_id=?", (user_id,)
        ).fetchone()
        if row is None:
            raise NotFound("用户不存在")
        if not row["active"]:
            raise Forbidden("用户已停用")
        return row

    def _require(self, user_id: str, permission: str) -> sqlite3.Row:
        user = self._user(user_id)
        if permission not in ROLE_PERMISSIONS[user["role"]]:
            raise Forbidden(f"角色 {user['role']} 无权执行 {permission}")
        return user

    def _audit(
        self,
        entity_type: str,
        entity_id: str,
        event_type: str,
        actor_id: str,
        payload: Mapping[str, Any],
    ) -> None:
        previous = self.connection.execute(
            "SELECT event_hash FROM chain_audit_events ORDER BY event_id DESC LIMIT 1"
        ).fetchone()
        previous_hash = "0" * 64 if previous is None else previous["event_hash"]
        body = {
            "entity_type": entity_type,
            "entity_id": entity_id,
            "event_type": event_type,
            "actor_id": actor_id,
            "payload": payload,
            "created_at": self._now(),
            "previous_hash": previous_hash,
        }
        event_hash = digest(body)
        self.connection.execute(
            "INSERT INTO chain_audit_events(entity_type,entity_id,event_type,actor_id,payload_json,"
            "previous_hash,event_hash,created_at) VALUES(?,?,?,?,?,?,?,?)",
            (
                entity_type,
                entity_id,
                event_type,
                actor_id,
                canonical_json(payload),
                previous_hash,
                event_hash,
                body["created_at"],
            ),
        )

    def create_user(self, user_id: str, display_name: str, role: str) -> dict[str, Any]:
        if role not in ROLE_PERMISSIONS:
            raise ValidationFailed("未知角色")
        if not user_id.strip() or not display_name.strip():
            raise ValidationFailed("用户编号和名称不能为空")
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO chain_users(user_id,display_name,role,created_at) VALUES(?,?,?,?)",
                    (user_id.strip(), display_name.strip(), role, self._now()),
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict("用户已经存在") from exc
        return {"user_id": user_id.strip(), "role": role}

    # ── 许可证与许可范围 ──────────────────────────────────────────

    def register_license(self, actor_id: str, raw: Mapping[str, Any]) -> dict[str, Any]:
        self._require(actor_id, "license.write")
        draft = LicenseDraft.from_dict(raw)
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO licenses(license_id,holder_id,kind,authority,document_no,valid_from,valid_to,"
                    "created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        draft.license_id,
                        draft.holder_id,
                        draft.kind,
                        draft.authority,
                        draft.document_no,
                        draft.valid_from,
                        draft.valid_to,
                        actor_id,
                        self._now(),
                    ),
                )
                self._audit("license", draft.license_id, "license.registered", actor_id, dict(raw))
        except sqlite3.IntegrityError as exc:
            raise Conflict("许可证编号已经存在") from exc
        return self.license(draft.license_id)

    def add_license_scope(self, actor_id: str, license_id: str, raw: Mapping[str, Any]) -> dict[str, Any]:
        self._require(actor_id, "license.write")
        license_row = self._license_row(license_id)
        if license_row["state"] != "active":
            raise InvalidState("已撤销许可证不能增加范围")
        item = ScopeItemDraft.from_dict(raw)
        added_on = item.added_on or self._today()
        if added_on < license_row["valid_from"]:
            raise ValidationFailed("范围生效日不能早于许可起始日")
        try:
            with transaction(self.connection, immediate=True):
                cursor = self.connection.execute(
                    "INSERT INTO license_scopes(license_id,scope_code,activity,note,added_on,created_at) "
                    "VALUES(?,?,?,?,?,?)",
                    (license_id, item.scope_code_value, item.activity, item.note, added_on, self._now()),
                )
                scope_id = int(cursor.lastrowid)
                self._audit(
                    "license",
                    license_id,
                    "license.scope_added",
                    actor_id,
                    {"scope_id": scope_id, "scope_code": item.scope_code_value, "added_on": added_on},
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict("该许可范围代码已存在") from exc
        return {
            "scope_id": scope_id,
            "license_id": license_id,
            "scope_code": item.scope_code_value,
            "activity": item.activity,
        }

    def revoke_license(
        self, actor_id: str, license_id: str, effective_on: str, reason: str
    ) -> dict[str, Any]:
        self._require(actor_id, "license.revoke")
        license_row = self._license_row(license_id)
        if license_row["state"] == "revoked":
            raise InvalidState("许可证已经撤销")
        day = self._validate_day(effective_on, "effective_on")
        if day < license_row["valid_from"]:
            raise ValidationFailed("撤销生效日不能早于许可起始日")
        # 撤销不得推翻生效日之前（含当日）已合法完成的交接
        tainted = self.connection.execute(
            "SELECT h.handover_id FROM handover_authorizations a "
            "JOIN handovers h ON h.handover_id=a.handover_id "
            "WHERE a.basis_type='license' AND a.ref_id=? AND h.decision='recorded' "
            "AND h.occurred_on>=? LIMIT 1",
            (license_id, day),
        ).fetchone()
        if tainted is not None:
            raise Conflict(
                "撤销生效日晚于或等于依据该许可完成的交接日，将动摇既有合法交接",
                {"earliest_conflict_handover": tainted["handover_id"]},
            )
        with transaction(self.connection, immediate=True):
            cursor = self.connection.execute(
                "UPDATE licenses SET state='revoked',revoke_effective_on=?,revoke_reason=?,"
                "revoked_by=?,revoked_at=?,revision=revision+1 WHERE license_id=? AND state='active'",
                (day, reason, actor_id, self._now(), license_id),
            )
            if cursor.rowcount != 1:
                raise InvalidState("许可证状态已变化")
            self._audit(
                "license",
                license_id,
                "license.revoked",
                actor_id,
                {"effective_on": day, "reason": reason},
            )
        return self.license(license_id)

    def license(self, license_id: str) -> dict[str, Any]:
        row = self._license_row(license_id)
        result = dict(row)
        result["scopes"] = [
            dict(item)
            for item in self.connection.execute(
                "SELECT scope_id,scope_code,activity,note,added_on FROM license_scopes "
                "WHERE license_id=? ORDER BY scope_id",
                (license_id,),
            ).fetchall()
        ]
        return result

    def _license_row(self, license_id: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM licenses WHERE license_id=?", (license_id,)
        ).fetchone()
        if row is None:
            raise NotFound("许可证不存在")
        return row

    # ── 场所资质 ──────────────────────────────────────────────────

    def register_site(self, actor_id: str, raw: Mapping[str, Any]) -> dict[str, Any]:
        self._require(actor_id, "site.write")
        draft = SiteQualificationDraft.from_dict(raw)
        name = str(raw.get("name", "")).strip()
        if not name:
            raise ValidationFailed("name 不能为空")
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO site_qualifications(site_id,operator_id,name,purpose,document_no,"
                    "qualified_on,valid_to,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        draft.site_id,
                        draft.operator_id,
                        name,
                        draft.purpose,
                        draft.document_no,
                        draft.qualified_on,
                        draft.valid_to,
                        actor_id,
                        self._now(),
                    ),
                )
                self._audit("site", draft.site_id, "site.registered", actor_id, dict(raw))
        except sqlite3.IntegrityError as exc:
            raise Conflict("场所编号已经存在") from exc
        return self.site(draft.site_id)

    def revoke_site(self, actor_id: str, site_id: str, effective_on: str, reason: str) -> dict[str, Any]:
        self._require(actor_id, "license.revoke")
        row = self._site_row(site_id)
        if row["state"] == "revoked":
            raise InvalidState("场所资质已经撤销")
        day = self._validate_day(effective_on, "effective_on")
        if day < row["qualified_on"]:
            raise ValidationFailed("撤销生效日不能早于资质取得日")
        tainted = self.connection.execute(
            "SELECT h.handover_id FROM handover_authorizations a "
            "JOIN handovers h ON h.handover_id=a.handover_id "
            "WHERE a.basis_type='site' AND a.ref_id=? AND h.decision='recorded' "
            "AND h.occurred_on>=? LIMIT 1",
            (site_id, day),
        ).fetchone()
        if tainted is not None:
            raise Conflict(
                "撤销生效日将推翻在该场所已合法完成的交接",
                {"earliest_conflict_handover": tainted["handover_id"]},
            )
        with transaction(self.connection, immediate=True):
            cursor = self.connection.execute(
                "UPDATE site_qualifications SET state='revoked',revoke_effective_on=?,revoke_reason=?,"
                "revoked_by=?,revoked_at=?,revision=revision+1 WHERE site_id=? AND state='active'",
                (day, reason, actor_id, self._now(), site_id),
            )
            if cursor.rowcount != 1:
                raise InvalidState("场所资质状态已变化")
            self._audit("site", site_id, "site.revoked", actor_id, {"effective_on": day, "reason": reason})
        return self.site(site_id)

    def site(self, site_id: str) -> dict[str, Any]:
        return dict(self._site_row(site_id))

    def _site_row(self, site_id: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM site_qualifications WHERE site_id=?", (site_id,)
        ).fetchone()
        if row is None:
            raise NotFound("场所资质不存在")
        return row

    # ── 产品批次 ──────────────────────────────────────────────────

    def register_batch(self, actor_id: str, raw: Mapping[str, Any]) -> dict[str, Any]:
        self._require(actor_id, "batch.write")
        draft = ProductBatchDraft.from_dict(raw)
        if self._site_row(draft.site_id)["operator_id"] != draft.owner_id:
            raise ValidationFailed("批次初始场所不属于批次持有人")
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO product_batches(batch_id,product_code,category,owner_id,site_id,"
                    "produced_on,created_by,created_at) VALUES(?,?,?,?,?,?,?,?)",
                    (
                        draft.batch_id,
                        draft.product_code,
                        draft.category,
                        draft.owner_id,
                        draft.site_id,
                        draft.produced_on,
                        actor_id,
                        self._now(),
                    ),
                )
                self._audit("batch", draft.batch_id, "batch.registered", actor_id, dict(raw))
        except sqlite3.IntegrityError as exc:
            raise Conflict("产品批次编号已经存在") from exc
        return self.batch(draft.batch_id)

    def batch(self, batch_id: str) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT * FROM product_batches WHERE batch_id=?", (batch_id,)
        ).fetchone()
        if row is None:
            raise NotFound("产品批次不存在")
        return dict(row)

    # ── 授权评估引擎（按业务日期 d 重放） ─────────────────────────

    @staticmethod
    def _valid_on(row: sqlite3.Row, day: str) -> bool:
        """凭证在业务日 d 是否有效：到期判断 + 撤销生效日判断。"""
        start = row["qualified_on"] if "qualified_on" in row.keys() else row["valid_from"]
        end = row["valid_to"]
        if day < start or (end is not None and day > end):
            return False
        effective = row["revoke_effective_on"]
        return effective is None or day < effective

    def _license_status(
        self, holder_id: str, kinds: Iterable[str], product_code: str, day: str
    ) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
        """返回（授权依据，缺失环节）。同一证覆盖多个类别时只计一次。"""
        bases: list[dict[str, str]] = []
        gaps: list[dict[str, str]] = []
        kind_values = tuple(kinds)
        rows = self.connection.execute(
            "SELECT * FROM licenses WHERE holder_id=? AND kind IN (%s) ORDER BY license_id"
            % ",".join("?" for _ in kind_values),
            (holder_id, *kind_values),
        ).fetchall()
        if not rows:
            gaps.append(gap("actor.license_missing", f"{holder_id} 缺少相应类别的许可证"))
            return bases, gaps
        live = [row for row in rows if self._valid_on(row, day)]
        if not live:
            revoked = next(
                (row for row in rows if row["revoke_effective_on"] is not None and day >= row["revoke_effective_on"]),
                None,
            )
            if revoked is not None:
                gaps.append(gap("actor.license_revoked", f"许可证 {revoked['license_id']} 已在 {day} 前撤销"))
            elif any(row["valid_to"] is not None and row["valid_to"] < day for row in rows):
                expired = next(row for row in rows if row["valid_to"] is not None and row["valid_to"] < day)
                gaps.append(gap("actor.license_expired", f"许可证 {expired['license_id']} 已超过有效期"))
            else:
                gaps.append(gap("actor.license_not_started", f"{holder_id} 的许可证在 {day} 尚未生效"))
            return bases, gaps
        covered = False
        for row in live:
            scope = self.connection.execute(
                "SELECT scope_code,activity,added_on FROM license_scopes "
                "WHERE license_id=? AND scope_code=? AND added_on<=?",
                (row["license_id"], product_code, day),
            ).fetchone()
            if scope is not None:
                covered = True
                bases.append(
                    {
                        "type": "license",
                        "id": row["license_id"],
                        "detail": f"{row['kind']} 许可 {row['document_no']}，范围 {scope['scope_code']}（{scope['activity']}）",
                    }
                )
        if not covered:
            gaps.append(gap("scope.not_covered", f"许可证范围未覆盖产品 {product_code}"))
        return bases, gaps

    def _site_status(
        self, site_id: str, operator_id: str, purposes: Iterable[str], day: str
    ) -> tuple[dict[str, str] | None, list[dict[str, str]]]:
        row = self.connection.execute(
            "SELECT * FROM site_qualifications WHERE site_id=?", (site_id,)
        ).fetchone()
        if row is None:
            return None, [gap("site.qualification_missing", f"场所 {site_id} 没有资质登记")]
        gaps: list[dict[str, str]] = []
        if row["operator_id"] != operator_id:
            gaps.append(
                gap("site.operator_mismatch", f"场所 {site_id} 由 {row['operator_id']} 运营，不属于 {operator_id}")
            )
        if row["purpose"] not in tuple(purposes):
            gaps.append(gap("site.purpose_mismatch", f"场所用途 {row['purpose']} 不支持该动作"))
        if not self._valid_on(row, day):
            if row["revoke_effective_on"] is not None and day >= row["revoke_effective_on"]:
                code, message = "site.qualification_revoked", f"场所 {site_id} 资质已撤销"
            else:
                code, message = "site.qualification_expired", f"场所 {site_id} 资质不在有效期内"
            gaps.append(gap(code, message))
        if gaps:
            return None, gaps
        return {
            "type": "site",
            "id": site_id,
            "detail": f"场所资质 {row['document_no']}，用途 {row['purpose']}",
        }, []

    def _custodian_on(self, batch_id: str, day: str) -> tuple[str | None, sqlite3.Row | None]:
        """d 日（含）之前最后一次已登记交接后的实际保管单位。"""
        row = self.connection.execute(
            "SELECT * FROM handovers WHERE batch_id=? AND decision='recorded' AND occurred_on<=? "
            "ORDER BY occurred_on DESC, rowid DESC LIMIT 1",
            (batch_id, day),
        ).fetchone()
        if row is None:
            return None, None
        return row["receiver_id"], row

    def assess_handover(self, draft: HandoverDraft) -> dict[str, Any]:
        """对交接单做完整授权链评估，不写库。"""
        batch_row = self.connection.execute(
            "SELECT * FROM product_batches WHERE batch_id=?", (draft.batch_id,)
        ).fetchone()
        if batch_row is None:
            raise NotFound("产品批次不存在")
        day = draft.occurred_on
        gaps: list[dict[str, str]] = []
        bases: list[dict[str, str]] = []

        # 1) 保管链连续性：运输时托运方、其余动作时执行单位必须是当前保管方
        custody_claimant = draft.shipper_id if draft.kind == "transport" else draft.actor_id
        claimant_label = "托运方" if draft.kind == "transport" else "执行单位"
        previous = self.connection.execute(
            "SELECT * FROM handovers WHERE batch_id=? AND decision='recorded' AND occurred_on<=? "
            "ORDER BY occurred_on DESC, rowid DESC LIMIT 1",
            (draft.batch_id, day),
        ).fetchone()
        if previous is None:
            if custody_claimant != batch_row["owner_id"]:
                gaps.append(
                    gap(
                        "chain.origin",
                        f"批次原始持有人为 {batch_row['owner_id']}，{claimant_label} {custody_claimant} 无法发起首笔交接",
                    )
                )
            else:
                bases.append({"type": "batch", "id": draft.batch_id, "detail": "批次登记的原始持有人"})
        elif previous["receiver_id"] != custody_claimant:
            gaps.append(
                gap(
                    "chain.custody",
                    f"上一合法保管单位为 {previous['receiver_id']}（交接单 {previous['handover_id']}），"
                    f"{claimant_label} {custody_claimant} 不持有该批次",
                )
            )
        else:
            bases.append(
                {"type": "handover", "id": previous["handover_id"], "detail": f"{day} 前最近一次合法交接"}
            )

        # 2) 执行单位许可证 + 产品范围（运输时为承运人，其余为执行单位本身）
        kinds = ACTION_LICENSE_KINDS[draft.kind]
        license_bases, license_gaps = self._license_status(
            draft.actor_id, kinds, batch_row["product_code"], day
        )
        bases.extend(license_bases)
        gaps.extend(license_gaps)

        # 3) 接收单位也须具备合法持有该产品的许可（运输的收货方同样要能持有）
        receiver_bases, receiver_gaps = self._license_status(
            draft.receiver_id, ("sale", "medical_use", "irradiation"), batch_row["product_code"], day
        )
        bases.extend(receiver_bases)
        gaps.extend(receiver_gaps)

        # 4) 接收场所资质
        site_basis, site_gaps = self._site_status(
            draft.site_id, draft.receiver_id, ACTION_SITE_PURPOSES[draft.kind], day
        )
        if site_basis is not None:
            bases.append(site_basis)
        gaps.extend(site_gaps)

        gaps.extend(site_gaps)

        deduped: list[dict[str, str]] = []
        for base in bases:
            if all(base["type"] != other["type"] or base["id"] != other["id"] for other in deduped):
                deduped.append(base)

        return {
            "batch_id": draft.batch_id,
            "kind": draft.kind,
            "on": day,
            "actor_id": draft.actor_id,
            "shipper_id": draft.shipper_id,
            "receiver_id": draft.receiver_id,
            "site_id": draft.site_id,
            "authorized": not gaps,
            "bases": deduped,
            "gaps": gaps,
        }

    # ── 交接登记 ──────────────────────────────────────────────────

    def record_handover(self, actor_id: str, raw: Mapping[str, Any]) -> dict[str, Any]:
        self._require(actor_id, "handover.write")
        draft = HandoverDraft.from_dict(raw)
        assessment = self.assess_handover(draft)
        decision = "recorded" if assessment["authorized"] else "rejected"
        late_entry = 1 if self._today() > draft.occurred_on else 0
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO handovers(handover_id,batch_id,kind,actor_id,shipper_id,receiver_id,site_id,"
                    "occurred_on,document_no,decision,assessment_json,late_entry,created_by,created_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        draft.handover_id,
                        draft.batch_id,
                        draft.kind,
                        draft.actor_id,
                        draft.shipper_id,
                        draft.receiver_id,
                        draft.site_id,
                        draft.occurred_on,
                        draft.document_no,
                        decision,
                        canonical_json(assessment),
                        late_entry,
                        actor_id,
                        self._now(),
                    ),
                )
                if decision == "recorded":
                    for base in assessment["bases"]:
                        if base["type"] in ("license", "site"):
                            self.connection.execute(
                                "INSERT OR IGNORE INTO handover_authorizations(handover_id,basis_type,ref_id) "
                                "VALUES(?,?,?)",
                                (draft.handover_id, base["type"], base["id"]),
                            )
                # 迟到凭证触及既有审查（含已结案）时留痕，但绝不回写其结论
                self.connection.execute(
                    "INSERT INTO review_evidence_changes(review_id,handover_id,kind,occurred_on,"
                    "late_entry,noted_at) SELECT review_id,?,?,?,?,? FROM compliance_reviews "
                    "WHERE batch_id=? AND as_of_on>=?",
                    (
                        draft.handover_id,
                        draft.kind,
                        draft.occurred_on,
                        late_entry,
                        self._now(),
                        draft.batch_id,
                        draft.occurred_on,
                    ),
                )
                self._audit(
                    "handover",
                    draft.handover_id,
                    "handover.recorded" if decision == "recorded" else "handover.rejected",
                    actor_id,
                    {"batch_id": draft.batch_id, "occurred_on": draft.occurred_on, "late_entry": late_entry},
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict("交接单号已经存在") from exc
        return {"handover_id": draft.handover_id, "decision": decision, "late_entry": bool(late_entry), **assessment}

    # ── 时点授权查询 ──────────────────────────────────────────────

    @staticmethod
    def _validate_day(value: str, field: str) -> str:
        text = value.strip() if isinstance(value, str) else ""
        try:
            return date.fromisoformat(text).isoformat()
        except ValueError as exc:
            raise ValidationFailed(f"{field} 必须是 YYYY-MM-DD 日期") from exc

    def authorization_at(self, actor_id: str, batch_id: str, unit_id: str, action: str, on: str) -> dict[str, Any]:
        """某批次在 on 日能否由 unit_id 执行 action（运输/使用/转交）。"""
        self._require(actor_id, "report.read")
        if action not in ACTION_LICENSE_KINDS:
            raise ValidationFailed("action 必须是 transport、use 或 transfer")
        day = self._validate_day(on, "on")
        batch = self.batch(batch_id)
        gaps: list[dict[str, str]] = []
        bases: list[dict[str, str]] = []

        custodian, last_handover = self._custodian_on(batch_id, day)
        if custodian is None:
            custodian = batch["owner_id"]
            bases.append({"type": "batch", "id": batch_id, "detail": "批次登记的原始持有人"})
        else:
            bases.append(
                {"type": "handover", "id": last_handover["handover_id"], "detail": f"{day} 时的最近合法交接"}
            )
        # 承运人是受托运输，不要求持有批次；使用/转交单位必须是当前保管方
        if action != "transport" and unit_id != custodian:
            gaps.append(gap("custody.not_holder", f"{day} 时批次由 {custodian} 保管，{unit_id} 无权{action}"))

        license_bases, license_gaps = self._license_status(
            unit_id, ACTION_LICENSE_KINDS[action], batch["product_code"], day
        )
        bases.extend(license_bases)
        gaps.extend(license_gaps)

        if action != "transport":
            # 使用/转交需在该单位名下有一处用途匹配且当日有效的场所
            purposes = ACTION_SITE_PURPOSES[action]
            site_row = self.connection.execute(
                "SELECT * FROM site_qualifications WHERE operator_id=? AND purpose IN (%s) "
                "AND qualified_on<=? ORDER BY site_id LIMIT 1" % ",".join("?" for _ in purposes),
                (unit_id, *purposes, day),
            ).fetchone()
            if site_row is None or not self._valid_on(site_row, day):
                gaps.append(gap("site.qualification_missing", f"{unit_id} 在 {day} 没有用途匹配的有效场所"))
            else:
                bases.append(
                    {"type": "site", "id": site_row["site_id"], "detail": f"场所资质 {site_row['document_no']}"}
                )
        return {
            "batch_id": batch_id,
            "unit_id": unit_id,
            "action": action,
            "on": day,
            "custodian": custodian,
            "authorized": not gaps,
            "bases": bases,
            "gaps": gaps,
        }

    # ── 批次保管链追溯 ────────────────────────────────────────────

    def chain_trace(self, actor_id: str, batch_id: str) -> dict[str, Any]:
        self._require(actor_id, "report.read")
        batch = self.batch(batch_id)
        rows = self.connection.execute(
            "SELECT * FROM handovers WHERE batch_id=? ORDER BY occurred_on,rowid",
            (batch_id,),
        ).fetchall()
        current_custodian, last = self._custodian_on(batch_id, "9999-12-31")
        events = []
        for row in rows:
            events.append(
                {
                    "handover_id": row["handover_id"],
                    "kind": row["kind"],
                    "occurred_on": row["occurred_on"],
                    "actor_id": row["actor_id"],
                    "shipper_id": row["shipper_id"],
                    "receiver_id": row["receiver_id"],
                    "site_id": row["site_id"],
                    "decision": row["decision"],
                    "late_entry": bool(row["late_entry"]),
                    "document_no": row["document_no"],
                    **json.loads(row["assessment_json"]),
                }
            )
        return {
            "batch": batch,
            "current_custodian": current_custodian or batch["owner_id"],
            "latest_handover_id": None if last is None else last["handover_id"],
            "events": events,
        }

    # ── 合规审查（结案固化，迟到凭证不静默改写） ──────────────────

    def open_review(self, actor_id: str, review_id: str, batch_id: str, as_of_on: str) -> dict[str, Any]:
        self._require(actor_id, "review.write")
        day = self._validate_day(as_of_on, "as_of_on")
        self.batch(batch_id)
        finding = self._build_finding(batch_id, day)
        snapshot = self._snapshot(batch_id, day)
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO compliance_reviews(review_id,batch_id,as_of_on,conclusion,"
                    "evidence_snapshot_json,evidence_sha256,state,finding_json,created_by,created_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (
                        review_id,
                        batch_id,
                        day,
                        "compliant" if finding["compliant"] else "non_compliant",
                        canonical_json(snapshot),
                        digest(snapshot),
                        "open",
                        canonical_json(finding),
                        actor_id,
                        self._now(),
                    ),
                )
                self._audit("review", review_id, "review.opened", actor_id, {"batch_id": batch_id, "as_of_on": day})
        except sqlite3.IntegrityError as exc:
            raise Conflict("审查编号冲突或同批次同日审查已存在") from exc
        return self.review(actor_id, review_id)

    def _snapshot(self, batch_id: str, day: str) -> dict[str, Any]:
        handovers = [
            {
                "handover_id": row["handover_id"],
                "kind": row["kind"],
                "occurred_on": row["occurred_on"],
                "actor_id": row["actor_id"],
                "shipper_id": row["shipper_id"],
                "receiver_id": row["receiver_id"],
                "site_id": row["site_id"],
                "decision": row["decision"],
                "late_entry": bool(row["late_entry"]),
                "assessment": json.loads(row["assessment_json"]),
            }
            for row in self.connection.execute(
                "SELECT * FROM handovers WHERE batch_id=? AND occurred_on<=? ORDER BY occurred_on,rowid",
                (batch_id, day),
            ).fetchall()
        ]
        licenses = []
        for row in self.connection.execute(
            "SELECT license_id,holder_id,kind,document_no,valid_from,valid_to,state,revoke_effective_on "
            "FROM licenses ORDER BY license_id"
        ).fetchall():
            item = dict(row)
            item["scopes"] = [
                dict(scope)
                for scope in self.connection.execute(
                    "SELECT scope_code,activity,note,added_on FROM license_scopes "
                    "WHERE license_id=? ORDER BY scope_id",
                    (row["license_id"],),
                ).fetchall()
            ]
            licenses.append(item)
        sites = [
            dict(row)
            for row in self.connection.execute(
                "SELECT site_id,operator_id,name,purpose,document_no,qualified_on,valid_to,state,"
                "revoke_effective_on FROM site_qualifications ORDER BY site_id"
            ).fetchall()
        ]
        return {"batch_id": batch_id, "as_of_on": day, "handovers": handovers, "licenses": licenses, "sites": sites}

    def _build_finding(self, batch_id: str, day: str) -> dict[str, Any]:
        trace = self.chain_trace_engine(batch_id)
        relevant = [event for event in trace if event["occurred_on"] <= day]
        items = []
        compliant = True
        for event in relevant:
            if event["decision"] != "recorded":
                compliant = False
            items.append(
                {
                    "handover_id": event["handover_id"],
                    "occurred_on": event["occurred_on"],
                    "decision": event["decision"],
                    "bases": event["bases"],
                    "gaps": event["gaps"],
                }
            )
        return {
            "compliant": compliant,
            "as_of_on": day,
            "checked_handovers": len(items),
            "items": items,
        }

    def chain_trace_engine(self, batch_id: str) -> list[dict[str, Any]]:
        events = []
        for row in self.connection.execute(
            "SELECT handover_id,occurred_on,decision,assessment_json FROM handovers "
            "WHERE batch_id=? ORDER BY occurred_on,rowid",
            (batch_id,),
        ).fetchall():
            assessment = json.loads(row["assessment_json"])
            events.append(
                {
                    "handover_id": row["handover_id"],
                    "occurred_on": row["occurred_on"],
                    "decision": row["decision"],
                    "bases": assessment["bases"],
                    "gaps": assessment["gaps"],
                }
            )
        return events

    def refresh_review(self, actor_id: str, review_id: str) -> dict[str, Any]:
        """仅未结案审查可用新证据重算；结案审查拒绝刷新。"""
        self._require(actor_id, "review.write")
        row = self.connection.execute(
            "SELECT * FROM compliance_reviews WHERE review_id=?", (review_id,)
        ).fetchone()
        if row is None:
            raise NotFound("合规审查不存在")
        if row["state"] != "open":
            raise InvalidState("审查已经结案，迟到凭证不能改写其结论")
        finding = self._build_finding(row["batch_id"], row["as_of_on"])
        snapshot = self._snapshot(row["batch_id"], row["as_of_on"])
        with transaction(self.connection, immediate=True):
            cursor = self.connection.execute(
                "UPDATE compliance_reviews SET conclusion=?,evidence_snapshot_json=?,evidence_sha256=?,"
                "finding_json=? WHERE review_id=? AND state='open'",
                (
                    "compliant" if finding["compliant"] else "non_compliant",
                    canonical_json(snapshot),
                    digest(snapshot),
                    canonical_json(finding),
                    review_id,
                ),
            )
            if cursor.rowcount != 1:
                raise InvalidState("审查状态已变化")
            self.connection.execute(
                "DELETE FROM review_evidence_changes WHERE review_id=?", (review_id,)
            )
            self._audit("review", review_id, "review.refreshed", actor_id, {})
        return self.review(actor_id, review_id)

    def close_review(self, actor_id: str, review_id: str) -> dict[str, Any]:
        self._require(actor_id, "review.close")
        row = self.connection.execute(
            "SELECT * FROM compliance_reviews WHERE review_id=?", (review_id,)
        ).fetchone()
        if row is None:
            raise NotFound("合规审查不存在")
        if row["state"] != "open":
            raise InvalidState("审查已经结案")
        with transaction(self.connection, immediate=True):
            cursor = self.connection.execute(
                "UPDATE compliance_reviews SET state='closed',closed_at=?,closed_by=? "
                "WHERE review_id=? AND state='open'",
                (self._now(), actor_id, review_id),
            )
            if cursor.rowcount != 1:
                raise InvalidState("审查状态已变化")
            self._audit("review", review_id, "review.closed", actor_id, {})
        return self.review(actor_id, review_id)

    def review(self, actor_id: str, review_id: str) -> dict[str, Any]:
        self._require(actor_id, "report.read")
        row = self.connection.execute(
            "SELECT * FROM compliance_reviews WHERE review_id=?", (review_id,)
        ).fetchone()
        if row is None:
            raise NotFound("合规审查不存在")
        snapshot = json.loads(row["evidence_snapshot_json"])
        recorded_hash = digest(snapshot)
        changes = [
            dict(item)
            for item in self.connection.execute(
                "SELECT handover_id,kind,occurred_on,late_entry,noted_at FROM review_evidence_changes "
                "WHERE review_id=? ORDER BY change_id",
                (review_id,),
            ).fetchall()
        ]
        for item in changes:
            item["late_entry"] = bool(item["late_entry"])
        return {
            "review_id": review_id,
            "batch_id": row["batch_id"],
            "as_of_on": row["as_of_on"],
            "state": row["state"],
            "conclusion": row["conclusion"],
            "finding": json.loads(row["finding_json"]),
            "evidence_sha256": row["evidence_sha256"],
            "snapshot_intact": recorded_hash == row["evidence_sha256"],
            "evidence_changed": bool(changes),
            "new_evidence": changes,
            "closed_at": row["closed_at"],
        }

    # ── 审计哈希链 ────────────────────────────────────────────────

    def audit_chain(self, actor_id: str) -> dict[str, Any]:
        self._require(actor_id, "audit.read")
        rows = self.connection.execute("SELECT * FROM chain_audit_events ORDER BY event_id").fetchall()
        previous_hash = "0" * 64
        valid = True
        for row in rows:
            body = {
                "entity_type": row["entity_type"],
                "entity_id": row["entity_id"],
                "event_type": row["event_type"],
                "actor_id": row["actor_id"],
                "payload": json.loads(row["payload_json"]),
                "created_at": row["created_at"],
                "previous_hash": row["previous_hash"],
            }
            if row["previous_hash"] != previous_hash or row["event_hash"] != digest(body):
                valid = False
                break
            previous_hash = row["event_hash"]
        return {"valid": valid, "events": len(rows), "head_hash": previous_hash}
