"""许可登记、批次流转与合规审查的事务用例。"""

from __future__ import annotations

import json
import sqlite3
from typing import Any, Mapping

from . import chain as chain_mod
from .clock import SystemClock, parse_utc, utc_text
from .encoding import canonical_json, digest
from .errors import (
    AuthorizationBlocked,
    Conflict,
    Forbidden,
    InvalidState,
    NotFound,
    ValidationFailed,
)
from .storage import initialize, transaction


ROLE_PERMISSIONS = {
    "registry": {"registry.write"},
    "dispatcher": {"handoff.write"},
    "compliance": {"review.write", "report.read"},
    "auditor": {"report.read", "audit.read"},
}

_ACTIVITIES = {"transport", "use", "transfer"}


class LicensingService:
    def __init__(self, connection: sqlite3.Connection, clock=None) -> None:
        self.connection = connection
        self.clock = clock or SystemClock()
        initialize(connection)

    def _now(self) -> str:
        return utc_text(self.clock.now())

    # ------------------------------------------------------------------ 用户/权限

    def create_user(self, user_id: str, display_name: str, role: str) -> dict[str, Any]:
        if role not in ROLE_PERMISSIONS:
            raise ValidationFailed("未知角色")
        if not user_id.strip() or not display_name.strip():
            raise ValidationFailed("用户编号和名称不能为空")
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO nuc_users(user_id,display_name,role,created_at) VALUES(?,?,?,?)",
                    (user_id.strip(), display_name.strip(), role, self._now()),
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict("用户已经存在") from exc
        return {"user_id": user_id.strip(), "role": role}

    def _user(self, user_id: str) -> sqlite3.Row:
        row = self.connection.execute("SELECT * FROM nuc_users WHERE user_id=?", (user_id,)).fetchone()
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

    def _require_report(self, user_id: str) -> sqlite3.Row:
        user = self._user(user_id)
        if "report.read" not in ROLE_PERMISSIONS[user["role"]]:
            raise Forbidden(f"角色 {user['role']} 无权查询授权链")
        return user

    # ------------------------------------------------------------------ 审计链

    def _audit(
        self,
        entity_type: str,
        entity_id: str,
        event_type: str,
        actor_id: str,
        payload: Mapping[str, Any],
    ) -> None:
        previous = self.connection.execute(
            "SELECT event_hash FROM nuc_audit_events ORDER BY event_id DESC LIMIT 1"
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
            "INSERT INTO nuc_audit_events(entity_type,entity_id,event_type,actor_id,payload_json,"
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

    def audit_chain(self, actor_id: str) -> dict[str, Any]:
        self._require(actor_id, "audit.read")
        rows = self.connection.execute("SELECT * FROM nuc_audit_events ORDER BY event_id").fetchall()
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

    # ------------------------------------------------------------------ 基础登记

    def register_org(self, actor_id: str, raw: Mapping[str, Any]) -> dict[str, Any]:
        self._require(actor_id, "registry.write")
        org_id = str(raw.get("org_id", "")).strip()
        name = str(raw.get("name", "")).strip()
        kind = str(raw.get("kind", "")).strip()
        if not org_id or not name:
            raise ValidationFailed("单位编号和名称不能为空")
        if kind not in {"medical", "irradiation", "enterprise", "carrier"}:
            raise ValidationFailed("单位类型必须是 medical/irradiation/enterprise/carrier")
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO organizations(org_id,name,kind,created_at) VALUES(?,?,?,?)",
                    (org_id, name, kind, self._now()),
                )
                self._audit("organization", org_id, "org.registered", actor_id, dict(raw))
        except sqlite3.IntegrityError as exc:
            raise Conflict("单位编号已经存在") from exc
        return {"org_id": org_id, "name": name, "kind": kind}

    def register_site(
        self,
        actor_id: str,
        site_id: str,
        org_id: str,
        name: str,
        valid_from: str,
        valid_to: str | None = None,
    ) -> dict[str, Any]:
        self._require(actor_id, "registry.write")
        start = self._time(valid_from, "valid_from")
        end = None if valid_to is None else self._time(valid_to, "valid_to")
        if end is not None and end <= start:
            raise ValidationFailed("valid_to 必须晚于 valid_from")
        self._org(org_id)
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO sites(site_id,org_id,name,valid_from,valid_to,created_at) VALUES(?,?,?,?,?,?)",
                    (site_id, org_id, name, utc_text(start), None if end is None else utc_text(end), self._now()),
                )
                self._audit("site", site_id, "site.registered", actor_id, {"org_id": org_id, "name": name})
        except sqlite3.IntegrityError as exc:
            raise Conflict("场所编号已经存在") from exc
        return self.site(site_id)

    def suspend_site(
        self,
        actor_id: str,
        site_id: str,
        effective_at: str,
        reason: str,
        ends_at: str | None = None,
    ) -> dict[str, Any]:
        self._require(actor_id, "registry.write")
        self.site(site_id)
        start = self._time(effective_at, "effective_at")
        end = None if ends_at is None else self._time(ends_at, "ends_at")
        if end is not None and end <= start:
            raise ValidationFailed("ends_at 必须晚于 effective_at")
        if not reason.strip():
            raise ValidationFailed("停用原因不能为空")
        with transaction(self.connection, immediate=True):
            cursor = self.connection.execute(
                "INSERT INTO site_suspensions(site_id,effective_at,ends_at,reason,recorded_by,recorded_at) "
                "VALUES(?,?,?,?,?,?)",
                (site_id, utc_text(start), None if end is None else utc_text(end), reason.strip(), actor_id, self._now()),
            )
            suspension_id = int(cursor.lastrowid)
            self._audit("site", site_id, "site.suspended", actor_id, {"suspension_id": suspension_id, "reason": reason})
        return {"suspension_id": suspension_id, "site_id": site_id, "effective_at": utc_text(start)}

    def site(self, site_id: str) -> dict[str, Any]:
        row = self.connection.execute("SELECT * FROM sites WHERE site_id=?", (site_id,)).fetchone()
        if row is None:
            raise NotFound("场所不存在")
        return dict(row)

    def _org(self, org_id: str) -> sqlite3.Row:
        row = self.connection.execute("SELECT * FROM organizations WHERE org_id=?", (org_id,)).fetchone()
        if row is None:
            raise NotFound(f"单位 {org_id} 不存在")
        return row

    @staticmethod
    def _time(value: str, field: str) -> object:
        try:
            return parse_utc(value, field)
        except ValueError as exc:
            raise ValidationFailed(str(exc)) from exc

    # ------------------------------------------------------------------ 许可

    def record_license(self, actor_id: str, raw: Mapping[str, Any]) -> dict[str, Any]:
        self._require(actor_id, "registry.write")
        license_id = str(raw.get("license_id", "")).strip()
        license_no = str(raw.get("license_no", "")).strip()
        holder = str(raw.get("holder_org_id", "")).strip()
        document_ref = str(raw.get("document_ref", "")).strip()
        if not license_id or not license_no or not document_ref:
            raise ValidationFailed("license_id、license_no、document_ref 不能为空")
        start = self._time(str(raw.get("valid_from", "")), "valid_from")
        end = self._time(str(raw.get("valid_to", "")), "valid_to")
        if end <= start:
            raise ValidationFailed("valid_to 必须晚于 valid_from")
        self._org(holder)
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO licenses(license_id,license_no,holder_org_id,valid_from,valid_to,"
                    "document_ref,created_by,created_at) VALUES(?,?,?,?,?,?,?,?)",
                    (
                        license_id,
                        license_no,
                        holder,
                        utc_text(start),
                        utc_text(end),
                        document_ref,
                        actor_id,
                        self._now(),
                    ),
                )
                self._audit("license", license_id, "license.recorded", actor_id, dict(raw))
        except sqlite3.IntegrityError as exc:
            raise Conflict("许可编号或批文号已经存在") from exc
        return self.license(license_id)

    def add_license_scope(
        self,
        actor_id: str,
        license_id: str,
        activity: str,
        item_code: str,
        document_ref: str,
        site_id: str | None = None,
        backfilled: bool = False,
    ) -> dict[str, Any]:
        self._require(actor_id, "registry.write")
        license_row = self._license(license_id)
        if activity not in _ACTIVITIES:
            raise ValidationFailed("活动类型必须是 transport/use/transfer")
        if not item_code.strip() or not document_ref.strip():
            raise ValidationFailed("产品编码和凭证文号不能为空")
        if activity == "use":
            if not site_id:
                raise ValidationFailed("使用类许可范围必须指定场所")
            site = self.site(site_id)
            if site["org_id"] != license_row["holder_org_id"]:
                raise ValidationFailed("使用场所不属于许可持有人")
        elif site_id:
            raise ValidationFailed("运输/转让类许可范围不能绑定场所")
        recorded_at = self._now()
        with transaction(self.connection, immediate=True):
            cursor = self.connection.execute(
                "INSERT INTO license_scopes(license_id,activity,item_code,site_id,document_ref,backfilled,"
                "recorded_by,recorded_at) VALUES(?,?,?,?,?,?,?,?)",
                (license_id, activity, item_code.strip(), site_id, document_ref.strip(), 1 if backfilled else 0,
                 actor_id, recorded_at),
            )
            scope_id = int(cursor.lastrowid)
            self._audit(
                "license",
                license_id,
                "scope.added" + (".backfilled" if backfilled else ""),
                actor_id,
                {"scope_id": scope_id, "activity": activity, "item_code": item_code, "site_id": site_id},
            )
        return {"scope_id": scope_id, "license_id": license_id, "activity": activity, "item_code": item_code,
                "site_id": site_id, "backfilled": bool(backfilled), "recorded_at": recorded_at}

    def revoke_license(self, actor_id: str, license_id: str, effective_at: str, reason: str) -> dict[str, Any]:
        self._require(actor_id, "registry.write")
        self._license(license_id)
        if not reason.strip():
            raise ValidationFailed("撤销原因不能为空")
        effective = self._time(effective_at, "effective_at")
        recorded_at = self._now()
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO license_revocations(license_id,effective_at,reason,recorded_by,recorded_at) "
                    "VALUES(?,?,?,?,?)",
                    (license_id, utc_text(effective), reason.strip(), actor_id, recorded_at),
                )
                self._audit(
                    "license",
                    license_id,
                    "license.revoked",
                    actor_id,
                    {"effective_at": utc_text(effective), "reason": reason.strip()},
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict("该许可已被撤销") from exc
        return {"license_id": license_id, "effective_at": utc_text(effective), "recorded_at": recorded_at}

    def _license(self, license_id: str) -> sqlite3.Row:
        row = self.connection.execute("SELECT * FROM licenses WHERE license_id=?", (license_id,)).fetchone()
        if row is None:
            raise NotFound("许可不存在")
        return row

    def license(self, license_id: str) -> dict[str, Any]:
        row = self._license(license_id)
        result = dict(row)
        revocation = self.connection.execute(
            "SELECT * FROM license_revocations WHERE license_id=?", (license_id,)
        ).fetchone()
        result["revocation"] = None if revocation is None else dict(revocation)
        result["scopes"] = [
            dict(item) for item in self.connection.execute(
                "SELECT * FROM license_scopes WHERE license_id=? ORDER BY scope_id", (license_id,)
            ).fetchall()
        ]
        return result

    # ------------------------------------------------------------------ 批次与交接

    def register_batch(self, actor_id: str, raw: Mapping[str, Any]) -> dict[str, Any]:
        self._require(actor_id, "registry.write")
        batch_id = str(raw.get("batch_id", "")).strip()
        required = ("item_code", "product_name", "nuclide")
        values = {key: str(raw.get(key, "")).strip() for key in required}
        origin = str(raw.get("origin_org_id", "")).strip()
        if not batch_id or not origin or not all(values.values()):
            raise ValidationFailed("批次编号、产品信息和起源单位不能为空")
        produced_at = self._time(str(raw.get("produced_at", "")), "produced_at")
        self._org(origin)
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO product_batches(batch_id,item_code,product_name,nuclide,origin_org_id,"
                    "produced_at,created_by,created_at) VALUES(?,?,?,?,?,?,?,?)",
                    (batch_id, values["item_code"], values["product_name"], values["nuclide"], origin,
                     utc_text(produced_at), actor_id, self._now()),
                )
                self._audit("batch", batch_id, "batch.registered", actor_id, dict(raw))
        except sqlite3.IntegrityError as exc:
            raise Conflict("批次编号已经存在") from exc
        return self.batch(batch_id)

    def batch(self, batch_id: str) -> dict[str, Any]:
        row = self.connection.execute("SELECT * FROM product_batches WHERE batch_id=?", (batch_id,)).fetchone()
        if row is None:
            raise NotFound("产品批次不存在")
        return dict(row)

    def record_handoff(self, actor_id: str, raw: Mapping[str, Any]) -> dict[str, Any]:
        self._require(actor_id, "handoff.write")
        handoff_id = str(raw.get("handoff_id", "")).strip()
        batch_id = str(raw.get("batch_id", "")).strip()
        from_org = str(raw.get("from_org_id", "")).strip()
        to_org = str(raw.get("to_org_id", "")).strip()
        carrier = str(raw.get("carrier_org_id", "")).strip()
        site_id = raw.get("site_id") or None
        evidence = str(raw.get("evidence_doc", "")).strip()
        idem_key = str(raw.get("idempotency_key", "")).strip()
        if not all((handoff_id, batch_id, from_org, to_org, carrier, evidence, idem_key)):
            raise ValidationFailed("交接单字段不完整")
        if from_org == to_org:
            raise ValidationFailed("交出方与接收方不能相同")
        occurred = self._time(str(raw.get("occurred_at", "")), "occurred_at")
        self.batch(batch_id)
        for org_id in (from_org, to_org, carrier):
            self._org(org_id)
        if site_id is not None:
            site = self.site(str(site_id))
            if site["org_id"] != to_org:
                raise ValidationFailed("落地场所不属于接收单位")
        occurred_text = utc_text(occurred)

        request_digest = digest(raw)
        stored = self.connection.execute(
            "SELECT request_sha256,response_json FROM nuc_idempotency WHERE scope='handoff' AND idempotency_key=?",
            (idem_key,),
        ).fetchone()
        if stored is not None:
            if stored["request_sha256"] != request_digest:
                raise Conflict("幂等键对应不同交接单内容")
            return json.loads(stored["response_json"])

        recorded_at = self._now()
        with transaction(self.connection, immediate=True):
            # 用“当前已知事实”在交接发生时点验证授权链：硬阻断（撤销、停用、
            # 链断裂）拒绝登记；缺失凭证允许登记，由审计指出缺口。
            current_chain = chain_mod.build_chain(self.connection, batch_id, occurred_text, recorded_at)
            expected_holder = current_chain["holder_org_id"]
            if expected_holder != from_org:
                raise AuthorizationBlocked(
                    f"交接发起方 {from_org} 不是链上当前持有人 {expected_holder}",
                    {"expected_holder": expected_holder},
                )
            findings = self._simulate_findings(
                batch_id, from_org, to_org, carrier, site_id, occurred_text, recorded_at
            )
            blocked = [item for item in findings if item["status"] == "blocked"]
            if blocked:
                raise AuthorizationBlocked("授权链存在硬性阻断，交接不得登记", {"findings": blocked})
            status = "incomplete" if any(item["status"] == "missing" for item in findings) else "authorized"

            self.connection.execute(
                "INSERT INTO custody_handoffs(handoff_id,batch_id,from_org_id,to_org_id,carrier_org_id,site_id,"
                "activity,occurred_at,evidence_doc,idempotency_key,recorded_by,recorded_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (handoff_id, batch_id, from_org, to_org, carrier, site_id, "transfer", occurred_text, evidence,
                 idem_key, actor_id, recorded_at),
            )
            self.connection.execute(
                "INSERT INTO nuc_idempotency(scope,idempotency_key,request_sha256,response_json,created_at) "
                "VALUES('handoff',?,?,?,?)",
                (idem_key, request_digest,
                 canonical_json({"handoff_id": handoff_id, "status": status}), recorded_at),
            )
            self._audit(
                "handoff",
                handoff_id,
                "handoff.recorded" + (".late_evidence" if recorded_at > occurred_text else ""),
                actor_id,
                {"batch_id": batch_id, "from_org_id": from_org, "to_org_id": to_org,
                 "occurred_at": occurred_text, "status": status},
            )
        return {
            "handoff_id": handoff_id,
            "batch_id": batch_id,
            "occurred_at": occurred_text,
            "recorded_at": recorded_at,
            "late_evidence": recorded_at > occurred_text,
            "status": status,
            "findings": findings,
        }

    def _simulate_findings(
        self,
        batch_id: str,
        from_org: str,
        to_org: str,
        carrier: str,
        site_id: str | None,
        at: str,
        cutoff: str,
    ) -> list[dict[str, Any]]:
        batch = self.batch(batch_id)
        findings = chain_mod.authorize_party(self.connection, from_org, "transfer", batch["item_code"], at, cutoff)
        findings += chain_mod.authorize_party(self.connection, carrier, "transport", batch["item_code"], at, cutoff)
        findings += chain_mod.authorize_party(self.connection, to_org, "transfer", batch["item_code"], at, cutoff)
        if site_id is not None:
            findings += chain_mod.authorize_party(
                self.connection, to_org, "use", batch["item_code"], at, cutoff, site_id
            )
        return findings

    # ------------------------------------------------------------------ 查询

    def chain(self, actor_id: str, batch_id: str, as_of: str | None = None,
              knowledge_cutoff: str | None = None) -> dict[str, Any]:
        self._require_report(actor_id)
        self.batch(batch_id)
        if as_of is not None:
            as_of = utc_text(self._time(as_of, "as_of"))
        if knowledge_cutoff is not None:
            knowledge_cutoff = utc_text(self._time(knowledge_cutoff, "knowledge_cutoff"))
        return chain_mod.build_chain(self.connection, batch_id, as_of, knowledge_cutoff)

    def authorize(
        self,
        actor_id: str,
        batch_id: str,
        org_id: str,
        activity: str,
        as_of: str,
        site_id: str | None = None,
        knowledge_cutoff: str | None = None,
    ) -> dict[str, Any]:
        self._require_report(actor_id)
        if activity not in _ACTIVITIES:
            raise ValidationFailed("活动类型必须是 transport/use/transfer")
        if activity == "use" and not site_id:
            raise ValidationFailed("使用类授权查询必须指定 site_id")
        self.batch(batch_id)
        self._org(org_id)
        as_of_text = utc_text(self._time(as_of, "as_of"))
        cutoff_text = None
        if knowledge_cutoff is not None:
            cutoff_text = utc_text(self._time(knowledge_cutoff, "knowledge_cutoff"))
        return chain_mod.can_authorize(
            self.connection, batch_id, org_id, activity, as_of_text, cutoff_text, site_id
        )

    # ------------------------------------------------------------------ 合规审查

    def open_review(self, actor_id: str, review_id: str, batch_id: str, as_of: str) -> dict[str, Any]:
        self._require(actor_id, "review.write")
        self.batch(batch_id)
        as_of_text = utc_text(self._time(as_of, "as_of"))
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO compliance_reviews(review_id,batch_id,as_of,state,opened_by,opened_at) "
                    "VALUES(?,?,?,?,?,?)",
                    (review_id, batch_id, as_of_text, "open", actor_id, self._now()),
                )
                self._audit("review", review_id, "review.opened", actor_id,
                            {"batch_id": batch_id, "as_of": as_of_text})
        except sqlite3.IntegrityError as exc:
            raise Conflict("审查编号已经存在") from exc
        return {"review_id": review_id, "state": "open", "as_of": as_of_text}

    def close_review(self, actor_id: str, review_id: str) -> dict[str, Any]:
        self._require(actor_id, "review.write")
        review = self._review(review_id)
        if review["state"] == "closed":
            raise InvalidState("审查已经结案，不能重复结案（如需采用新证据请先重开）")
        cutoff = self._now()
        result = chain_mod.build_chain(self.connection, review["batch_id"], review["as_of"], cutoff)
        conclusion = {
            "authorized": "授权链完整",
            "incomplete": "授权链存在缺失环节",
            "blocked": "授权链被撤销/停用等事实硬性阻断",
        }[result["status"]]
        with transaction(self.connection, immediate=True):
            self.connection.execute(
                "UPDATE compliance_reviews SET state='closed',closed_by=?,closed_at=?,"
                "knowledge_cutoff=?,result_json=?,conclusion=? WHERE review_id=?",
                (actor_id, cutoff, cutoff, canonical_json(result), conclusion, review_id),
            )
            self._audit("review", review_id, "review.closed", actor_id,
                        {"knowledge_cutoff": cutoff, "status": result["status"]})
        return self.get_review(actor_id, review_id)

    def reopen_review(self, actor_id: str, review_id: str) -> dict[str, Any]:
        self._require(actor_id, "review.write")
        review = self._review(review_id)
        if review["state"] != "closed":
            raise InvalidState("只有已结案审查可以重开")
        with transaction(self.connection, immediate=True):
            self.connection.execute(
                "UPDATE compliance_reviews SET state='reopened' WHERE review_id=?", (review_id,)
            )
            self._audit("review", review_id, "review.reopened", actor_id, {})
        return {"review_id": review_id, "state": "reopened"}

    def _review(self, review_id: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM compliance_reviews WHERE review_id=?", (review_id,)
        ).fetchone()
        if row is None:
            raise NotFound("合规审查不存在")
        return row

    def get_review(self, actor_id: str, review_id: str) -> dict[str, Any]:
        self._require_report(actor_id)
        review = self._review(review_id)
        response: dict[str, Any] = {
            "review_id": review_id,
            "batch_id": review["batch_id"],
            "as_of": review["as_of"],
            "state": review["state"],
            "conclusion": review["conclusion"],
            "knowledge_cutoff": review["knowledge_cutoff"],
        }
        if review["result_json"] is not None:
            frozen = json.loads(review["result_json"])
            response["frozen_result"] = frozen
            response["late_evidence"] = self._late_evidence(
                review["batch_id"], review["as_of"], review["knowledge_cutoff"]
            )
            # 当前视角仅作对照展示；冻结结论本身不被改写。
            response["current_view"] = chain_mod.build_chain(
                self.connection, review["batch_id"], review["as_of"], self._now()
            )
        else:
            response["frozen_result"] = None
            response["late_evidence"] = []
            response["current_view"] = chain_mod.build_chain(
                self.connection, review["batch_id"], review["as_of"], self._now()
            )
        return response

    def _late_evidence(self, batch_id: str, as_of: str, cutoff: str) -> list[dict[str, Any]]:
        """列出结案截止时点之后补录、且与该批次相关的凭证。"""
        batch = self.batch(batch_id)
        org_rows = self.connection.execute(
            "SELECT DISTINCT org_id FROM ("
            "SELECT origin_org_id AS org_id FROM product_batches WHERE batch_id=? "
            "UNION SELECT from_org_id FROM custody_handoffs WHERE batch_id=? "
            "UNION SELECT to_org_id FROM custody_handoffs WHERE batch_id=? "
            "UNION SELECT carrier_org_id FROM custody_handoffs WHERE batch_id=?)",
            (batch_id, batch_id, batch_id, batch_id),
        ).fetchall()
        org_ids = [row["org_id"] for row in org_rows]
        late: list[dict[str, Any]] = []

        if org_ids:
            placeholders = ",".join("?" for _ in org_ids)
            scope_rows = self.connection.execute(
                f"SELECT s.scope_id,s.license_id,s.activity,s.item_code,s.site_id,s.recorded_at,s.backfilled,"
                f"l.holder_org_id FROM license_scopes s JOIN licenses l ON l.license_id=s.license_id "
                f"WHERE s.recorded_at>? AND s.item_code=? AND l.holder_org_id IN ({placeholders})",
                (cutoff, batch["item_code"], *org_ids),
            ).fetchall()
            for row in scope_rows:
                late.append({
                    "kind": "license_scope" + (".backfilled" if row["backfilled"] else ""),
                    "scope_id": row["scope_id"],
                    "license_id": row["license_id"],
                    "holder_org_id": row["holder_org_id"],
                    "activity": row["activity"],
                    "item_code": row["item_code"],
                    "site_id": row["site_id"],
                    "recorded_at": row["recorded_at"],
                })
            revocation_rows = self.connection.execute(
                f"SELECT r.license_id,r.effective_at,r.recorded_at,l.holder_org_id "
                f"FROM license_revocations r JOIN licenses l ON l.license_id=r.license_id "
                f"WHERE r.recorded_at>? AND l.holder_org_id IN ({placeholders})",
                (cutoff, *org_ids),
            ).fetchall()
            for row in revocation_rows:
                late.append({
                    "kind": "license.revoked",
                    "license_id": row["license_id"],
                    "holder_org_id": row["holder_org_id"],
                    "effective_at": row["effective_at"],
                    "recorded_at": row["recorded_at"],
                })

        handoff_rows = self.connection.execute(
            "SELECT handoff_id,occurred_at,recorded_at,from_org_id,to_org_id FROM custody_handoffs "
            "WHERE batch_id=? AND recorded_at>?",
            (batch_id, cutoff),
        ).fetchall()
        for row in handoff_rows:
            late.append({
                "kind": "handoff" + (".backfilled" if row["recorded_at"] > row["occurred_at"] else ""),
                "handoff_id": row["handoff_id"],
                "occurred_at": row["occurred_at"],
                "recorded_at": row["recorded_at"],
                "from_org_id": row["from_org_id"],
                "to_org_id": row["to_org_id"],
            })

        site_rows = self.connection.execute(
            "SELECT x.suspension_id,x.site_id,x.effective_at,x.recorded_at FROM site_suspensions x "
            "JOIN sites s ON s.site_id=x.site_id WHERE x.recorded_at>? AND s.org_id IN ("
            + ",".join("?" for _ in org_ids) + ")",
            (cutoff, *org_ids),
        ).fetchall() if org_ids else []
        for row in site_rows:
            late.append({
                "kind": "site.suspended",
                "suspension_id": row["suspension_id"],
                "site_id": row["site_id"],
                "effective_at": row["effective_at"],
                "recorded_at": row["recorded_at"],
            })
        late.sort(key=lambda item: (item["recorded_at"], item["kind"]))
        return late
