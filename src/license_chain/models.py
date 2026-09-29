"""许可与流转领域输入契约。

所有凭证都有两个时间维度：

- 业务日期（valid_from / valid_to / occurred_on / qualified_on）：描述许可或事实
  在现实世界中何时生效，用于按历史时点重建授权状态；
- 录入时刻（recorded_at，由服务时钟给出）：描述系统何时知道该事实，
  用于区分按时凭证与补录的迟到凭证。
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date
from typing import Any, Mapping

from .errors import ValidationFailed

IDENTIFIER = re.compile(r"^[A-Za-z0-9一-龥][A-Za-z0-9_.:\-一-龥]{0,63}$")

# 许可类别：销售、医疗使用（放射诊疗）、辐照加工、放射性物品运输（许可制）
LICENSE_KINDS = {"sale", "medical_use", "irradiation", "transport"}
# 交接动作
HANDOVER_KINDS = {"transport", "use", "transfer"}
# 场所资质用途
SITE_PURPOSES = {"medical_use", "irradiation", "storage", "sale"}


def required_text(value: object, field: str, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationFailed(f"{field} 不能为空")
    result = value.strip()
    if len(result) > maximum:
        raise ValidationFailed(f"{field} 不能超过 {maximum} 个字符")
    return result


def identifier(value: object, field: str) -> str:
    result = required_text(value, field, 64)
    if not IDENTIFIER.fullmatch(result):
        raise ValidationFailed(f"{field} 格式不正确")
    return result


def date_text(value: object, field: str) -> str:
    result = required_text(value, field, 10)
    try:
        return date.fromisoformat(result).isoformat()
    except ValueError as exc:
        raise ValidationFailed(f"{field} 必须是 YYYY-MM-DD 日期") from exc


def optional_date(value: object, field: str) -> str | None:
    if value is None or (isinstance(value, str) and not value.strip()):
        return None
    return date_text(value, field)


def scope_code(value: object, field: str) -> str:
    result = required_text(value, field, 48)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.\-]{0,47}", result):
        raise ValidationFailed(f"{field} 必须是由字母数字与 ._- 组成的代码")
    return result


@dataclass(frozen=True, slots=True)
class LicenseDraft:
    """辐射安全许可证批文。"""

    license_id: str
    holder_id: str
    kind: str
    authority: str
    valid_from: str
    valid_to: str | None
    document_no: str

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "LicenseDraft":
        kind = required_text(raw.get("kind"), "kind", 24)
        if kind not in LICENSE_KINDS:
            raise ValidationFailed("kind 必须是 sale、medical_use、irradiation 或 transport")
        valid_from = date_text(raw.get("valid_from"), "valid_from")
        valid_to = optional_date(raw.get("valid_to"), "valid_to")
        if valid_to is not None and valid_to < valid_from:
            raise ValidationFailed("valid_to 不能早于 valid_from")
        return cls(
            license_id=identifier(raw.get("license_id"), "license_id"),
            holder_id=identifier(raw.get("holder_id"), "holder_id"),
            kind=kind,
            authority=required_text(raw.get("authority"), "authority", 128),
            valid_from=valid_from,
            valid_to=valid_to,
            document_no=required_text(raw.get("document_no"), "document_no", 64),
        )


def optional_text(value: object, field: str, maximum: int = 256) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ValidationFailed(f"{field} 必须是文本")
    result = value.strip()
    if len(result) > maximum:
        raise ValidationFailed(f"{field} 不能超过 {maximum} 个字符")
    return result


@dataclass(frozen=True, slots=True)
class ScopeItemDraft:
    """许可范围中的一个条目（许可种类与范围）。"""

    scope_code_value: str
    activity: str
    note: str
    added_on: str | None = None

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "ScopeItemDraft":
        return cls(
            scope_code_value=scope_code(raw.get("scope_code"), "scope_code"),
            activity=required_text(raw.get("activity"), "activity", 128),
            note=optional_text(raw.get("note"), "note"),
            added_on=optional_date(raw.get("added_on"), "added_on"),
        )


@dataclass(frozen=True, slots=True)
class SiteQualificationDraft:
    """场所资质（辐射安全许可/环评批复对应的具体场所）。"""

    site_id: str
    operator_id: str
    purpose: str
    qualified_on: str
    valid_to: str | None
    document_no: str

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "SiteQualificationDraft":
        purpose = required_text(raw.get("purpose"), "purpose", 24)
        if purpose not in SITE_PURPOSES:
            raise ValidationFailed("purpose 必须是 medical_use、irradiation、storage 或 sale")
        qualified_on = date_text(raw.get("qualified_on"), "qualified_on")
        valid_to = optional_date(raw.get("valid_to"), "valid_to")
        if valid_to is not None and valid_to < qualified_on:
            raise ValidationFailed("valid_to 不能早于 qualified_on")
        return cls(
            site_id=identifier(raw.get("site_id"), "site_id"),
            operator_id=identifier(raw.get("operator_id"), "operator_id"),
            purpose=purpose,
            qualified_on=qualified_on,
            valid_to=valid_to,
            document_no=required_text(raw.get("document_no"), "document_no", 64),
        )


@dataclass(frozen=True, slots=True)
class ProductBatchDraft:
    """产品批次（放射性同位素/射线装置，含放射源编码）。"""

    batch_id: str
    product_code: str
    category: str
    owner_id: str
    site_id: str
    produced_on: str

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "ProductBatchDraft":
        produced_on = date_text(raw.get("produced_on"), "produced_on")
        return cls(
            batch_id=identifier(raw.get("batch_id"), "batch_id"),
            product_code=scope_code(raw.get("product_code"), "product_code"),
            category=required_text(raw.get("category"), "category", 32),
            owner_id=identifier(raw.get("owner_id"), "owner_id"),
            site_id=identifier(raw.get("site_id"), "site_id"),
            produced_on=produced_on,
        )


@dataclass(frozen=True, slots=True)
class HandoverDraft:
    """交接单：某批次在某日由某单位经某动作交给接收单位。

    kind=transport 时 actor_id 为承运人，shipper_id 为托运方（必须是当前保管方）；
    kind=use/transfer 时不填 shipper_id，执行单位本身必须是当前保管方。
    """

    handover_id: str
    batch_id: str
    kind: str
    actor_id: str
    receiver_id: str
    site_id: str
    occurred_on: str
    document_no: str
    shipper_id: str | None = None

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "HandoverDraft":
        kind = required_text(raw.get("kind"), "kind", 16)
        if kind not in HANDOVER_KINDS:
            raise ValidationFailed("kind 必须是 transport、use 或 transfer")
        shipper_raw = raw.get("shipper_id")
        shipper_id = None if shipper_raw is None else identifier(shipper_raw, "shipper_id")
        if kind == "transport" and shipper_id is None:
            raise ValidationFailed("运输交接必须提供 shipper_id（托运方）")
        if kind != "transport" and shipper_id is not None:
            raise ValidationFailed("只有运输交接才能填写 shipper_id")
        return cls(
            handover_id=identifier(raw.get("handover_id"), "handover_id"),
            batch_id=identifier(raw.get("batch_id"), "batch_id"),
            kind=kind,
            actor_id=identifier(raw.get("actor_id"), "actor_id"),
            receiver_id=identifier(raw.get("receiver_id"), "receiver_id"),
            site_id=identifier(raw.get("site_id"), "site_id"),
            occurred_on=date_text(raw.get("occurred_on"), "occurred_on"),
            document_no=required_text(raw.get("document_no"), "document_no", 64),
            shipper_id=shipper_id,
        )
