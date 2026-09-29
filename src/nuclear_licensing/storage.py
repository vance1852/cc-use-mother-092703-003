"""许可与流转服务的 SQLite 模式与事务辅助。

所有事实表同时保留两条时间轴：

- 业务时间（valid_from / occurred_at / effective_at）：凭证在现实世界生效或
  交接实际发生的时刻；
- 登记时间（recorded_at）：凭证进入本系统的时刻，补录的迟到凭证可以晚于其
  业务时间，但不会覆盖既有事实。

事实只追加、不原地改写：许可撤销、场所停用各自独立成表，历史行保持不变，
因此既能在当前视角下阻止后续流转，也能按历史登记时点重建当时的判断。
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS nuc_users (
    user_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('registry','dispatcher','compliance','auditor')),
    active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS organizations (
    org_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('medical','irradiation','enterprise','carrier')),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sites (
    site_id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(org_id),
    name TEXT NOT NULL,
    valid_from TEXT NOT NULL,
    valid_to TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sites_org ON sites(org_id);

CREATE TABLE IF NOT EXISTS site_suspensions (
    suspension_id INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id TEXT NOT NULL REFERENCES sites(site_id),
    effective_at TEXT NOT NULL,
    ends_at TEXT,
    reason TEXT NOT NULL,
    recorded_by TEXT NOT NULL REFERENCES nuc_users(user_id),
    recorded_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_site_susp_time ON site_suspensions(site_id, effective_at);

CREATE TABLE IF NOT EXISTS licenses (
    license_id TEXT PRIMARY KEY,
    license_no TEXT NOT NULL UNIQUE,
    holder_org_id TEXT NOT NULL REFERENCES organizations(org_id),
    valid_from TEXT NOT NULL,
    valid_to TEXT NOT NULL,
    document_ref TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES nuc_users(user_id),
    created_at TEXT NOT NULL,
    CHECK(valid_to > valid_from)
);

CREATE INDEX IF NOT EXISTS idx_licenses_holder ON licenses(holder_org_id);

-- 许可范围可随批文增补逐批追加（含补录）；行本身不可变。
CREATE TABLE IF NOT EXISTS license_scopes (
    scope_id INTEGER PRIMARY KEY AUTOINCREMENT,
    license_id TEXT NOT NULL REFERENCES licenses(license_id),
    activity TEXT NOT NULL CHECK(activity IN ('transport','use','transfer')),
    item_code TEXT NOT NULL,
    -- 使用类范围必须落到具体场所；运输/转让类范围留空。
    site_id TEXT REFERENCES sites(site_id),
    document_ref TEXT NOT NULL,
    backfilled INTEGER NOT NULL DEFAULT 0 CHECK(backfilled IN (0,1)),
    recorded_by TEXT NOT NULL REFERENCES nuc_users(user_id),
    recorded_at TEXT NOT NULL,
    CHECK((activity = 'use') = (site_id IS NOT NULL))
);

CREATE INDEX IF NOT EXISTS idx_scopes_lookup
ON license_scopes(license_id, activity, item_code);

-- 撤销是独立事实：业务生效时间可以早于登记时间，但历史交接行不被改写。
CREATE TABLE IF NOT EXISTS license_revocations (
    revocation_id INTEGER PRIMARY KEY AUTOINCREMENT,
    license_id TEXT NOT NULL UNIQUE REFERENCES licenses(license_id),
    effective_at TEXT NOT NULL,
    reason TEXT NOT NULL,
    recorded_by TEXT NOT NULL REFERENCES nuc_users(user_id),
    recorded_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS product_batches (
    batch_id TEXT PRIMARY KEY,
    item_code TEXT NOT NULL,
    product_name TEXT NOT NULL,
    nuclide TEXT NOT NULL,
    origin_org_id TEXT NOT NULL REFERENCES organizations(org_id),
    produced_at TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES nuc_users(user_id),
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_batches_item ON product_batches(item_code);

-- 交接事实（交接单）。occurred_at 为实际交接时刻，recorded_at 为登记时刻，
-- 迟到的交接单两者可以相差很远。
CREATE TABLE IF NOT EXISTS custody_handoffs (
    handoff_id TEXT PRIMARY KEY,
    batch_id TEXT NOT NULL REFERENCES product_batches(batch_id),
    from_org_id TEXT NOT NULL REFERENCES organizations(org_id),
    to_org_id TEXT NOT NULL REFERENCES organizations(org_id),
    carrier_org_id TEXT NOT NULL REFERENCES organizations(org_id),
    -- 接收方落地使用场所；仅仓储中转时为空。
    site_id TEXT REFERENCES sites(site_id),
    activity TEXT NOT NULL CHECK(activity IN ('transfer','transport_only')),
    occurred_at TEXT NOT NULL,
    evidence_doc TEXT NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE,
    recorded_by TEXT NOT NULL REFERENCES nuc_users(user_id),
    recorded_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_handoffs_batch_time
ON custody_handoffs(batch_id, occurred_at, handoff_id);

-- 合规审查结案时冻结当时的知识截止时刻与完整结论；之后补录的凭证只作为
-- 迟到事实提示，不回写冻结结论。
CREATE TABLE IF NOT EXISTS compliance_reviews (
    review_id TEXT PRIMARY KEY,
    batch_id TEXT NOT NULL REFERENCES product_batches(batch_id),
    as_of TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'open' CHECK(state IN ('open','closed','reopened')),
    opened_by TEXT NOT NULL REFERENCES nuc_users(user_id),
    opened_at TEXT NOT NULL,
    closed_by TEXT REFERENCES nuc_users(user_id),
    closed_at TEXT,
    knowledge_cutoff TEXT,
    result_json TEXT,
    conclusion TEXT
);

CREATE TABLE IF NOT EXISTS nuc_idempotency (
    scope TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_sha256 TEXT NOT NULL,
    response_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY(scope, idempotency_key)
);

CREATE TABLE IF NOT EXISTS nuc_audit_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_nuc_audit_entity
ON nuc_audit_events(entity_type, entity_id, event_id);
"""


def connect(path: str | Path) -> sqlite3.Connection:
    # ThreadingHTTPServer 会在工作线程中复用同一连接；写事务已由
    # BEGIN IMMEDIATE 与 busy_timeout 串行化，因此放宽同线程限制。
    connection = sqlite3.connect(str(path), isolation_level=None, timeout=10, check_same_thread=False)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA busy_timeout=5000")
    initialize(connection)
    return connection


def initialize(connection: sqlite3.Connection) -> None:
    connection.executescript(SCHEMA)


@contextmanager
def transaction(connection: sqlite3.Connection, *, immediate: bool = False) -> Iterator[None]:
    connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
    try:
        yield
    except BaseException:
        connection.rollback()
        raise
    else:
        connection.commit()
