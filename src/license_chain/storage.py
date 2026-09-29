"""许可与流转服务的 SQLite 模式和事务辅助。

时间字段约定：
- *_on 为 YYYY-MM-DD 业务日期；
- *_at 为 UTC ISO 8601 录入时刻（record time）；
- 撤销记录 revoke_effective_on 表示撤销在现实中的生效日，
  不删除原凭证行，因此撤销前已完成的交接保持可追溯。
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS chain_users (
    user_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('licensor','operator','compliance','auditor')),
    active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS licenses (
    license_id TEXT PRIMARY KEY,
    holder_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('sale','medical_use','irradiation','transport')),
    authority TEXT NOT NULL,
    document_no TEXT NOT NULL,
    valid_from TEXT NOT NULL,
    valid_to TEXT,
    state TEXT NOT NULL DEFAULT 'active' CHECK(state IN ('active','revoked')),
    revoke_effective_on TEXT,
    revoke_reason TEXT,
    revoked_by TEXT REFERENCES chain_users(user_id),
    revoked_at TEXT,
    revision INTEGER NOT NULL DEFAULT 1,
    created_by TEXT NOT NULL REFERENCES chain_users(user_id),
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_licenses_holder_kind
ON licenses(holder_id, kind, valid_from);

CREATE TABLE IF NOT EXISTS license_scopes (
    scope_id INTEGER PRIMARY KEY AUTOINCREMENT,
    license_id TEXT NOT NULL REFERENCES licenses(license_id),
    scope_code TEXT NOT NULL,
    activity TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    added_on TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(license_id, scope_code)
);

CREATE TABLE IF NOT EXISTS site_qualifications (
    site_id TEXT PRIMARY KEY,
    operator_id TEXT NOT NULL,
    name TEXT NOT NULL,
    purpose TEXT NOT NULL CHECK(purpose IN ('medical_use','irradiation','storage','sale')),
    document_no TEXT NOT NULL,
    qualified_on TEXT NOT NULL,
    valid_to TEXT,
    state TEXT NOT NULL DEFAULT 'active' CHECK(state IN ('active','revoked')),
    revoke_effective_on TEXT,
    revoke_reason TEXT,
    revoked_by TEXT REFERENCES chain_users(user_id),
    revoked_at TEXT,
    revision INTEGER NOT NULL DEFAULT 1,
    created_by TEXT NOT NULL REFERENCES chain_users(user_id),
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sites_operator_purpose
ON site_qualifications(operator_id, purpose, qualified_on);

CREATE TABLE IF NOT EXISTS product_batches (
    batch_id TEXT PRIMARY KEY,
    product_code TEXT NOT NULL,
    category TEXT NOT NULL,
    owner_id TEXT NOT NULL,
    site_id TEXT NOT NULL REFERENCES site_qualifications(site_id),
    produced_on TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES chain_users(user_id),
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_batches_product
ON product_batches(product_code, owner_id);

CREATE TABLE IF NOT EXISTS handovers (
    handover_id TEXT PRIMARY KEY,
    batch_id TEXT NOT NULL REFERENCES product_batches(batch_id),
    kind TEXT NOT NULL CHECK(kind IN ('transport','use','transfer')),
    actor_id TEXT NOT NULL,
    shipper_id TEXT,
    receiver_id TEXT NOT NULL,
    site_id TEXT NOT NULL REFERENCES site_qualifications(site_id),
    occurred_on TEXT NOT NULL,
    document_no TEXT NOT NULL,
    decision TEXT NOT NULL CHECK(decision IN ('recorded','rejected')),
    assessment_json TEXT NOT NULL,
    late_entry INTEGER NOT NULL DEFAULT 0 CHECK(late_entry IN (0,1)),
    supersedes_handover_id TEXT REFERENCES handovers(handover_id),
    created_by TEXT NOT NULL REFERENCES chain_users(user_id),
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_handovers_batch_date
ON handovers(batch_id, occurred_on, handover_id);

CREATE TABLE IF NOT EXISTS handover_authorizations (
    handover_id TEXT NOT NULL REFERENCES handovers(handover_id),
    basis_type TEXT NOT NULL CHECK(basis_type IN ('license','site')),
    ref_id TEXT NOT NULL,
    PRIMARY KEY(handover_id, basis_type, ref_id)
);

CREATE INDEX IF NOT EXISTS idx_handover_auth_basis
ON handover_authorizations(basis_type, ref_id);

CREATE TABLE IF NOT EXISTS compliance_reviews (
    review_id TEXT PRIMARY KEY,
    batch_id TEXT NOT NULL REFERENCES product_batches(batch_id),
    as_of_on TEXT NOT NULL,
    conclusion TEXT NOT NULL CHECK(conclusion IN ('compliant','non_compliant')),
    evidence_snapshot_json TEXT NOT NULL,
    evidence_sha256 TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'open' CHECK(state IN ('open','closed')),
    finding_json TEXT NOT NULL,
    closed_at TEXT,
    closed_by TEXT REFERENCES chain_users(user_id),
    created_by TEXT NOT NULL REFERENCES chain_users(user_id),
    created_at TEXT NOT NULL,
    UNIQUE(batch_id, as_of_on)
);

CREATE TABLE IF NOT EXISTS review_evidence_changes (
    change_id INTEGER PRIMARY KEY AUTOINCREMENT,
    review_id TEXT NOT NULL REFERENCES compliance_reviews(review_id),
    handover_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    occurred_on TEXT NOT NULL,
    late_entry INTEGER NOT NULL CHECK(late_entry IN (0,1)),
    noted_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_review_changes_review
ON review_evidence_changes(review_id, change_id);

CREATE TABLE IF NOT EXISTS chain_audit_events (
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

CREATE INDEX IF NOT EXISTS idx_chain_audit_entity
ON chain_audit_events(entity_type, entity_id, event_id);
"""


def connect(path: str | Path) -> sqlite3.Connection:
    connection = sqlite3.connect(
        str(path), isolation_level=None, timeout=10, check_same_thread=False
    )
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
