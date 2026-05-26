"""SQLite schema + thin DAO layer.

Four tables match §3 of the protocol spec:

  * ``operators``           — registered operator identities
  * ``submissions``         — signed export bodies (one row per submit)
  * ``cross_anchors``       — periodic cross-anchor records
  * ``anchor_participants`` — N-to-N: which operator's chain head went
    into which cross-anchor

All writes wrap ``BEGIN IMMEDIATE`` for multi-writer safety, same
discipline as ``bijotel`` itself.
"""

from __future__ import annotations

import json
import sqlite3
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS operators (
    operator_id        TEXT PRIMARY KEY,
    org_name           TEXT NOT NULL,
    public_key_pem     TEXT NOT NULL,
    contact_email      TEXT NOT NULL DEFAULT '',
    registered_at      TEXT NOT NULL,
    rekor_log_index    INTEGER,
    last_submission_at TEXT
);

CREATE TABLE IF NOT EXISTS submissions (
    submission_id        TEXT PRIMARY KEY,
    operator_id          TEXT NOT NULL REFERENCES operators(operator_id),
    signed_export_json   TEXT NOT NULL,
    entry_count          INTEGER NOT NULL,
    first_seq            INTEGER NOT NULL,
    last_seq             INTEGER NOT NULL,
    chain_head_signature TEXT NOT NULL,
    continuity_verified  INTEGER NOT NULL DEFAULT 0,
    submitted_at         TEXT NOT NULL,
    cross_anchor_id      TEXT
);
CREATE INDEX IF NOT EXISTS idx_submissions_operator
    ON submissions(operator_id, submitted_at);
CREATE INDEX IF NOT EXISTS idx_submissions_pending
    ON submissions(cross_anchor_id) WHERE cross_anchor_id IS NULL;

CREATE TABLE IF NOT EXISTS cross_anchors (
    anchor_id            TEXT PRIMARY KEY,
    cross_anchor_hash    TEXT NOT NULL,
    anchored_at          TEXT NOT NULL,
    rekor_log_index      INTEGER,
    rekor_url            TEXT,
    federation_signature TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS anchor_participants (
    anchor_id       TEXT NOT NULL REFERENCES cross_anchors(anchor_id),
    operator_id     TEXT NOT NULL REFERENCES operators(operator_id),
    chain_signature TEXT NOT NULL,
    PRIMARY KEY (anchor_id, operator_id)
);
"""


def init_db(db_path: str) -> None:
    """Create the schema if it doesn't exist."""
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        conn.executescript(SCHEMA)


@contextmanager
def get_conn(db_path: str) -> Iterator[sqlite3.Connection]:
    """Yield a SQLite connection with WAL + row factory set."""
    conn = sqlite3.connect(db_path, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
    finally:
        conn.close()


# ---------------------------------------------------------------------
# Operators
# ---------------------------------------------------------------------


def operator_create(
    db_path: str,
    *,
    operator_id: str,
    org_name: str,
    public_key_pem: str,
    contact_email: str,
    rekor_log_index: int | None = None,
) -> dict[str, Any]:
    with get_conn(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        now = _iso_now()
        conn.execute(
            "INSERT INTO operators "
            "(operator_id, org_name, public_key_pem, contact_email, "
            "registered_at, rekor_log_index) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (operator_id, org_name, public_key_pem, contact_email, now, rekor_log_index),
        )
        conn.execute("COMMIT")
    return operator_get(db_path, operator_id)


def operator_get(db_path: str, operator_id: str) -> dict[str, Any] | None:
    with get_conn(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM operators WHERE operator_id = ?", (operator_id,)
        ).fetchone()
    return dict(row) if row else None


def operator_count(db_path: str) -> int:
    with get_conn(db_path) as conn:
        return conn.execute("SELECT COUNT(*) FROM operators").fetchone()[0]


# ---------------------------------------------------------------------
# Submissions
# ---------------------------------------------------------------------


def submission_create(
    db_path: str,
    *,
    submission_id: str,
    operator_id: str,
    signed_export_json: str,
    entry_count: int,
    first_seq: int,
    last_seq: int,
    chain_head_signature: str,
    continuity_verified: bool,
) -> dict[str, Any]:
    with get_conn(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        now = _iso_now()
        conn.execute(
            "INSERT INTO submissions "
            "(submission_id, operator_id, signed_export_json, entry_count, first_seq, last_seq, "
            "chain_head_signature, continuity_verified, submitted_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                submission_id,
                operator_id,
                signed_export_json,
                entry_count,
                first_seq,
                last_seq,
                chain_head_signature,
                1 if continuity_verified else 0,
                now,
            ),
        )
        conn.execute(
            "UPDATE operators SET last_submission_at = ? WHERE operator_id = ?",
            (now, operator_id),
        )
        conn.execute("COMMIT")
    return submission_get(db_path, submission_id)


def submission_get(db_path: str, submission_id: str) -> dict[str, Any] | None:
    with get_conn(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM submissions WHERE submission_id = ?", (submission_id,)
        ).fetchone()
    return dict(row) if row else None


def submissions_pending_anchor(db_path: str) -> list[dict[str, Any]]:
    """Latest unanchored submission per operator — input to the
    cross-anchor builder."""
    with get_conn(db_path) as conn:
        rows = conn.execute(
            """
            SELECT s.* FROM submissions s
            JOIN (
                SELECT operator_id, MAX(submitted_at) AS latest
                FROM submissions
                WHERE cross_anchor_id IS NULL
                GROUP BY operator_id
            ) latest_per_op
            ON s.operator_id = latest_per_op.operator_id
            AND s.submitted_at = latest_per_op.latest
            WHERE s.cross_anchor_id IS NULL
            """
        ).fetchall()
    return [dict(r) for r in rows]


def submissions_mark_anchored(
    db_path: str, *, submission_ids: list[str], cross_anchor_id: str
) -> None:
    placeholders = ",".join("?" * len(submission_ids))
    with get_conn(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            f"UPDATE submissions SET cross_anchor_id = ? WHERE submission_id IN ({placeholders})",
            (cross_anchor_id, *submission_ids),
        )
        conn.execute("COMMIT")


# ---------------------------------------------------------------------
# Cross-anchors
# ---------------------------------------------------------------------


def cross_anchor_create(
    db_path: str,
    *,
    anchor_id: str,
    cross_anchor_hash: str,
    anchored_at: str,
    participants: list[dict[str, str]],
    rekor_log_index: int | None,
    rekor_url: str | None,
    federation_signature: str,
) -> None:
    with get_conn(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            "INSERT INTO cross_anchors "
            "(anchor_id, cross_anchor_hash, anchored_at, rekor_log_index, rekor_url, "
            "federation_signature) VALUES (?, ?, ?, ?, ?, ?)",
            (
                anchor_id,
                cross_anchor_hash,
                anchored_at,
                rekor_log_index,
                rekor_url,
                federation_signature,
            ),
        )
        conn.executemany(
            "INSERT INTO anchor_participants (anchor_id, operator_id, chain_signature) "
            "VALUES (?, ?, ?)",
            [(anchor_id, p["operator_id"], p["chain_signature"]) for p in participants],
        )
        conn.execute("COMMIT")


def cross_anchor_get(db_path: str, anchor_id: str) -> dict[str, Any] | None:
    with get_conn(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM cross_anchors WHERE anchor_id = ?", (anchor_id,)
        ).fetchone()
        if not row:
            return None
        result = dict(row)
        parts = conn.execute(
            "SELECT operator_id, chain_signature FROM anchor_participants WHERE anchor_id = ?",
            (anchor_id,),
        ).fetchall()
    result["participating_operators"] = [dict(r) for r in parts]
    return result


def cross_anchor_latest(db_path: str) -> dict[str, Any] | None:
    with get_conn(db_path) as conn:
        row = conn.execute(
            "SELECT anchor_id FROM cross_anchors ORDER BY anchored_at DESC LIMIT 1"
        ).fetchone()
    if not row:
        return None
    return cross_anchor_get(db_path, row["anchor_id"])


def _iso_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def to_json(obj: Any) -> str:
    """Helper for stringifying rows when needed."""
    return json.dumps(obj, separators=(",", ":"), sort_keys=True)
