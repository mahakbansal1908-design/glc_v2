"""Append-only SQLite audit log.

Every channel message, agent decision, policy verdict, and tool dispatch
lands here. Append-only is enforced at the application layer: only
`append()` is exposed; there is no update or delete function. The schema
ships with `audit_schema` version 1; bumping it requires a documented
migration step (see schema.sql).

Each append commits immediately so writes survive a hard kill.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any

DEFAULT_DIR = Path(os.path.expanduser("~/.glc"))


def _resolve_path() -> str:
    """Resolve at call time, not import time, so tests that swap the env
    var see the change."""
    return os.getenv("GLC_AUDIT_DB", str(DEFAULT_DIR / "audit.sqlite"))


@contextmanager
def _conn():
    p = _resolve_path()
    Path(p).parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(p, isolation_level=None)  # autocommit; each insert flushes
    c.row_factory = sqlite3.Row
    try:
        yield c
    finally:
        c.close()


_SCHEMA_PATH = Path(__file__).parent / "schema.sql"


def init_store() -> None:
    with _conn() as c:
        c.executescript(_SCHEMA_PATH.read_text())
        
        # Migration to v2: Add hash chaining columns
        row = c.execute("SELECT MAX(version) AS v FROM audit_schema").fetchone()
        v = int(row["v"] or 0) if row else 0
        if v < 2:
            try:
                c.execute("ALTER TABLE audit_log ADD COLUMN prev_hash TEXT")
                c.execute("ALTER TABLE audit_log ADD COLUMN curr_hash TEXT")
            except sqlite3.OperationalError:
                # Ignore if columns were already added manually
                pass
            c.execute("INSERT OR IGNORE INTO audit_schema (version, applied_at) VALUES (2, strftime('%s','now'))")


def _jsonify(v: Any) -> str | None:
    if v is None:
        return None
    if isinstance(v, str):
        return v
    try:
        return json.dumps(v, default=str)
    except Exception:
        return json.dumps({"_repr": repr(v)})


class AuditStore:
    """Application-layer write-once store. The class deliberately exposes
    no update or delete methods. Reads (for the replay viewer) live in
    query() which is read-only."""

    def append(
        self,
        *,
        channel: str,
        channel_user_id: str,
        trust_level: str,
        event_type: str,
        session_id: str | None = None,
        tool: str | None = None,
        policy_verdict: str | None = None,
        params: Any = None,
        result: Any = None,
    ) -> int:
        with _conn() as c:
            # FIX for Leak 2: Calculate cryptographic hash chain
            row = c.execute("SELECT curr_hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
            prev_hash = row["curr_hash"] if row and row["curr_hash"] else "0" * 64
            
            ts = time.time()
            pj = _jsonify(params)
            rj = _jsonify(result)
            
            import hashlib
            raw_data = f"{prev_hash}|{ts}|{session_id}|{channel}|{channel_user_id}|{trust_level}|{event_type}|{tool}|{policy_verdict}|{pj}|{rj}"
            curr_hash = hashlib.sha256(raw_data.encode("utf-8")).hexdigest()
            
            cur = c.execute(
                """INSERT INTO audit_log
                   (ts, session_id, channel, channel_user_id, trust_level,
                    event_type, tool, policy_verdict, params_json, result_json, prev_hash, curr_hash)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    ts,
                    session_id,
                    channel,
                    channel_user_id,
                    trust_level,
                    event_type,
                    tool,
                    policy_verdict,
                    pj,
                    rj,
                    prev_hash,
                    curr_hash
                ),
            )
            return int(cur.lastrowid or 0)


_singleton: AuditStore | None = None


def get_store() -> AuditStore:
    global _singleton
    if _singleton is None:
        init_store()
        _singleton = AuditStore()
    return _singleton


def append(**kwargs: Any) -> int:
    return get_store().append(**kwargs)


def query(limit: int = 100, session_id: str | None = None, channel: str | None = None) -> list[dict]:
    q = "SELECT * FROM audit_log"
    where, args = [], []
    if session_id:
        where.append("session_id=?")
        args.append(session_id)
    if channel:
        where.append("channel=?")
        args.append(channel)
    if where:
        q += " WHERE " + " AND ".join(where)
    q += " ORDER BY ts DESC LIMIT ?"
    args.append(limit)
    with _conn() as c:
        return [dict(r) for r in c.execute(q, args).fetchall()]


def schema_version() -> int:
    with _conn() as c:
        row = c.execute("SELECT MAX(version) AS v FROM audit_schema").fetchone()
        return int(row["v"] or 0)
