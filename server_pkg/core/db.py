"""
SQLite schema initialisation and helper queries.

Tables:
  users      - credentials and role assignment
  roles      - role definitions with permissions JSON
  audit_log  - immutable append-only log of all sensitive operations

The DB file path defaults to data/efs_tdm.db but can be overridden via
the DB_PATH environment variable, which is useful for tests.
"""

import hashlib
import hmac
import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

# Serialises the SELECT-then-INSERT in append_audit so that concurrent threads
# cannot interleave between reading prev_hash and writing the new row.
_audit_chain_lock = threading.Lock()

DEFAULT_DB_PATH = Path(__file__).parent.parent / "data" / "efs_tdm.db"

_DEFAULT_ROLES = {
    "Admin":       ["list", "read", "write", "delete_own", "delete_any",
                    "mask", "export_raw", "manage_permissions", "manage_users",
                    "view_audit", "encrypt", "decrypt"],
    "Analyst":     ["list", "read", "mask"],
    "Contributor": ["list", "read", "write", "delete_own"],
    "Viewer":      ["list", "read"],
    "Auditor":     ["view_audit"],
    "Guest":       ["list"],
}

_DEFAULT_ROLES_JSON = Path(__file__).parent.parent / "config" / "roles.json"


def load_roles_config(roles_config: str | None = None) -> dict:
    """Load role definitions from a JSON file, falling back to built-in defaults."""
    path = Path(roles_config) if roles_config else _DEFAULT_ROLES_JSON
    if path.exists():
        try:
            data = json.loads(path.read_text())
            if isinstance(data, dict) and data:
                return data
        except Exception:
            pass
    return dict(_DEFAULT_ROLES)


# Backward-compat alias
BUILT_IN_ROLES = _DEFAULT_ROLES


def get_db_path() -> str:
    return os.environ.get("EFS_DB_PATH", str(DEFAULT_DB_PATH))


@contextmanager
def get_conn(db_path: str | None = None):
    """Context manager yielding a SQLite connection with WAL mode and FK enforcement."""
    path = db_path or get_db_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(db_path: str | None = None, roles_config: str | None = None) -> None:
    """
    Create all tables if they do not exist and seed roles.

    Args:
        db_path: Override DB path.
        roles_config: Path to roles.json. Falls back to config/roles.json then
                      built-in defaults.
    """
    with get_conn(db_path) as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS roles (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                name             TEXT NOT NULL UNIQUE,
                permissions_json TEXT NOT NULL DEFAULT '[]'
            );

            CREATE TABLE IF NOT EXISTS users (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                username     TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role         TEXT NOT NULL DEFAULT 'Guest',
                created_at   TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (role) REFERENCES roles(name)
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL DEFAULT (datetime('now')),
                user_id   INTEGER,
                username  TEXT,
                action    TEXT NOT NULL,
                file_id   TEXT,
                outcome   TEXT NOT NULL CHECK(outcome IN ('success', 'failure')),
                pid       INTEGER NOT NULL DEFAULT 0,
                chain_hash TEXT
            );

            CREATE TABLE IF NOT EXISTS inodes (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                name       TEXT NOT NULL,
                parent_id  INTEGER REFERENCES inodes(id) ON DELETE CASCADE,
                is_dir     INTEGER NOT NULL DEFAULT 0 CHECK(is_dir IN (0,1)),
                owner      TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                UNIQUE(parent_id, name)
            );

            CREATE TABLE IF NOT EXISTS file_meta (
                inode_id      INTEGER PRIMARY KEY REFERENCES inodes(id) ON DELETE CASCADE,
                blob_name     TEXT NOT NULL UNIQUE,
                size_bytes    INTEGER NOT NULL DEFAULT 0,
                original_name TEXT NOT NULL,
                content_hash  TEXT,
                uploaded_at   TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS acl (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                inode_id INTEGER NOT NULL REFERENCES inodes(id) ON DELETE CASCADE,
                role     TEXT NOT NULL,
                perm     TEXT NOT NULL,
                UNIQUE(inode_id, role, perm)
            );

            CREATE TABLE IF NOT EXISTS deliveries (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                sender         TEXT    NOT NULL,
                recipient      TEXT    NOT NULL,
                vfs_path       TEXT    NOT NULL,
                inode_id       INTEGER,
                sent_at        TEXT    NOT NULL DEFAULT (datetime('now')),
                delivered_at   TEXT,
                status         TEXT    NOT NULL DEFAULT 'pending',
                failure_reason TEXT,
                unmasked       INTEGER NOT NULL DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_audit_log_username
                ON audit_log(username);
            CREATE INDEX IF NOT EXISTS idx_audit_log_action
                ON audit_log(action);
            CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp
                ON audit_log(timestamp);
            CREATE INDEX IF NOT EXISTS idx_inodes_parent_sort
                ON inodes(parent_id, is_dir DESC, name);
            CREATE INDEX IF NOT EXISTS idx_deliveries_recipient_status
                ON deliveries(recipient, status);
        """)

    # Run column migrations in a separate connection so they commit independently
    # of the executescript above (executescript issues an implicit COMMIT which
    # can interfere with subsequent conn.execute calls in the same block).
    _migrations = [
        "ALTER TABLE audit_log ADD COLUMN chain_hash TEXT",
        "ALTER TABLE file_meta ADD COLUMN content_hash TEXT",
        "ALTER TABLE acl ADD COLUMN action TEXT NOT NULL DEFAULT 'grant'",
        "ALTER TABLE audit_log ADD COLUMN role TEXT",
        "ALTER TABLE inodes ADD COLUMN dir_size_bytes INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE deliveries ADD COLUMN unmasked INTEGER NOT NULL DEFAULT 0",
    ]
    with get_conn(db_path) as conn:
        for sql in _migrations:
            try:
                conn.execute(sql)
                if "dir_size_bytes" in sql:
                    _backfill_dir_sizes(conn)
            except sqlite3.OperationalError:
                pass  # column already exists

        # Sync roles from config file — always overwrite so roles.json is the source of truth
        roles = load_roles_config(roles_config)
        for role_name, perms in roles.items():
            conn.execute(
                "INSERT OR REPLACE INTO roles (name, permissions_json) VALUES (?, ?)",
                (role_name, json.dumps(perms)),
            )


# ---------------------------------------------------------------------------
# Role helpers
# ---------------------------------------------------------------------------

def get_role(name: str, db_path: str | None = None) -> dict | None:
    with get_conn(db_path) as conn:
        row = conn.execute("SELECT * FROM roles WHERE name = ?", (name,)).fetchone()
    if row is None:
        return None
    return {"id": row["id"], "name": row["name"], "permissions": json.loads(row["permissions_json"])}


def list_roles(db_path: str | None = None) -> list[dict]:
    with get_conn(db_path) as conn:
        rows = conn.execute("SELECT * FROM roles ORDER BY name").fetchall()
    return [{"id": r["id"], "name": r["name"], "permissions": json.loads(r["permissions_json"])} for r in rows]


# ---------------------------------------------------------------------------
# User helpers
# ---------------------------------------------------------------------------

def create_user(username: str, password_hash: str, role: str = "Guest",
                db_path: str | None = None) -> int:
    """
    Insert a new user row. Raises sqlite3.IntegrityError if username exists
    or role is not in the roles table.
    Returns the new user's id.
    """
    with get_conn(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username, password_hash, role),
        )
        return cur.lastrowid


def get_user(username: str, db_path: str | None = None) -> dict | None:
    with get_conn(db_path) as conn:
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if row is None:
        return None
    return dict(row)


def get_user_by_id(user_id: int, db_path: str | None = None) -> dict | None:
    with get_conn(db_path) as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if row is None:
        return None
    return dict(row)


def update_user_role(username: str, new_role: str, db_path: str | None = None) -> bool:
    """Returns True if a row was updated, False if username not found."""
    with get_conn(db_path) as conn:
        cur = conn.execute(
            "UPDATE users SET role = ? WHERE username = ?", (new_role, username)
        )
        return cur.rowcount > 0


def update_user_password(username: str, new_hash: str, db_path: str | None = None) -> bool:
    """Returns True if a row was updated, False if username not found."""
    with get_conn(db_path) as conn:
        cur = conn.execute(
            "UPDATE users SET password_hash = ? WHERE username = ?", (new_hash, username)
        )
        return cur.rowcount > 0


def list_users(db_path: str | None = None) -> list[dict]:
    with get_conn(db_path) as conn:
        rows = conn.execute(
            "SELECT id, username, role, created_at FROM users ORDER BY username"
        ).fetchall()
    return [dict(r) for r in rows]


def delete_user(username: str, db_path: str | None = None) -> bool:
    with get_conn(db_path) as conn:
        cur = conn.execute("DELETE FROM users WHERE username = ?", (username,))
        return cur.rowcount > 0


# ---------------------------------------------------------------------------
# Audit log helpers
# ---------------------------------------------------------------------------

def append_audit(
    action: str,
    outcome: str,
    username: str | None = None,
    user_id: int | None = None,
    file_id: str | None = None,
    pid: int | None = None,
    role: str | None = None,
    db_path: str | None = None,
) -> None:
    """Append a single row to the audit log."""
    actual_pid = pid if pid is not None else os.getpid()
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    with _audit_chain_lock:
        with get_conn(db_path) as conn:
            row = conn.execute(
                "SELECT chain_hash FROM audit_log ORDER BY id DESC LIMIT 1"
            ).fetchone()
            prev_hash = row["chain_hash"] if row and row["chain_hash"] is not None else ""
            new_hash = hmac.new(
                b"efs-audit-chain",
                (
                    prev_hash
                    + timestamp
                    + action
                    + outcome
                    + (username or "")
                    + str(actual_pid)
                    + str(user_id or "")
                    + (file_id or "")
                    + (role or "")
                ).encode(),
                hashlib.sha256,
            ).hexdigest()
            conn.execute(
                """INSERT INTO audit_log
                       (timestamp, username, user_id, action, file_id, outcome, pid, role, chain_hash)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (timestamp, username, user_id, action, file_id, outcome, actual_pid, role, new_hash),
            )


def verify_audit_chain(db_path: str | None = None) -> bool:
    """
    Return True if all chain_hash values in audit_log are consistent.

    When called with the live db_path, verifies only the live log.
    Use verify_audit_chain_across() to verify continuity across archives.
    """
    with get_conn(db_path) as conn:
        rows = conn.execute(
            """SELECT timestamp, action, outcome, username, pid,
                      user_id, file_id, role, chain_hash
               FROM audit_log ORDER BY id ASC"""
        ).fetchall()
    prev_hash = ""
    for row in rows:
        expected = hmac.new(
            b"efs-audit-chain",
            (
                prev_hash
                + (row["timestamp"] or "")
                + row["action"]
                + row["outcome"]
                + (row["username"] or "")
                + str(row["pid"] or 0)
                + str(row["user_id"] or "")
                + (row["file_id"] or "")
                + (row["role"] or "")
            ).encode(),
            hashlib.sha256,
        ).hexdigest()
        if row["chain_hash"] != expected:
            return False
        prev_hash = row["chain_hash"]
    return True


def verify_audit_chain_incremental(
    db_path: str | None = None,
    last_id: int = 0,
    last_hash: str = "",
) -> tuple[bool, int, str]:
    """
    Verify only audit rows with id > last_id, starting the HMAC chain from
    last_hash (the chain_hash of row last_id).

    When last_id == 0, verifies the entire chain from the beginning (last_hash
    is ignored; the expected prev_hash for the first row is "").

    Returns (ok, new_last_id, new_last_hash).
    If there are no new rows, returns (True, last_id, last_hash) unchanged.
    On a broken chain, returns (False, last_id, last_hash) — caller's tracked
    state is not advanced so the broken region is not skipped.
    """
    with get_conn(db_path) as conn:
        rows = conn.execute(
            """SELECT id, timestamp, action, outcome, username, pid,
                      user_id, file_id, role, chain_hash
               FROM audit_log
               WHERE id > ?
               ORDER BY id ASC""",
            (last_id,),
        ).fetchall()

    if not rows:
        return True, last_id, last_hash

    prev_hash = "" if last_id == 0 else last_hash

    for row in rows:
        expected = hmac.new(
            b"efs-audit-chain",
            (
                prev_hash
                + (row["timestamp"] or "")
                + row["action"]
                + row["outcome"]
                + (row["username"] or "")
                + str(row["pid"] or 0)
                + str(row["user_id"] or "")
                + (row["file_id"] or "")
                + (row["role"] or "")
            ).encode(),
            hashlib.sha256,
        ).hexdigest()
        if row["chain_hash"] != expected:
            return False, last_id, last_hash
        prev_hash = row["chain_hash"]

    last_row = rows[-1]
    return True, last_row["id"], last_row["chain_hash"]


def verify_audit_chain_across(db_paths: list[str]) -> tuple[bool, str]:
    """
    Verify the audit chain is unbroken across a sequence of DB files.

    db_paths must be ordered oldest-first, ending with the live DB.
    Each archive's last chain_hash must match the prev_hash encoded in the
    first entry of the next DB (the audit_rotated_from bootstrap entry).

    Returns (ok: bool, message: str).
    """
    prev_tip = ""  # chain_hash at end of previous file

    for idx, path in enumerate(db_paths):
        # Verify the internal chain of this file
        if not verify_audit_chain(path):
            return False, f"Internal chain broken in {Path(path).name}"

        with get_conn(path) as conn:
            rows = conn.execute(
                "SELECT action, file_id, chain_hash FROM audit_log ORDER BY id ASC"
            ).fetchall()

        if not rows:
            return False, f"Empty audit log in {Path(path).name}"

        first = rows[0]

        # If the first entry of the very first file is audit_rotated_from,
        # it means a preceding archive is missing from the sequence
        if idx == 0 and first["action"] == "audit_rotated_from":
            return False, (
                f"{Path(path).name} starts with a rotation bootstrap entry — "
                f"one or more preceding archives are missing from the sequence"
            )

        # Every subsequent file must start with audit_rotated_from whose
        # file_id encodes the previous file's chain tip
        if idx > 0:
            if first["action"] != "audit_rotated_from":
                return False, f"Missing rotation bootstrap entry in {Path(path).name}"
            file_id = first["file_id"] or ""
            if f"prev_hash:{prev_tip}" not in file_id:
                return False, (
                    f"Chain break between {Path(db_paths[idx-1]).name} and "
                    f"{Path(path).name}: expected prev_hash {prev_tip!r}"
                )

        # The tip of this file is the last chain_hash
        prev_tip = rows[-1]["chain_hash"] or ""

    return True, "Chain intact across all archives"


def _adjust_ancestor_sizes(start_id: int, delta: int, conn) -> None:
    """Walk up the parent chain from start_id and adjust dir_size_bytes by delta."""
    if delta == 0:
        return
    node_id = start_id
    while node_id is not None:
        conn.execute(
            "UPDATE inodes SET dir_size_bytes = dir_size_bytes + ? WHERE id = ?",
            (delta, node_id),
        )
        row = conn.execute(
            "SELECT parent_id FROM inodes WHERE id = ?", (node_id,)
        ).fetchone()
        if row is None:
            break
        node_id = row["parent_id"]


def _backfill_dir_sizes(conn) -> None:
    """One-time backfill of dir_size_bytes for existing installations."""
    dirs = conn.execute("SELECT id FROM inodes WHERE is_dir = 1").fetchall()
    updates = []
    for d in dirs:
        row = conn.execute(
            """
            WITH RECURSIVE descendants(id) AS (
                SELECT id FROM inodes WHERE id = ?
                UNION ALL
                SELECT i.id FROM inodes i
                JOIN descendants dc ON i.parent_id = dc.id
            )
            SELECT COALESCE(SUM(fm.size_bytes), 0) AS total
            FROM descendants dc
            JOIN file_meta fm ON fm.inode_id = dc.id
            """,
            (d["id"],),
        ).fetchone()
        updates.append((row["total"], d["id"]))
    conn.executemany(
        "UPDATE inodes SET dir_size_bytes = ? WHERE id = ?", updates
    )


def ensure_root(db_path: str | None = None) -> int:
    """Ensure the VFS root inode (parent_id IS NULL, name='/') exists. Returns its id."""
    with get_conn(db_path) as conn:
        row = conn.execute(
            "SELECT id FROM inodes WHERE parent_id IS NULL AND name = '/'",
        ).fetchone()
        if row:
            return row["id"]
        cur = conn.execute(
            "INSERT INTO inodes (name, parent_id, is_dir, owner) VALUES ('/', NULL, 1, 'system')",
        )
        return cur.lastrowid


def get_inode(inode_id: int, db_path: str | None = None) -> dict | None:
    with get_conn(db_path) as conn:
        row = conn.execute("SELECT * FROM inodes WHERE id = ?", (inode_id,)).fetchone()
    return dict(row) if row else None


def get_inode_by_path_components(parent_id: int | None, name: str,
                                  db_path: str | None = None) -> dict | None:
    with get_conn(db_path) as conn:
        if parent_id is None:
            row = conn.execute(
                "SELECT * FROM inodes WHERE parent_id IS NULL AND name = ?", (name,),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT * FROM inodes WHERE parent_id = ? AND name = ?", (parent_id, name),
            ).fetchone()
    return dict(row) if row else None


def list_inodes(parent_id: int, db_path: str | None = None) -> list[dict]:
    with get_conn(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM inodes WHERE parent_id = ? ORDER BY is_dir DESC, name",
            (parent_id,),
        ).fetchall()
    return [dict(r) for r in rows]


def create_inode(name: str, parent_id: int, is_dir: bool, owner: str,
                  db_path: str | None = None) -> int:
    with get_conn(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO inodes (name, parent_id, is_dir, owner) VALUES (?, ?, ?, ?)",
            (name, parent_id, 1 if is_dir else 0, owner),
        )
        return cur.lastrowid


def delete_inode(inode_id: int, db_path: str | None = None) -> bool:
    with get_conn(db_path) as conn:
        node = conn.execute(
            "SELECT parent_id, is_dir, dir_size_bytes FROM inodes WHERE id = ?", (inode_id,)
        ).fetchone()
        if not node:
            return False
        parent_id = node["parent_id"]
        if node["is_dir"]:
            size_to_remove = node["dir_size_bytes"]
        else:
            fm = conn.execute(
                "SELECT size_bytes FROM file_meta WHERE inode_id = ?", (inode_id,)
            ).fetchone()
            size_to_remove = fm["size_bytes"] if fm else 0
        cur = conn.execute("DELETE FROM inodes WHERE id = ?", (inode_id,))
        if cur.rowcount > 0 and parent_id is not None and size_to_remove > 0:
            _adjust_ancestor_sizes(parent_id, -size_to_remove, conn)
        return cur.rowcount > 0


def move_inode(inode_id: int, new_parent_id: int, new_name: str,
               db_path: str | None = None) -> bool:
    with get_conn(db_path) as conn:
        node = conn.execute(
            "SELECT parent_id, is_dir, dir_size_bytes FROM inodes WHERE id = ?", (inode_id,)
        ).fetchone()
        if not node:
            return False
        old_parent_id = node["parent_id"]
        if node["is_dir"]:
            size = node["dir_size_bytes"]
        else:
            fm = conn.execute(
                "SELECT size_bytes FROM file_meta WHERE inode_id = ?", (inode_id,)
            ).fetchone()
            size = fm["size_bytes"] if fm else 0
        cur = conn.execute(
            "UPDATE inodes SET parent_id = ?, name = ? WHERE id = ?",
            (new_parent_id, new_name, inode_id),
        )
        if cur.rowcount > 0 and size > 0:
            if old_parent_id is not None:
                _adjust_ancestor_sizes(old_parent_id, -size, conn)
            _adjust_ancestor_sizes(new_parent_id, size, conn)
        return cur.rowcount > 0


def create_file_meta(inode_id: int, blob_name: str, size_bytes: int,
                      original_name: str, db_path: str | None = None,
                      content_hash: str | None = None) -> None:
    with get_conn(db_path) as conn:
        conn.execute(
            """INSERT INTO file_meta (inode_id, blob_name, size_bytes, original_name, content_hash)
               VALUES (?, ?, ?, ?, ?)""",
            (inode_id, blob_name, size_bytes, original_name, content_hash),
        )
        row = conn.execute(
            "SELECT parent_id FROM inodes WHERE id = ?", (inode_id,)
        ).fetchone()
        if row and row["parent_id"] is not None:
            _adjust_ancestor_sizes(row["parent_id"], size_bytes, conn)


def get_file_meta(inode_id: int, db_path: str | None = None) -> dict | None:
    with get_conn(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM file_meta WHERE inode_id = ?", (inode_id,),
        ).fetchone()
    return dict(row) if row else None


def update_file_meta_size(inode_id: int, size_bytes: int,
                           db_path: str | None = None,
                           content_hash: str | None = None) -> None:
    with get_conn(db_path) as conn:
        old = conn.execute(
            "SELECT size_bytes FROM file_meta WHERE inode_id = ?", (inode_id,)
        ).fetchone()
        old_size = old["size_bytes"] if old else 0
        conn.execute(
            "UPDATE file_meta SET size_bytes = ?, content_hash = ?, uploaded_at = datetime('now') WHERE inode_id = ?",
            (size_bytes, content_hash, inode_id),
        )
        delta = size_bytes - old_size
        if delta != 0:
            row = conn.execute(
                "SELECT parent_id FROM inodes WHERE id = ?", (inode_id,)
            ).fetchone()
            if row and row["parent_id"] is not None:
                _adjust_ancestor_sizes(row["parent_id"], delta, conn)


def get_acl(inode_id: int, db_path: str | None = None) -> list[dict]:
    with get_conn(db_path) as conn:
        rows = conn.execute(
            "SELECT role, perm, action FROM acl WHERE inode_id = ?", (inode_id,),
        ).fetchall()
    return [dict(r) for r in rows]


def set_acl(inode_id: int, role: str, perm: str, db_path: str | None = None) -> None:
    with get_conn(db_path) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO acl (inode_id, role, perm, action) VALUES (?, ?, ?, 'grant')",
            (inode_id, role, perm),
        )


def revoke_acl(inode_id: int, role: str, perm: str, db_path: str | None = None) -> None:
    with get_conn(db_path) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO acl (inode_id, role, perm, action) VALUES (?, ?, ?, 'deny')",
            (inode_id, role, perm),
        )


# ---------------------------------------------------------------------------
# Deliveries
# ---------------------------------------------------------------------------

def create_delivery(sender: str, recipient: str, vfs_path: str,
                    inode_id: int, db_path: str | None = None,
                    unmasked: bool = False) -> int:
    """Insert a pending delivery record. Returns the new delivery id."""
    with get_conn(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO deliveries (sender, recipient, vfs_path, inode_id, unmasked)"
            " VALUES (?, ?, ?, ?, ?)",
            (sender, recipient, vfs_path, inode_id, int(unmasked)),
        )
        return cur.lastrowid


def get_pending_deliveries(recipient: str, db_path: str | None = None) -> list[dict]:
    """Return all pending deliveries for a recipient, oldest first."""
    with get_conn(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM deliveries WHERE recipient = ? AND status = 'pending' ORDER BY id",
            (recipient,),
        ).fetchall()
    return [dict(r) for r in rows]


def update_delivery_status(delivery_id: int, status: str,
                           failure_reason: str | None = None,
                           db_path: str | None = None) -> None:
    with get_conn(db_path) as conn:
        if status == "delivered":
            conn.execute(
                "UPDATE deliveries SET status=?, failure_reason=?, delivered_at=datetime('now') WHERE id=?",
                (status, failure_reason, delivery_id),
            )
        else:
            conn.execute(
                "UPDATE deliveries SET status=?, failure_reason=? WHERE id=?",
                (status, failure_reason, delivery_id),
            )


def query_audit(
    username: str | None = None,
    action: str | None = None,
    limit: int = 100,
    from_ts: str | None = None,
    to_ts: str | None = None,
    db_path: str | None = None,
    default_limit: int | None = None,
) -> list[dict]:
    """Query audit log with optional filters.

    Args:
        default_limit: If provided and limit was not explicitly overridden by
                       the caller, use this as the limit instead of 100.
    """
    if default_limit is not None and limit == 100:
        limit = default_limit
    clauses = []
    params = []
    if username:
        clauses.append("username = ?")
        params.append(username)
    if action:
        clauses.append("action = ?")
        params.append(action)
    if from_ts:
        clauses.append("timestamp >= ?")
        params.append(from_ts)
    if to_ts:
        clauses.append("timestamp <= ?")
        params.append(to_ts)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    with get_conn(db_path) as conn:
        if limit and limit > 0:
            # Fetch the newest N rows (DESC), then reverse so display is oldest-first
            params.append(limit)
            rows = conn.execute(
                f"SELECT * FROM (SELECT * FROM audit_log {where} ORDER BY id DESC LIMIT ?) ORDER BY id ASC",
                params,
            ).fetchall()
        else:
            rows = conn.execute(
                f"SELECT * FROM audit_log {where} ORDER BY id ASC", params
            ).fetchall()
    return [dict(r) for r in rows]


def _purge_old_archives(data_dir: Path, retention_max: int) -> None:
    """Delete oldest archive files if count exceeds retention_max."""
    if retention_max <= 0:
        return
    archives = sorted(data_dir.glob("audit_*.db"))
    while len(archives) > retention_max:
        oldest = archives.pop(0)
        try:
            oldest.unlink()
        except Exception:
            pass


def rotate_audit_log(db_path: str | None = None, username: str | None = None,
                     retention_max_archives: int = 0) -> str:
    """
    Archive the current audit_log to a separate dated SQLite file and truncate
    the live table.

    Steps:
      1. Write sentinel entry: action=audit_rotated, file_id=<archive_name>
      2. Read the final chain_hash from the live log (the sentinel's hash)
      3. Copy all rows to <data_dir>/audit_<timestamp>.db
      4. DELETE all rows from audit_log (resets the live log)
      5. Write bootstrap entry to new log carrying the previous archive's last
         chain_hash in file_id — this links the new chain to the old one so
         any gap, deletion, or tampering of an archive is detectable.
      6. If retention_max_archives > 0, purge oldest archives exceeding the limit.

    The bootstrap entry format:
        action    = audit_rotated_from
        file_id   = <archive_name>|prev_hash:<last_chain_hash>

    Returns the archive filename (basename only).
    Caller is responsible for holding any write-quiesce lock before calling.
    """
    path = db_path or get_db_path()
    data_dir = Path(path).parent
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S-%f")
    archive_name = f"audit_{ts}.db"
    archive_path = str(data_dir / archive_name)

    # Write sentinel into live log so the old chain ends with a rotation pointer
    append_audit("audit_rotated", "success", username=username, file_id=archive_name, db_path=db_path)

    # Read the last chain_hash (the sentinel's hash) — this is the chain tip
    # that the new log must reference to prove continuity
    with get_conn(db_path) as conn:
        row = conn.execute(
            "SELECT chain_hash FROM audit_log ORDER BY id DESC LIMIT 1"
        ).fetchone()
        last_hash = row["chain_hash"] if row and row["chain_hash"] else ""

    # Use SQLite's online backup API instead of shutil.copy2:
    # - WAL-safe: checkpoints WAL into archive before copying
    # - No file-level lock held during the copy, so other connections are not blocked
    src  = sqlite3.connect(path)
    dest = sqlite3.connect(archive_path)
    with dest:
        src.backup(dest)
    dest.close()
    src.close()

    # Lock the archive against modification (best-effort; no-op on Windows)
    try:
        os.chmod(archive_path, 0o444)
    except OSError:
        pass

    # Truncate audit_log in the live DB and reset the sqlite sequence counter
    with get_conn(db_path) as conn:
        conn.execute("DELETE FROM audit_log")
        conn.execute("DELETE FROM sqlite_sequence WHERE name = 'audit_log'")

    # Write bootstrap entry carrying the previous archive's last hash.
    # The file_id encodes both the archive name and the prev_hash so an auditor
    # can verify the chain tip of the archive matches this entry's file_id.
    append_audit(
        "audit_rotated_from", "success",
        file_id=f"{archive_name}|prev_hash:{last_hash}",
        db_path=db_path,
    )

    # Enforce retention policy
    if retention_max_archives > 0:
        _purge_old_archives(data_dir, retention_max_archives)

    return archive_name


def append_audit_with_config(
    action: str,
    outcome: str,
    username: str | None = None,
    user_id: int | None = None,
    file_id: str | None = None,
    pid: int | None = None,
    role: str | None = None,
    db_path: str | None = None,
    audit_config: dict | None = None,
) -> None:
    """Append audit entry and auto-rotate if a configured threshold is reached.

    Rotation triggers when either:
      - auto_rotate_max_entries is exceeded, or
      - the oldest entry is older than auto_rotate_max_days days.
    Both checks are skipped when the respective config value is 0.
    Rotation is recorded as a system entry in both the old and new log.
    """
    append_audit(action, outcome, username=username, user_id=user_id,
                 file_id=file_id, pid=pid, role=role, db_path=db_path)

    if not audit_config:
        return

    retention = audit_config.get("retention_max_archives", 0)
    should_rotate = False

    max_entries = audit_config.get("auto_rotate_max_entries", 0)
    if max_entries > 0:
        with get_conn(db_path) as conn:
            row = conn.execute("SELECT COUNT(*) as cnt FROM audit_log").fetchone()
            if row and row["cnt"] > max_entries:
                should_rotate = True

    if not should_rotate:
        max_days = audit_config.get("auto_rotate_max_days", 0)
        if max_days > 0:
            with get_conn(db_path) as conn:
                row = conn.execute(
                    "SELECT timestamp FROM audit_log ORDER BY id ASC LIMIT 1"
                ).fetchone()
                if row and row["timestamp"]:
                    try:
                        oldest = datetime.fromisoformat(row["timestamp"])
                        age = (datetime.now(timezone.utc) - oldest.replace(tzinfo=timezone.utc)).days
                        if age >= max_days:
                            should_rotate = True
                    except ValueError:
                        pass

    if should_rotate:
        rotate_audit_log(db_path=db_path, username="system",
                         retention_max_archives=retention)
