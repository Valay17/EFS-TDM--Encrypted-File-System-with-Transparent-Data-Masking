"""
Audit Logger.

Thin facade over core.db.append_audit / core.db.query_audit that
provides named, typed log methods for every sensitive event in the system.

All log entries are written to the audit_log table in SQLite.
Each entry records: timestamp, username, user_id, action, file_id,
                    outcome (success|failure), pid.

Usage:
    from server.audit_logger import AuditLogger
    log = AuditLogger()                  # uses default DB path
    log = AuditLogger(db_path="/tmp/t.db")  # override for tests

    log.login("alice", user_id=3, success=True)
    log.logout("alice", user_id=3)
    log.encrypt("alice", user_id=3, file_id="employees.csv", success=True)
    log.permission_denied("bob", action="decrypt", file_id="report.pdf")
    entries = log.query(username="alice", limit=20)
"""

import os
from typing import Any

from core.db import append_audit_with_config, query_audit, rotate_audit_log


class AuditLogger:
    """
    Named audit-log methods for every event category.

    All methods ultimately call core.db.append_audit_with_config so the storage
    layer stays in one place and auto-rotation is applied on every write.
    """

    def __init__(self, db_path: str | None = None, audit_config: dict | None = None):
        self._db = db_path
        self._audit_config = audit_config or {}

    def _log(
        self,
        action: str,
        outcome: str,
        username: str | None = None,
        user_id: int | None = None,
        file_id: str | None = None,
        role: str | None = None,
    ) -> None:
        append_audit_with_config(
            action=action,
            outcome=outcome,
            username=username,
            user_id=user_id,
            file_id=file_id,
            pid=os.getpid(),
            role=role,
            db_path=self._db,
            audit_config=self._audit_config,
        )

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    def login(self, username: str, user_id: int | None = None, success: bool = True,
              role: str | None = None) -> None:
        self._log("login", "success" if success else "failure",
                  username=username, user_id=user_id, role=role)

    def logout(self, username: str, user_id: int | None = None,
               role: str | None = None) -> None:
        self._log("logout", "success", username=username, user_id=user_id, role=role)

    # ------------------------------------------------------------------
    # Key management
    # ------------------------------------------------------------------

    def key_issued(self, username: str, user_id: int | None = None,
                   file_id: str | None = None, role: str | None = None) -> None:
        self._log("key_issued", "success", username=username,
                  user_id=user_id, file_id=file_id, role=role)

    def key_revoked(self, username: str, user_id: int | None = None,
                    file_id: str | None = None, role: str | None = None) -> None:
        self._log("key_revoked", "success", username=username,
                  user_id=user_id, file_id=file_id, role=role)

    def key_expired(self, username: str | None = None, file_id: str | None = None,
                    role: str | None = None) -> None:
        self._log("key_expired", "failure", username=username, file_id=file_id, role=role)

    # ------------------------------------------------------------------
    # File operations
    # ------------------------------------------------------------------

    def encrypt(self, username: str, user_id: int | None = None,
                file_id: str | None = None, success: bool = True,
                role: str | None = None) -> None:
        self._log("encrypt", "success" if success else "failure",
                  username=username, user_id=user_id, file_id=file_id, role=role)

    def decrypt(self, username: str, user_id: int | None = None,
                file_id: str | None = None, success: bool = True,
                role: str | None = None) -> None:
        self._log("decrypt", "success" if success else "failure",
                  username=username, user_id=user_id, file_id=file_id, role=role)

    def mask(self, username: str, user_id: int | None = None,
             file_id: str | None = None, success: bool = True,
             role: str | None = None) -> None:
        self._log("mask", "success" if success else "failure",
                  username=username, user_id=user_id, file_id=file_id, role=role)

    # ------------------------------------------------------------------
    # RBAC / user management
    # ------------------------------------------------------------------

    def add_user(self, admin_username: str, target_username: str,
                 target_role: str, success: bool = True,
                 caller_role: str | None = None) -> None:
        self._log("add_user", "success" if success else "failure",
                  username=admin_username,
                  file_id=f"user:{target_username} role:{target_role}",
                  role=caller_role)

    def remove_user(self, admin_username: str, target_username: str,
                    success: bool = True, caller_role: str | None = None) -> None:
        self._log("remove_user", "success" if success else "failure",
                  username=admin_username, file_id=f"user:{target_username}",
                  role=caller_role)

    def assign_role(self, admin_username: str, target_username: str,
                    new_role: str, success: bool = True,
                    caller_role: str | None = None) -> None:
        self._log("assign_role", "success" if success else "failure",
                  username=admin_username,
                  file_id=f"user:{target_username} role:{new_role}",
                  role=caller_role)

    # ------------------------------------------------------------------
    # Deliveries
    # ------------------------------------------------------------------

    def delivery_sent(self, sender: str, recipient: str, vfs_path: str,
                      user_id: int | None = None, role: str | None = None) -> None:
        self._log("send_to_user", "success", username=sender, user_id=user_id,
                  file_id=f"{vfs_path} -> {recipient}", role=role)

    def delivery_received(self, recipient: str, vfs_path: str, sender: str,
                          user_id: int | None = None, role: str | None = None) -> None:
        self._log("delivery_received", "success", username=recipient, user_id=user_id,
                  file_id=f"{vfs_path} (from {sender})", role=role)

    def delivery_skipped(self, recipient: str, vfs_path: str,
                         user_id: int | None = None, role: str | None = None) -> None:
        self._log("delivery_skipped", "failure", username=recipient, user_id=user_id,
                  file_id=vfs_path, role=role)

    def delivery_failed(self, recipient: str, vfs_path: str, reason: str,
                        user_id: int | None = None, role: str | None = None) -> None:
        self._log("delivery_failed", "failure", username=recipient, user_id=user_id,
                  file_id=f"{vfs_path} ({reason})", role=role)

    # Permission denials
    # ------------------------------------------------------------------

    def permission_denied(self, username: str, action: str,
                          user_id: int | None = None,
                          file_id: str | None = None,
                          role: str | None = None) -> None:
        self._log(f"denied:{action}", "failure",
                  username=username, user_id=user_id, file_id=file_id, role=role)

    def log(self, action: str, outcome: str, username: str | None = None,
            user_id: int | None = None, file_id: str | None = None,
            role: str | None = None) -> None:
        self._log(action, outcome, username=username, user_id=user_id,
                  file_id=file_id, role=role)

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def query(
        self,
        username: str | None = None,
        action: str | None = None,
        limit: int = 100,
        from_ts: str | None = None,
        to_ts: str | None = None,
        db_path: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        Return audit log entries, oldest first.

        Args:
            username: Filter to entries by this username.
            action:   Filter to entries with this action string.
            limit:    Maximum number of entries to return (default 100).
            from_ts:  ISO timestamp lower bound (inclusive), e.g. "2026-03-25 00:00:00".
            to_ts:    ISO timestamp upper bound (inclusive), e.g. "2026-03-25 23:59:59".
            db_path:  Override DB path (used for archive queries).

        Returns:
            List of dicts with keys: id, timestamp, username, user_id,
            action, file_id, outcome, pid, role.
        """
        return query_audit(
            username=username, action=action, limit=limit,
            from_ts=from_ts, to_ts=to_ts,
            db_path=db_path or self._db,
        )

    def rotate(self, username: str | None = None,
               retention_max_archives: int = 0) -> str:
        """Archive and truncate the live audit log. Returns archive filename."""
        return rotate_audit_log(db_path=self._db, username=username,
                                retention_max_archives=retention_max_archives)
