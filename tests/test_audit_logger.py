"""
Unit tests for server/audit_logger.py.
Each test uses a fresh temp DB initialized with the schema.
"""

import os
import sqlite3
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.db import append_audit, init_db, verify_audit_chain, verify_audit_chain_incremental
from server.audit_logger import AuditLogger


def make_logger() -> tuple[AuditLogger, str]:
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    init_db(path)
    return AuditLogger(db_path=path), path


class TestLogin(unittest.TestCase):

    def setUp(self):
        self.log, self.db = make_logger()

    def tearDown(self):
        os.unlink(self.db)

    def test_login_success_recorded(self):
        self.log.login("alice", user_id=1, success=True)
        entries = self.log.query(username="alice", action="login")
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["outcome"], "success")

    def test_login_failure_recorded(self):
        self.log.login("alice", success=False)
        entries = self.log.query(username="alice", action="login")
        self.assertEqual(entries[0]["outcome"], "failure")

    def test_logout_recorded(self):
        self.log.logout("alice", user_id=1)
        entries = self.log.query(username="alice", action="logout")
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["outcome"], "success")


class TestKeyEvents(unittest.TestCase):

    def setUp(self):
        self.log, self.db = make_logger()

    def tearDown(self):
        os.unlink(self.db)

    def test_key_issued(self):
        self.log.key_issued("bob", user_id=2, file_id="report.csv")
        entries = self.log.query(username="bob", action="key_issued")
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["file_id"], "report.csv")

    def test_key_revoked(self):
        self.log.key_revoked("bob", file_id="report.csv")
        entries = self.log.query(action="key_revoked")
        self.assertEqual(entries[0]["outcome"], "success")

    def test_key_expired(self):
        self.log.key_expired(username="carol", file_id="data.csv")
        entries = self.log.query(action="key_expired")
        self.assertEqual(entries[0]["outcome"], "failure")


class TestFileEvents(unittest.TestCase):

    def setUp(self):
        self.log, self.db = make_logger()

    def tearDown(self):
        os.unlink(self.db)

    def test_encrypt_success(self):
        self.log.encrypt("admin", user_id=1, file_id="employees.csv", success=True)
        entries = self.log.query(action="encrypt")
        self.assertEqual(entries[0]["outcome"], "success")
        self.assertEqual(entries[0]["file_id"], "employees.csv")

    def test_encrypt_failure(self):
        self.log.encrypt("bob", file_id="secret.csv", success=False)
        entries = self.log.query(action="encrypt")
        self.assertEqual(entries[0]["outcome"], "failure")

    def test_decrypt_success(self):
        self.log.decrypt("admin", user_id=1, file_id="employees.csv.enc")
        entries = self.log.query(action="decrypt")
        self.assertEqual(entries[0]["outcome"], "success")

    def test_mask_success(self):
        self.log.mask("alice", user_id=2, file_id="employees.csv.enc")
        entries = self.log.query(action="mask")
        self.assertEqual(entries[0]["outcome"], "success")

    def test_mask_failure(self):
        self.log.mask("guest", file_id="employees.csv.enc", success=False)
        entries = self.log.query(action="mask")
        self.assertEqual(entries[0]["outcome"], "failure")


class TestRBACEvents(unittest.TestCase):

    def setUp(self):
        self.log, self.db = make_logger()

    def tearDown(self):
        os.unlink(self.db)

    def test_add_user_logged(self):
        self.log.add_user("admin", "newuser", target_role="Analyst")
        entries = self.log.query(action="add_user")
        self.assertEqual(len(entries), 1)
        self.assertIn("newuser", entries[0]["file_id"])
        self.assertIn("Analyst", entries[0]["file_id"])

    def test_remove_user_logged(self):
        self.log.remove_user("admin", "olduser")
        entries = self.log.query(action="remove_user")
        self.assertIn("olduser", entries[0]["file_id"])

    def test_assign_role_logged(self):
        self.log.assign_role("admin", "alice", "Admin")
        entries = self.log.query(action="assign_role")
        self.assertIn("alice", entries[0]["file_id"])
        self.assertIn("Admin", entries[0]["file_id"])


class TestPermissionDenied(unittest.TestCase):

    def setUp(self):
        self.log, self.db = make_logger()

    def tearDown(self):
        os.unlink(self.db)

    def test_denial_recorded(self):
        self.log.permission_denied("bob", action="decrypt", file_id="secret.enc")
        entries = self.log.query(username="bob")
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["outcome"], "failure")
        self.assertIn("decrypt", entries[0]["action"])

    def test_denial_action_prefixed(self):
        self.log.permission_denied("guest", action="mask")
        entries = self.log.query(username="guest")
        self.assertEqual(entries[0]["action"], "denied:mask")


class TestQuery(unittest.TestCase):

    def setUp(self):
        self.log, self.db = make_logger()
        self.log.login("alice", success=True)
        self.log.encrypt("alice", file_id="a.csv")
        self.log.mask("alice", file_id="a.csv.enc")
        self.log.login("bob", success=False)
        self.log.permission_denied("bob", action="decrypt")

    def tearDown(self):
        os.unlink(self.db)

    def test_query_all(self):
        entries = self.log.query()
        self.assertEqual(len(entries), 5)

    def test_filter_by_username(self):
        entries = self.log.query(username="alice")
        self.assertEqual(len(entries), 3)
        for e in entries:
            self.assertEqual(e["username"], "alice")

    def test_filter_by_action(self):
        entries = self.log.query(action="login")
        self.assertEqual(len(entries), 2)

    def test_filter_by_username_and_action(self):
        entries = self.log.query(username="alice", action="encrypt")
        self.assertEqual(len(entries), 1)

    def test_limit(self):
        entries = self.log.query(limit=2)
        self.assertEqual(len(entries), 2)

    def test_returns_oldest_first(self):
        entries = self.log.query()
        ids = [e["id"] for e in entries]
        self.assertEqual(ids, sorted(ids))

    def test_pid_recorded(self):
        entries = self.log.query(limit=1)
        self.assertIsInstance(entries[0]["pid"], int)
        self.assertGreater(entries[0]["pid"], 0)


def _make_db() -> str:
    """Create a fresh temp DB and return its path."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    init_db(path)
    return path


def _tamper(db_path: str, row_id: int, column: str, value) -> None:
    """Directly update a column in audit_log to simulate tampering."""
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            f"UPDATE audit_log SET {column} = ? WHERE id = ?",
            (value, row_id),
        )
        conn.commit()


class TestAuditChainIntegrity(unittest.TestCase):
    """HMAC chain covers all stored fields — tampering any field must be detected."""

    def setUp(self):
        self.db = _make_db()
        # Populate three entries with distinct field values
        append_audit("login",   "success", username="alice", user_id=1,  file_id=None,       pid=100, role="Admin",       db_path=self.db)
        append_audit("decrypt", "success", username="alice", user_id=1,  file_id="data.enc", pid=101, role="Admin",       db_path=self.db)
        append_audit("login",   "failure", username="bob",   user_id=2,  file_id=None,       pid=102, role="Contributor", db_path=self.db)

    def tearDown(self):
        os.unlink(self.db)

    def _first_row_id(self) -> int:
        with sqlite3.connect(self.db) as conn:
            return conn.execute("SELECT id FROM audit_log ORDER BY id ASC LIMIT 1").fetchone()[0]

    def _last_row_id(self) -> int:
        with sqlite3.connect(self.db) as conn:
            return conn.execute("SELECT id FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()[0]

    # --- intact chain ---

    def test_intact_chain_passes(self):
        self.assertTrue(verify_audit_chain(self.db))

    def test_empty_log_passes(self):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        init_db(path)
        try:
            self.assertTrue(verify_audit_chain(path))
        finally:
            os.unlink(path)

    # --- tamper fields already covered by old formula ---

    def test_tamper_action_detected(self):
        _tamper(self.db, self._first_row_id(), "action", "FORGED_ACTION")
        self.assertFalse(verify_audit_chain(self.db))

    def test_tamper_outcome_detected(self):
        _tamper(self.db, self._first_row_id(), "outcome", "failure")
        self.assertFalse(verify_audit_chain(self.db))

    def test_tamper_username_detected(self):
        _tamper(self.db, self._first_row_id(), "username", "attacker")
        self.assertFalse(verify_audit_chain(self.db))

    def test_tamper_pid_detected(self):
        _tamper(self.db, self._first_row_id(), "pid", 99999)
        self.assertFalse(verify_audit_chain(self.db))

    # --- tamper newly added fields ---

    def test_tamper_file_id_detected(self):
        _tamper(self.db, self._last_row_id(), "file_id", "injected.enc")
        self.assertFalse(verify_audit_chain(self.db))

    def test_tamper_role_detected(self):
        _tamper(self.db, self._first_row_id(), "role", "Guest")
        self.assertFalse(verify_audit_chain(self.db))

    def test_tamper_user_id_detected(self):
        _tamper(self.db, self._first_row_id(), "user_id", 999)
        self.assertFalse(verify_audit_chain(self.db))

    def test_tamper_timestamp_detected(self):
        _tamper(self.db, self._first_row_id(), "timestamp", "2000-01-01 00:00:00")
        self.assertFalse(verify_audit_chain(self.db))

    # --- tamper mid-chain propagates to all subsequent rows ---

    def test_tamper_middle_row_breaks_rest_of_chain(self):
        with sqlite3.connect(self.db) as conn:
            rows = conn.execute("SELECT id FROM audit_log ORDER BY id ASC").fetchall()
        mid_id = rows[1][0]
        _tamper(self.db, mid_id, "username", "tampered")
        self.assertFalse(verify_audit_chain(self.db))

    # --- chain_hash itself tampered ---

    def test_tamper_chain_hash_detected(self):
        _tamper(self.db, self._first_row_id(), "chain_hash", "deadbeef" * 8)
        self.assertFalse(verify_audit_chain(self.db))


class TestVerifyIncrementalChain(unittest.TestCase):
    """Unit tests for verify_audit_chain_incremental()."""

    def setUp(self):
        fd, self.db = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        init_db(self.db)

    def tearDown(self):
        try:
            os.unlink(self.db)
        except OSError:
            pass

    def test_empty_db_returns_true(self):
        ok, last_id, last_hash = verify_audit_chain_incremental(self.db)
        self.assertTrue(ok)
        self.assertEqual(last_id, 0)
        self.assertEqual(last_hash, "")

    def test_single_entry_verifies(self):
        append_audit("login", "success", username="alice", db_path=self.db)
        ok, last_id, last_hash = verify_audit_chain_incremental(self.db)
        self.assertTrue(ok)
        self.assertEqual(last_id, 1)
        self.assertTrue(last_hash)

    def test_multiple_entries_verify(self):
        for i in range(5):
            append_audit("action", "success", username=f"u{i}", db_path=self.db)
        ok, last_id, _ = verify_audit_chain_incremental(self.db)
        self.assertTrue(ok)
        self.assertEqual(last_id, 5)

    def test_incremental_resumes_from_last_id(self):
        append_audit("login", "success", username="alice", db_path=self.db)
        ok, last_id, last_hash = verify_audit_chain_incremental(self.db)
        self.assertTrue(ok)
        append_audit("logout", "success", username="alice", db_path=self.db)
        ok2, last_id2, _ = verify_audit_chain_incremental(
            self.db, last_id=last_id, last_hash=last_hash
        )
        self.assertTrue(ok2)
        self.assertEqual(last_id2, 2)

    def test_no_new_rows_returns_unchanged(self):
        append_audit("login", "success", username="alice", db_path=self.db)
        ok, last_id, last_hash = verify_audit_chain_incremental(self.db)
        ok2, last_id2, last_hash2 = verify_audit_chain_incremental(
            self.db, last_id=last_id, last_hash=last_hash
        )
        self.assertTrue(ok2)
        self.assertEqual(last_id2, last_id)
        self.assertEqual(last_hash2, last_hash)

    def test_tampered_first_entry_detected(self):
        append_audit("login", "success", username="alice", db_path=self.db)
        append_audit("logout", "success", username="alice", db_path=self.db)
        with sqlite3.connect(self.db) as conn:
            conn.execute("UPDATE audit_log SET chain_hash = 'badhash' WHERE id = 1")
        ok, _, _ = verify_audit_chain_incremental(self.db)
        self.assertFalse(ok)

    def test_tampered_later_entry_detected(self):
        for _ in range(3):
            append_audit("action", "success", username="user", db_path=self.db)
        with sqlite3.connect(self.db) as conn:
            conn.execute("UPDATE audit_log SET chain_hash = 'tampered' WHERE id = 3")
        ok, _, _ = verify_audit_chain_incremental(self.db)
        self.assertFalse(ok)

    def test_state_not_advanced_on_failure(self):
        for _ in range(3):
            append_audit("action", "success", username="user", db_path=self.db)
        with sqlite3.connect(self.db) as conn:
            conn.execute("UPDATE audit_log SET chain_hash = 'tampered' WHERE id = 2")
        ok, returned_id, returned_hash = verify_audit_chain_incremental(
            self.db, last_id=0, last_hash=""
        )
        self.assertFalse(ok)
        self.assertEqual(returned_id, 0)
        self.assertEqual(returned_hash, "")


class TestArchiveChmod(unittest.TestCase):
    """Verify that rotate_audit_log marks the archive file read-only."""

    def setUp(self):
        fd, self.db = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        init_db(self.db)
        self.log = AuditLogger(db_path=self.db)
        self._archives: list[str] = []

    def tearDown(self):
        import glob
        data_dir = os.path.dirname(self.db)
        for arc in glob.glob(os.path.join(data_dir, "audit_*.db")):
            try:
                os.chmod(arc, 0o644)
                os.unlink(arc)
            except OSError:
                pass
        try:
            os.unlink(self.db)
        except OSError:
            pass

    @unittest.skipIf(sys.platform == "win32", "chmod is a no-op on Windows")
    def test_archive_is_readonly_after_rotation(self):
        self.log.login("alice", user_id=1, success=True)
        archive_name = self.log.rotate(username="admin")
        archive_path = os.path.join(os.path.dirname(self.db), archive_name)
        mode = os.stat(archive_path).st_mode & 0o777
        self.assertEqual(mode, 0o444)

    @unittest.skipIf(sys.platform == "win32", "chmod is a no-op on Windows")
    def test_multiple_rotations_each_archive_readonly(self):
        for i in range(3):
            self.log.login(f"u{i}", user_id=i, success=True)
            archive_name = self.log.rotate(username="admin")
            archive_path = os.path.join(os.path.dirname(self.db), archive_name)
            mode = os.stat(archive_path).st_mode & 0o777
            self.assertEqual(mode, 0o444, f"Archive {archive_name} not read-only")


class TestClientTamperAlert(unittest.TestCase):
    """Verify _print_tamper_alert writes to stderr without raising."""

    def setUp(self):
        # Insert client_pkg into sys.path
        from pathlib import Path
        client_pkg = str(Path(__file__).parent.parent / "client_pkg")
        if client_pkg not in sys.path:
            sys.path.insert(0, client_pkg)

    def test_print_tamper_alert_writes_to_stderr(self):
        import io
        from client.client import _print_tamper_alert
        buf = io.StringIO()
        alert = {"detected_at": "2026-01-01 00:00:00 UTC", "message": "TEST ALERT", "mode": "incremental"}
        orig_stderr = sys.stderr
        sys.stderr = buf
        try:
            _print_tamper_alert(alert)
        finally:
            sys.stderr = orig_stderr
        output = buf.getvalue()
        self.assertIn("TAMPERING", output)
        self.assertIn("2026-01-01 00:00:00 UTC", output)

    def test_print_tamper_alert_missing_fields_no_crash(self):
        from client.client import _print_tamper_alert
        import io
        buf = io.StringIO()
        orig_stderr = sys.stderr
        sys.stderr = buf
        try:
            _print_tamper_alert({})
        finally:
            sys.stderr = orig_stderr
        self.assertIn("TAMPERING", buf.getvalue())


class TestAuditIntegrityMonitor(unittest.TestCase):
    """Functional tests for the _AuditIntegrityMonitor daemon."""

    def setUp(self):
        import server.server as srv_mod
        self.srv_mod = srv_mod
        with srv_mod._audit_tamper_lock:
            srv_mod._audit_tamper_alert.clear()
        fd, self.db = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        init_db(self.db)
        self._rotating = threading.Event()

    def tearDown(self):
        with self.srv_mod._audit_tamper_lock:
            self.srv_mod._audit_tamper_alert.clear()
        try:
            os.unlink(self.db)
        except OSError:
            pass

    def _make_monitor(self, interval: float = 0.1, full_every: int = 100):
        return self.srv_mod._AuditIntegrityMonitor(
            db_path=self.db,
            interval_seconds=interval,
            full_scan_every_n_polls=full_every,
            audit_rotating_event=self._rotating,
        )

    def test_clean_chain_raises_no_alert(self):
        for _ in range(3):
            append_audit("action", "success", username="user", db_path=self.db)
        mon = self._make_monitor()
        time.sleep(0.4)
        mon.stop()
        with self.srv_mod._audit_tamper_lock:
            self.assertFalse(self.srv_mod._audit_tamper_alert)

    def test_tampered_chain_sets_alert(self):
        for _ in range(3):
            append_audit("action", "success", username="user", db_path=self.db)
        with sqlite3.connect(self.db) as conn:
            conn.execute("UPDATE audit_log SET chain_hash = 'forged' WHERE id = 2")
        mon = self._make_monitor(interval=0.1)
        time.sleep(0.5)
        mon.stop()
        with self.srv_mod._audit_tamper_lock:
            alert = dict(self.srv_mod._audit_tamper_alert)
        self.assertTrue(alert)
        self.assertIn("detected_at", alert)
        self.assertIn("message", alert)

    def test_reset_clears_alert(self):
        for _ in range(2):
            append_audit("action", "success", username="user", db_path=self.db)
        with sqlite3.connect(self.db) as conn:
            conn.execute("UPDATE audit_log SET chain_hash = 'forged' WHERE id = 1")
        mon = self._make_monitor(interval=0.1)
        time.sleep(0.5)
        mon.stop()
        with self.srv_mod._audit_tamper_lock:
            self.assertTrue(self.srv_mod._audit_tamper_alert)
        mon.reset()
        with self.srv_mod._audit_tamper_lock:
            self.assertFalse(self.srv_mod._audit_tamper_alert)

    def test_monitor_skips_while_rotating(self):
        for _ in range(3):
            append_audit("action", "success", username="user", db_path=self.db)
        with sqlite3.connect(self.db) as conn:
            conn.execute("UPDATE audit_log SET chain_hash = 'forged' WHERE id = 2")
        self._rotating.set()
        mon = self._make_monitor(interval=0.1)
        time.sleep(0.5)
        mon.stop()
        with self.srv_mod._audit_tamper_lock:
            self.assertFalse(self.srv_mod._audit_tamper_alert)
        self._rotating.clear()

    def test_full_scan_detects_retroactive_tamper(self):
        for _ in range(5):
            append_audit("action", "success", username="user", db_path=self.db)
        # Establish incremental baseline (full_every=100 means only incremental)
        mon = self._make_monitor(interval=0.1, full_every=100)
        time.sleep(0.3)
        mon.stop()
        # Tamper a past entry that the incremental already passed
        with sqlite3.connect(self.db) as conn:
            conn.execute(
                "UPDATE audit_log SET chain_hash = 'retroactive' WHERE id = 3"
            )
        with self.srv_mod._audit_tamper_lock:
            self.srv_mod._audit_tamper_alert.clear()
        # New monitor with full_every=1 forces a full scan on first poll
        mon2 = self._make_monitor(interval=0.1, full_every=1)
        time.sleep(0.5)
        mon2.stop()
        with self.srv_mod._audit_tamper_lock:
            self.assertTrue(self.srv_mod._audit_tamper_alert)


if __name__ == "__main__":
    unittest.main(verbosity=2)
