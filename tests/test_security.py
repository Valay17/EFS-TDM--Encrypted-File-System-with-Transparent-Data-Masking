"""
Security-focused regression tests.

Covers: admin self-deletion guard, role escalation prevention, audit chain
integrity (single and cross-archive), archive tampering detection, and
masking-rules validation.
"""

import hashlib
import hmac
import os
import stat
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.db import (
    init_db, append_audit, get_user, verify_audit_chain,
    verify_audit_chain_across, rotate_audit_log, get_conn,
)
from core.masking import _validate_rules, load_rules
from server.access_control import add_user, assign_role, hash_password
from server.server import EFSServer

CERT_PATH = os.path.join(os.path.dirname(__file__), "..", "server_pkg", "certs", "cert.pem")
KEY_PATH = os.path.join(os.path.dirname(__file__), "..", "server_pkg", "certs", "key.pem")


def make_db() -> str:
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    init_db(path)
    return path


def make_server(db_path: str, data_enc=None) -> EFSServer:
    from pathlib import Path
    return EFSServer(
        host="127.0.0.1",
        port=19999,
        cert=CERT_PATH,
        key=KEY_PATH,
        db_path=db_path,
        data_enc=Path(data_enc) if data_enc else None,
    )


def make_admin_session(username: str, user_id: int) -> dict:
    return {
        "username": username,
        "user_id": user_id,
        "role": "Admin",
        "expires": 9999999999,
    }


def make_session(username: str, user_id: int, role: str) -> dict:
    return {
        "username": username,
        "user_id": user_id,
        "role": role,
        "expires": 9999999999,
    }


class TestAdminSelfDeletion(unittest.TestCase):

    def setUp(self):
        self.db = make_db()
        self._enc_dir = tempfile.TemporaryDirectory()
        add_user("adminuser", "Admin1234!", "Admin", self.db)
        user = get_user("adminuser", self.db)
        self.server = make_server(self.db, self._enc_dir.name)
        self.session = make_admin_session("adminuser", user["id"])

    def tearDown(self):
        self.server.km.stop()
        os.unlink(self.db)
        self._enc_dir.cleanup()

    def test_remove_user_self_blocked(self):
        req = {"cmd": "remove_user", "username": "adminuser"}
        result = self.server._handle_remove_user(req, self.session)
        self.assertFalse(result["ok"])
        self.assertIn("Cannot delete your own account", result["error"])

    def test_admin_self_deletion_blocked(self):
        req = {"cmd": "delete_account", "password": "Admin1234!", "session": "tok"}
        result = self.server._handle_delete_account(req, self.session)
        self.assertFalse(result["ok"])
        self.assertIn("Admin accounts cannot be self-deleted", result["error"])


class TestRoleEscalation(unittest.TestCase):

    def setUp(self):
        self.db = make_db()
        self._enc_dir = tempfile.TemporaryDirectory()
        add_user("adminuser", "Admin1234!", "Admin", self.db)
        add_user("contrib", "Contrib1!", "Contributor", self.db)
        self.admin_user = get_user("adminuser", self.db)
        self.contrib_user = get_user("contrib", self.db)
        self.server = make_server(self.db, self._enc_dir.name)

    def tearDown(self):
        self.server.km.stop()
        os.unlink(self.db)
        self._enc_dir.cleanup()

    def test_non_admin_cannot_assign_admin_role(self):
        assign_role("contrib", "Contributor", self.db)
        with get_conn(self.db) as conn:
            conn.execute(
                "UPDATE roles SET permissions_json = json_insert(permissions_json, '$[#]', 'manage_users') "
                "WHERE name = 'Contributor'"
            )
        session = make_session("contrib", self.contrib_user["id"], "Contributor")
        req = {"cmd": "assign_role", "username": "adminuser", "role": "Admin"}
        result = self.server._handle_assign_role(req, session)
        self.assertFalse(result["ok"])
        self.assertIn("Only admins can assign the Admin role", result["error"])

    def test_reset_password_self_blocked(self):
        session = make_admin_session("adminuser", self.admin_user["id"])
        req = {"cmd": "reset_password", "username": "adminuser", "new_password": "NewPass1!"}
        result = self.server._handle_reset_password(req, session)
        self.assertFalse(result["ok"])
        self.assertIn("Use change_password to change your own password", result["error"])


class TestAuditChain(unittest.TestCase):

    def setUp(self):
        self.db = make_db()

    def tearDown(self):
        os.unlink(self.db)

    def test_chain_populated(self):
        append_audit("login", "success", username="alice", db_path=self.db)
        append_audit("encrypt", "success", username="alice", db_path=self.db)
        with get_conn(self.db) as conn:
            rows = conn.execute("SELECT chain_hash FROM audit_log ORDER BY id ASC").fetchall()
        for row in rows:
            self.assertIsNotNone(row["chain_hash"])
            self.assertNotEqual(row["chain_hash"], "")

    def test_chain_verifies(self):
        append_audit("login", "success", username="bob", db_path=self.db)
        append_audit("decrypt", "failure", username="bob", db_path=self.db)
        self.assertTrue(verify_audit_chain(self.db))

    def test_chain_detects_tamper(self):
        append_audit("login", "success", username="carol", db_path=self.db)
        append_audit("mask", "success", username="carol", db_path=self.db)
        with get_conn(self.db) as conn:
            conn.execute(
                "UPDATE audit_log SET chain_hash = 'deadbeef' WHERE id = (SELECT MIN(id) FROM audit_log)"
            )
        self.assertFalse(verify_audit_chain(self.db))


class TestAuditChainCrossArchive(unittest.TestCase):
    """Verify cross-archive audit chain continuity after rotation."""

    def setUp(self):
        self.db = make_db()
        self._archive_paths = []

    def tearDown(self):
        for p in self._archive_paths:
            try:
                os.unlink(p)
            except FileNotFoundError:
                pass
        try:
            os.unlink(self.db)
        except FileNotFoundError:
            pass

    def _rotate(self):
        archive_name = rotate_audit_log(self.db)
        archive_path = str(Path(self.db).parent / archive_name)
        self._archive_paths.append(archive_path)
        return archive_path

    def test_single_rotation_chain_intact(self):
        append_audit("login", "success", username="alice", db_path=self.db)
        append_audit("encrypt", "success", username="alice", db_path=self.db)
        archive = self._rotate()
        append_audit("decrypt", "success", username="alice", db_path=self.db)

        ok, msg = verify_audit_chain_across([archive, self.db])
        self.assertTrue(ok, msg)

    def test_multiple_rotations_chain_intact(self):
        append_audit("login", "success", username="alice", db_path=self.db)
        archive1 = self._rotate()
        append_audit("mask", "success", username="bob", db_path=self.db)
        archive2 = self._rotate()
        append_audit("whoami", "success", username="carol", db_path=self.db)

        ok, msg = verify_audit_chain_across([archive1, archive2, self.db])
        self.assertTrue(ok, msg)

    def test_tampered_archive_detected(self):
        append_audit("login", "success", username="alice", db_path=self.db)
        archive = self._rotate()
        append_audit("decrypt", "success", username="alice", db_path=self.db)

        # Temporarily make archive writable to simulate tampering
        os.chmod(archive, stat.S_IRUSR | stat.S_IWUSR)
        with get_conn(archive) as conn:
            conn.execute(
                "UPDATE audit_log SET chain_hash = 'deadbeef' WHERE id = (SELECT MAX(id) FROM audit_log)"
            )
        os.chmod(archive, 0o444)

        ok, msg = verify_audit_chain_across([archive, self.db])
        self.assertFalse(ok, "Tampered archive should fail cross-archive verification")

    def test_deleted_archive_detected(self):
        append_audit("login", "success", username="alice", db_path=self.db)
        archive1 = self._rotate()
        append_audit("mask", "success", username="bob", db_path=self.db)
        archive2 = self._rotate()
        append_audit("whoami", "success", username="carol", db_path=self.db)

        # Skip archive1 — simulates deletion
        ok, msg = verify_audit_chain_across([archive2, self.db])
        # archive2's bootstrap entry references archive1's hash which won't match
        # a fresh chain starting from "" — so it must fail
        self.assertFalse(ok, "Missing archive should fail cross-archive verification")

    def test_empty_live_log_with_archive(self):
        append_audit("login", "success", username="alice", db_path=self.db)
        archive = self._rotate()
        # No new entries in live log yet — just the bootstrap entry

        ok, msg = verify_audit_chain_across([archive, self.db])
        self.assertTrue(ok, msg)


class TestMaskingRulesValidation(unittest.TestCase):

    def test_valid_rules_load(self):
        rules = load_rules()
        self.assertIn("rules", rules)
        self.assertIn("role_profiles", rules)

    def test_missing_rules_key_raises(self):
        with self.assertRaises(ValueError):
            _validate_rules({"role_profiles": {}})

    def test_invalid_rule_missing_pattern(self):
        config = {
            "rules": {"bad_rule": {"replacement": "***"}},
            "role_profiles": {},
        }
        with self.assertRaises(ValueError):
            _validate_rules(config)


if __name__ == "__main__":
    unittest.main()
