"""
Unit tests for core/db.py and server/access_control.py.
Each test class uses a fresh in-memory/temp SQLite DB to remain isolated.
"""

import os
import sys
import sqlite3
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.db import init_db, get_role, list_roles, get_user, list_users, append_audit, query_audit
from server.access_control import (
    hash_password,
    verify_password,
    check_permission,
    add_user,
    assign_role,
    remove_user,
    authenticate,
    list_users as ac_list_users,
    list_roles as ac_list_roles,
)


def make_db() -> str:
    """Create a fresh temp DB file, initialize schema, return its path."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    init_db(path)
    return path


class TestDBInit(unittest.TestCase):

    def test_init_creates_tables(self):
        db = make_db()
        try:
            roles = list_roles(db)
            names = {r["name"] for r in roles}
            self.assertIn("Admin", names)
            self.assertIn("Analyst", names)
            self.assertIn("Guest", names)
        finally:
            os.unlink(db)

    def test_init_is_idempotent(self):
        db = make_db()
        try:
            init_db(db)   # second call must not raise
            roles = list_roles(db)
            self.assertEqual(len(roles), 6)
        finally:
            os.unlink(db)

    def test_admin_permissions(self):
        db = make_db()
        try:
            role = get_role("Admin", db)
            for perm in ["encrypt", "decrypt", "mask", "manage_users", "view_audit"]:
                self.assertIn(perm, role["permissions"])
        finally:
            os.unlink(db)

    def test_analyst_permissions(self):
        db = make_db()
        try:
            role = get_role("Analyst", db)
            self.assertIn("mask", role["permissions"])
            self.assertNotIn("decrypt", role["permissions"])
            self.assertNotIn("manage_users", role["permissions"])
        finally:
            os.unlink(db)

    def test_guest_permissions(self):
        db = make_db()
        try:
            role = get_role("Guest", db)
            self.assertIn("list", role["permissions"])
            self.assertNotIn("mask", role["permissions"])
            self.assertNotIn("decrypt", role["permissions"])
        finally:
            os.unlink(db)


class TestPasswordHashing(unittest.TestCase):

    def test_hash_returns_string(self):
        h = hash_password("secret")
        self.assertIsInstance(h, str)

    def test_hash_starts_with_scrypt(self):
        h = hash_password("secret")
        self.assertTrue(h.startswith("scrypt:"))

    def test_verify_correct_password(self):
        h = hash_password("correct_password")
        self.assertTrue(verify_password("correct_password", h))

    def test_verify_wrong_password(self):
        h = hash_password("correct_password")
        self.assertFalse(verify_password("wrong_password", h))

    def test_two_hashes_of_same_password_differ(self):
        h1 = hash_password("password")
        h2 = hash_password("password")
        self.assertNotEqual(h1, h2)  # different salts

    def test_verify_malformed_hash_returns_false(self):
        self.assertFalse(verify_password("any", "notahash"))
        self.assertFalse(verify_password("any", ""))
        self.assertFalse(verify_password("any", "bcrypt:$2b$..."))


class TestAddUser(unittest.TestCase):

    def setUp(self):
        self.db = make_db()

    def tearDown(self):
        os.unlink(self.db)

    def test_add_user_success(self):
        result = add_user("alice", "pass123", role="Analyst", db_path=self.db)
        self.assertEqual(result["username"], "alice")
        self.assertEqual(result["role"], "Analyst")

    def test_added_user_exists_in_db(self):
        add_user("bob", "pass123", role="Guest", db_path=self.db)
        user = get_user("bob", self.db)
        self.assertIsNotNone(user)
        self.assertEqual(user["role"], "Guest")

    def test_password_stored_as_hash(self):
        add_user("carol", "secret", role="Guest", db_path=self.db)
        user = get_user("carol", self.db)
        self.assertNotEqual(user["password_hash"], "secret")
        self.assertTrue(user["password_hash"].startswith("scrypt:"))

    def test_duplicate_username_raises(self):
        add_user("dave", "pass", role="Guest", db_path=self.db)
        with self.assertRaises(sqlite3.IntegrityError):
            add_user("dave", "other", role="Guest", db_path=self.db)

    def test_invalid_role_raises(self):
        with self.assertRaises(ValueError):
            add_user("eve", "pass", role="superuser", db_path=self.db)

    def test_default_role_is_guest(self):
        add_user("frank", "pass", db_path=self.db)
        user = get_user("frank", self.db)
        self.assertEqual(user["role"], "Guest")


class TestAssignRole(unittest.TestCase):

    def setUp(self):
        self.db = make_db()
        add_user("alice", "pass", role="Guest", db_path=self.db)

    def tearDown(self):
        os.unlink(self.db)

    def test_assign_valid_role(self):
        result = assign_role("alice", "Analyst", db_path=self.db)
        self.assertTrue(result)
        user = get_user("alice", self.db)
        self.assertEqual(user["role"], "Analyst")

    def test_assign_invalid_role_raises(self):
        with self.assertRaises(ValueError):
            assign_role("alice", "superuser", db_path=self.db)

    def test_assign_to_nonexistent_user_returns_false(self):
        result = assign_role("nobody", "Analyst", db_path=self.db)
        self.assertFalse(result)


class TestRemoveUser(unittest.TestCase):

    def setUp(self):
        self.db = make_db()
        add_user("alice", "pass", role="Guest", db_path=self.db)

    def tearDown(self):
        os.unlink(self.db)

    def test_remove_existing_user(self):
        result = remove_user("alice", db_path=self.db)
        self.assertTrue(result)
        self.assertIsNone(get_user("alice", self.db))

    def test_remove_nonexistent_user_returns_false(self):
        result = remove_user("ghost", db_path=self.db)
        self.assertFalse(result)


class TestAuthenticate(unittest.TestCase):

    def setUp(self):
        self.db = make_db()
        add_user("alice", "correct_pass", role="Analyst", db_path=self.db)

    def tearDown(self):
        os.unlink(self.db)

    def test_correct_credentials_returns_user(self):
        result = authenticate("alice", "correct_pass", db_path=self.db)
        self.assertIsNotNone(result)
        self.assertEqual(result["username"], "alice")

    def test_password_hash_not_in_returned_dict(self):
        result = authenticate("alice", "correct_pass", db_path=self.db)
        self.assertNotIn("password_hash", result)

    def test_wrong_password_returns_none(self):
        result = authenticate("alice", "wrong_pass", db_path=self.db)
        self.assertIsNone(result)

    def test_unknown_user_returns_none(self):
        result = authenticate("nobody", "pass", db_path=self.db)
        self.assertIsNone(result)


class TestCheckPermission(unittest.TestCase):

    def setUp(self):
        self.db = make_db()
        add_user("admin_user", "pass", role="Admin", db_path=self.db)
        add_user("analyst_user", "pass", role="Analyst", db_path=self.db)
        add_user("guest_user", "pass", role="Guest", db_path=self.db)

    def tearDown(self):
        os.unlink(self.db)

    # Admin boundaries
    def test_admin_can_encrypt(self):
        self.assertTrue(check_permission("admin_user", "encrypt", self.db))

    def test_admin_can_decrypt(self):
        self.assertTrue(check_permission("admin_user", "decrypt", self.db))

    def test_admin_can_mask(self):
        self.assertTrue(check_permission("admin_user", "mask", self.db))

    def test_admin_can_manage_users(self):
        self.assertTrue(check_permission("admin_user", "manage_users", self.db))

    def test_admin_can_view_audit(self):
        self.assertTrue(check_permission("admin_user", "view_audit", self.db))

    # Analyst boundaries
    def test_analyst_can_mask(self):
        self.assertTrue(check_permission("analyst_user", "mask", self.db))

    def test_analyst_cannot_decrypt(self):
        self.assertFalse(check_permission("analyst_user", "decrypt", self.db))

    def test_analyst_cannot_encrypt(self):
        self.assertFalse(check_permission("analyst_user", "encrypt", self.db))

    def test_analyst_cannot_manage_users(self):
        self.assertFalse(check_permission("analyst_user", "manage_users", self.db))

    def test_analyst_cannot_view_audit(self):
        self.assertFalse(check_permission("analyst_user", "view_audit", self.db))

    # Guest boundaries
    def test_guest_can_list(self):
        self.assertTrue(check_permission("guest_user", "list", self.db))

    def test_guest_cannot_mask(self):
        self.assertFalse(check_permission("guest_user", "mask", self.db))

    def test_guest_cannot_decrypt(self):
        self.assertFalse(check_permission("guest_user", "decrypt", self.db))

    # Unknown user
    def test_unknown_user_denied(self):
        self.assertFalse(check_permission("nobody", "mask", self.db))

    # Dynamic role change takes effect immediately
    def test_role_change_reflected_in_permission(self):
        self.assertFalse(check_permission("guest_user", "mask", self.db))
        assign_role("guest_user", "Analyst", db_path=self.db)
        self.assertTrue(check_permission("guest_user", "mask", self.db))


class TestListUsersAndRoles(unittest.TestCase):

    def setUp(self):
        self.db = make_db()
        add_user("alice", "pass", role="Analyst", db_path=self.db)
        add_user("bob", "pass", role="Guest", db_path=self.db)

    def tearDown(self):
        os.unlink(self.db)

    def test_list_users_returns_all(self):
        users = ac_list_users(self.db)
        names = {u["username"] for u in users}
        self.assertIn("alice", names)
        self.assertIn("bob", names)

    def test_list_users_excludes_password_hash(self):
        users = ac_list_users(self.db)
        for u in users:
            self.assertNotIn("password_hash", u)

    def test_list_roles_returns_six(self):
        roles = ac_list_roles(self.db)
        self.assertEqual(len(roles), 6)


class TestAuditLog(unittest.TestCase):

    def setUp(self):
        self.db = make_db()

    def tearDown(self):
        os.unlink(self.db)

    def test_login_success_logged(self):
        add_user("alice", "pass", role="Analyst", db_path=self.db)
        authenticate("alice", "pass", db_path=self.db)
        logs = query_audit(username="alice", action="login", db_path=self.db)
        outcomes = {l["outcome"] for l in logs}
        self.assertIn("success", outcomes)

    def test_login_failure_logged(self):
        add_user("alice", "pass", role="Analyst", db_path=self.db)
        authenticate("alice", "wrong", db_path=self.db)
        logs = query_audit(username="alice", action="login", db_path=self.db)
        outcomes = {l["outcome"] for l in logs}
        self.assertIn("failure", outcomes)

    def test_add_user_logged(self):
        # audit logging for add_user is done by the server handler, not access_control.add_user
        append_audit("add_user", "success", username="admin",
                     file_id="user:bob role:Guest", db_path=self.db)
        logs = query_audit(action="add_user", db_path=self.db)
        self.assertGreater(len(logs), 0)

    def test_query_limit(self):
        for i in range(10):
            append_audit("test_action", "success", username=f"u{i}", db_path=self.db)
        logs = query_audit(limit=3, db_path=self.db)
        self.assertEqual(len(logs), 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
