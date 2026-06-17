"""
Regression tests for config-driven behavior.

Pins down the behavior of roles, permissions, password policy, audit
auto-rotation, and ACL rules as defined in roles.json and server_config.json.
"""

import base64
import datetime
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from core.db import (
    init_db, get_role, list_roles, append_audit, append_audit_with_config,
    query_audit, rotate_audit_log, ensure_root, set_acl, get_acl,
)
from core.vfs import check_acl, mkdir, resolve_path
from server.access_control import (
    add_user, assign_role, check_permission, authenticate,
    VALID_ROLES,
)
from server.server import _validate_password


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_db() -> str:
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    init_db(path)
    return path


# ===================================================================
# 1. Roles and permissions (currently hardcoded in BUILT_IN_ROLES)
# ===================================================================

class TestBuiltInRoles(unittest.TestCase):
    """Verify the 6 built-in roles and their exact permissions."""

    def setUp(self):
        self.db = make_db()

    def tearDown(self):
        os.unlink(self.db)

    def test_six_roles_exist(self):
        roles = list_roles(self.db)
        self.assertEqual(len(roles), 6)

    def test_role_names(self):
        roles = list_roles(self.db)
        names = {r["name"] for r in roles}
        self.assertEqual(names, {"Admin", "Analyst", "Contributor", "Viewer", "Auditor", "Guest"})

    def test_admin_has_all_permissions(self):
        role = get_role("Admin", self.db)
        expected = {"list", "read", "write", "delete_own", "delete_any",
                    "mask", "export_raw", "manage_permissions", "manage_users",
                    "view_audit", "encrypt", "decrypt"}
        self.assertEqual(set(role["permissions"]), expected)

    def test_analyst_permissions(self):
        role = get_role("Analyst", self.db)
        self.assertEqual(set(role["permissions"]), {"list", "read", "mask"})

    def test_contributor_permissions(self):
        role = get_role("Contributor", self.db)
        self.assertEqual(set(role["permissions"]), {"list", "read", "write", "delete_own"})

    def test_viewer_permissions(self):
        role = get_role("Viewer", self.db)
        self.assertEqual(set(role["permissions"]), {"list", "read"})

    def test_auditor_permissions(self):
        role = get_role("Auditor", self.db)
        self.assertEqual(set(role["permissions"]), {"view_audit"})

    def test_guest_permissions(self):
        role = get_role("Guest", self.db)
        self.assertEqual(set(role["permissions"]), {"list"})


class TestValidRoles(unittest.TestCase):
    """VALID_ROLES must match the roles in the database."""

    def setUp(self):
        self.db = make_db()

    def tearDown(self):
        os.unlink(self.db)

    def test_valid_roles_matches_db(self):
        db_roles = {r["name"] for r in list_roles(self.db)}
        self.assertEqual(VALID_ROLES, db_roles)

    def test_add_user_rejects_unknown_role(self):
        with self.assertRaises(ValueError):
            add_user("bad", "StrongPass1!", role="SuperUser", db_path=self.db)

    def test_add_user_accepts_all_valid_roles(self):
        for i, role in enumerate(sorted(VALID_ROLES)):
            result = add_user(f"user{i}", "StrongPass1!", role=role, db_path=self.db)
            self.assertEqual(result["role"], role)


class TestPermissionEnforcement(unittest.TestCase):
    """check_permission must enforce role-based access correctly."""

    def setUp(self):
        self.db = make_db()
        add_user("admin_u", "StrongPass1!", role="Admin", db_path=self.db)
        add_user("analyst_u", "StrongPass1!", role="Analyst", db_path=self.db)
        add_user("viewer_u", "StrongPass1!", role="Viewer", db_path=self.db)
        add_user("guest_u", "StrongPass1!", role="Guest", db_path=self.db)
        add_user("auditor_u", "StrongPass1!", role="Auditor", db_path=self.db)
        add_user("contrib_u", "StrongPass1!", role="Contributor", db_path=self.db)

    def tearDown(self):
        os.unlink(self.db)

    # Admin can do everything
    def test_admin_can_manage_users(self):
        self.assertTrue(check_permission("admin_u", "manage_users", self.db))

    def test_admin_can_export_raw(self):
        self.assertTrue(check_permission("admin_u", "export_raw", self.db))

    # Analyst boundaries
    def test_analyst_can_mask(self):
        self.assertTrue(check_permission("analyst_u", "mask", self.db))

    def test_analyst_cannot_write(self):
        self.assertFalse(check_permission("analyst_u", "write", self.db))

    def test_analyst_cannot_manage_users(self):
        self.assertFalse(check_permission("analyst_u", "manage_users", self.db))

    # Viewer boundaries
    def test_viewer_can_read(self):
        self.assertTrue(check_permission("viewer_u", "read", self.db))

    def test_viewer_cannot_write(self):
        self.assertFalse(check_permission("viewer_u", "write", self.db))

    def test_viewer_cannot_mask(self):
        self.assertFalse(check_permission("viewer_u", "mask", self.db))

    # Guest boundaries
    def test_guest_can_list(self):
        self.assertTrue(check_permission("guest_u", "list", self.db))

    def test_guest_cannot_read(self):
        self.assertFalse(check_permission("guest_u", "read", self.db))

    # Auditor boundaries
    def test_auditor_can_view_audit(self):
        self.assertTrue(check_permission("auditor_u", "view_audit", self.db))

    def test_auditor_cannot_read(self):
        self.assertFalse(check_permission("auditor_u", "read", self.db))

    # Contributor boundaries
    def test_contributor_can_write(self):
        self.assertTrue(check_permission("contrib_u", "write", self.db))

    def test_contributor_can_delete_own(self):
        self.assertTrue(check_permission("contrib_u", "delete_own", self.db))

    def test_contributor_cannot_delete_any(self):
        self.assertFalse(check_permission("contrib_u", "delete_any", self.db))

    def test_contributor_cannot_manage_users(self):
        self.assertFalse(check_permission("contrib_u", "manage_users", self.db))


# ===================================================================
# 2. Password policy (currently hardcoded)
# ===================================================================

class TestPasswordPolicy(unittest.TestCase):
    """Pin down current password validation rules."""

    def test_short_password_rejected(self):
        err = _validate_password("Ab1!xy")
        self.assertIsNotNone(err)

    def test_exactly_8_chars_accepted(self):
        err = _validate_password("Abcdef1!")
        self.assertIsNone(err)

    def test_no_uppercase_rejected(self):
        err = _validate_password("abcdefg1!")
        self.assertIsNotNone(err)

    def test_no_lowercase_rejected(self):
        err = _validate_password("ABCDEFG1!")
        self.assertIsNotNone(err)

    def test_no_digit_rejected(self):
        err = _validate_password("Abcdefgh!")
        self.assertIsNotNone(err)

    def test_no_special_char_rejected(self):
        err = _validate_password("Abcdefg1")
        self.assertIsNotNone(err)

    def test_strong_password_accepted(self):
        err = _validate_password("MyStr0ng!Pass")
        self.assertIsNone(err)


# ===================================================================
# 3. Session TTL (currently 1800)
# ===================================================================

class TestSessionTTL(unittest.TestCase):
    """Session TTL constant must be 1800 seconds (30 min)."""

    def test_session_ttl_value(self):
        from server.server import SESSION_TTL
        self.assertEqual(SESSION_TTL, 1800)


# ===================================================================
# 4. File size limit (currently 50 MB)
# ===================================================================

class TestFileSizeLimit(unittest.TestCase):
    """Max payload must be 50 MB."""

    def test_max_payload_value(self):
        from server.server import MAX_PAYLOAD_BYTES
        self.assertEqual(MAX_PAYLOAD_BYTES, 50 * 1024 * 1024)


# ===================================================================
# 5. Rate limiting constants
# ===================================================================

class TestRateLimitConstants(unittest.TestCase):
    """Pin down current rate limiting values."""

    def test_login_window(self):
        from server.server import _LOGIN_WINDOW
        self.assertEqual(_LOGIN_WINDOW, 300)

    def test_login_max_fails(self):
        from server.server import _LOGIN_MAX_FAILS
        self.assertEqual(_LOGIN_MAX_FAILS, 10)

    def test_vfs_bucket_capacity(self):
        from server.server import _VFS_BUCKET_CAPACITY
        self.assertEqual(_VFS_BUCKET_CAPACITY, 60)

    def test_vfs_refill_rate(self):
        from server.server import _VFS_REFILL_RATE
        self.assertEqual(_VFS_REFILL_RATE, 10.0)


# ===================================================================
# 6. Default role (currently "Guest")
# ===================================================================

class TestDefaultRole(unittest.TestCase):
    """New users without explicit role should get 'Guest'."""

    def setUp(self):
        self.db = make_db()

    def tearDown(self):
        os.unlink(self.db)

    def test_add_user_default_role_is_guest(self):
        from core.db import get_user
        add_user("defaultuser", "StrongPass1!", db_path=self.db)
        user = get_user("defaultuser", self.db)
        self.assertEqual(user["role"], "Guest")


# ===================================================================
# 7. ACL behavior (currently open-by-default)
# ===================================================================

class TestAclBehavior(unittest.TestCase):
    """ACL is only enforced when ACL entries exist on an inode."""

    def setUp(self):
        self.db = make_db()
        ensure_root(self.db)
        self.dir_id = mkdir("/acltest", "/", "admin", self.db)

    def tearDown(self):
        os.unlink(self.db)

    def test_no_acl_means_open_access(self):
        """Without any ACL, check_acl returns False (no entry found),
        but server skips ACL check entirely when get_acl returns empty."""
        acl = get_acl(self.dir_id, self.db)
        self.assertEqual(acl, [])

    def test_admin_always_passes_acl(self):
        self.assertTrue(check_acl(self.dir_id, "Admin", "read", self.db))

    def test_non_admin_denied_in_closed_mode_without_grant(self):
        # In closed mode, no matching ACL entry means denied
        self.assertFalse(check_acl(self.dir_id, "Viewer", "read", self.db,
                                   default_mode="closed"))

    def test_open_mode_allows_when_no_matching_acl(self):
        set_acl(self.dir_id, "Analyst", "write", self.db)
        # Viewer has no ACL entry for "read" — open mode allows
        self.assertTrue(check_acl(self.dir_id, "Viewer", "read", self.db,
                                  default_mode="open"))

    def test_explicit_grant_allows_access(self):
        set_acl(self.dir_id, "Viewer", "read", self.db)
        self.assertTrue(check_acl(self.dir_id, "Viewer", "read", self.db))


# ===================================================================
# 8. Audit log behavior
# ===================================================================

class TestAuditLogBehavior(unittest.TestCase):
    """Audit log query and rotation behavior."""

    def setUp(self):
        self.db_dir = tempfile.mkdtemp()
        self.db = os.path.join(self.db_dir, "test.db")
        init_db(self.db)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.db_dir, ignore_errors=True)

    def test_default_query_limit_is_100(self):
        """query_audit default limit should return at most 100 entries."""
        for i in range(105):
            append_audit("action", "success", username=f"u{i}", db_path=self.db)
        entries = query_audit(db_path=self.db)
        self.assertEqual(len(entries), 100)

    def test_explicit_limit_overrides_default(self):
        for i in range(10):
            append_audit("action", "success", username=f"u{i}", db_path=self.db)
        entries = query_audit(db_path=self.db, limit=3)
        self.assertEqual(len(entries), 3)

    def test_rotate_creates_archive(self):
        append_audit("action", "success", username="admin", db_path=self.db)
        archive_name = rotate_audit_log(db_path=self.db, username="admin")
        self.assertTrue(archive_name.startswith("audit_"))
        self.assertTrue(archive_name.endswith(".db"))
        archive_path = Path(self.db_dir) / archive_name
        self.assertTrue(archive_path.exists())

    def test_rotate_clears_live_table(self):
        for i in range(5):
            append_audit("action", "success", username=f"u{i}", db_path=self.db)
        rotate_audit_log(db_path=self.db, username="admin")
        # After rotation, only the bootstrap entry should remain
        entries = query_audit(db_path=self.db, limit=100)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["action"], "audit_rotated_from")

    def test_no_auto_rotation_below_threshold(self):
        """50 entries with max_entries=100 — no rotation should occur."""
        audit_config = {"auto_rotate_max_entries": 100, "auto_rotate_max_days": 0,
                        "retention_max_archives": 0}
        for i in range(50):
            append_audit_with_config("action", "success", username=f"u{i}",
                                     db_path=self.db, audit_config=audit_config)
        entries = query_audit(db_path=self.db, limit=0)
        self.assertEqual(len(entries), 50)
        archives = list(Path(self.db_dir).glob("audit_*.db"))
        self.assertEqual(len(archives), 0)

    def test_auto_rotation_triggers_at_max_entries(self):
        """Writing past max_entries threshold must auto-rotate the log."""
        audit_config = {"auto_rotate_max_entries": 10, "auto_rotate_max_days": 0,
                        "retention_max_archives": 0}
        for i in range(12):
            append_audit_with_config("action", "success", username=f"u{i}",
                                     db_path=self.db, audit_config=audit_config)
        archives = list(Path(self.db_dir).glob("audit_*.db"))
        self.assertGreater(len(archives), 0, "archive must exist after threshold exceeded")
        live = query_audit(db_path=self.db, limit=0)
        self.assertLess(len(live), 12, "live log must have been truncated after rotation")

    def test_auto_rotation_by_max_days(self):
        """Oldest entry older than max_days must trigger rotation."""
        audit_config = {"auto_rotate_max_entries": 0, "auto_rotate_max_days": 1,
                        "retention_max_archives": 0}
        # Insert an entry with a timestamp 2 days in the past
        old_ts = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=2)).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        from core.db import get_conn
        with get_conn(self.db) as conn:
            conn.execute(
                "INSERT INTO audit_log (timestamp, action, outcome, username, pid)"
                " VALUES (?, 'action', 'success', 'u0', 0)",
                (old_ts,),
            )
        # Next write should detect the old entry and rotate
        append_audit_with_config("action", "success", username="u1",
                                 db_path=self.db, audit_config=audit_config)
        archives = list(Path(self.db_dir).glob("audit_*.db"))
        self.assertGreater(len(archives), 0, "archive must exist after age threshold exceeded")

    def test_retention_purges_oldest_archives(self):
        """retention_max_archives=2 keeps only the 2 newest archives."""
        audit_config = {"auto_rotate_max_entries": 5, "auto_rotate_max_days": 0,
                        "retention_max_archives": 2}
        # Force 3 rotations by exceeding the threshold 3 times
        for rotation in range(3):
            for i in range(6):
                append_audit_with_config("action", "success", username=f"u{i}",
                                         db_path=self.db, audit_config=audit_config)
        archives = list(Path(self.db_dir).glob("audit_*.db"))
        self.assertLessEqual(len(archives), 2, "only 2 archives must be kept")

    def test_limit_zero_returns_all_entries(self):
        """query_audit with limit=0 must return every entry without cap."""
        for i in range(150):
            append_audit("action", "success", username=f"u{i}", db_path=self.db)
        entries = query_audit(db_path=self.db, limit=0)
        self.assertEqual(len(entries), 150)

    def test_audit_logger_triggers_auto_rotation(self):
        """AuditLogger must wire audit_config so auto-rotation fires."""
        from server.audit_logger import AuditLogger
        audit_config = {"auto_rotate_max_entries": 5, "auto_rotate_max_days": 0,
                        "retention_max_archives": 0}
        log = AuditLogger(db_path=self.db, audit_config=audit_config)
        for i in range(7):
            log.login(f"user{i}", success=True)
        archives = list(Path(self.db_dir).glob("audit_*.db"))
        self.assertGreater(len(archives), 0,
                           "AuditLogger must trigger rotation when threshold exceeded")


# ===================================================================
# 9. Download directory
# ===================================================================

class TestDownloadDir(unittest.TestCase):
    """DOWNLOADS_DIR should be _DEPLOY_ROOT / 'downloads'."""

    def test_downloads_dir_default(self):
        from client.client import DOWNLOADS_DIR, _DEPLOY_ROOT
        self.assertEqual(DOWNLOADS_DIR, _DEPLOY_ROOT / "downloads")


# ===================================================================
# 10. Server bind defaults
# ===================================================================

class TestServerBindDefaults(unittest.TestCase):
    """Server default host and port."""

    def test_default_host(self):
        from server.server import DEFAULT_HOST
        self.assertEqual(DEFAULT_HOST, "127.0.0.1")

    def test_default_port(self):
        from server.server import DEFAULT_PORT
        self.assertEqual(DEFAULT_PORT, 9999)


# ===================================================================
# 11. Client-side config.json
# ===================================================================

class TestClientConfig(unittest.TestCase):
    """Client _load_config returns host/port/cert from config.json."""

    def test_load_config_returns_defaults_when_no_file(self):
        import client.client as cc
        original = cc.CONFIG_FILE
        cc.CONFIG_FILE = Path("/nonexistent/config.json")
        try:
            cfg = cc._load_config()
            self.assertEqual(cfg["host"], "127.0.0.1")
            self.assertEqual(cfg["port"], 9999)
            self.assertIsNone(cfg["cert"])
        finally:
            cc.CONFIG_FILE = original

    def test_load_config_reads_file(self):
        import client.client as cc
        tmp = tempfile.mkdtemp()
        cfg_path = Path(tmp) / "config.json"
        cfg_path.write_text(json.dumps({"host": "10.0.0.1", "port": 8443, "cert": "/path/cert.pem"}))
        original = cc.CONFIG_FILE
        cc.CONFIG_FILE = cfg_path
        try:
            cfg = cc._load_config()
            self.assertEqual(cfg["host"], "10.0.0.1")
            self.assertEqual(cfg["port"], 8443)
            self.assertEqual(cfg["cert"], "/path/cert.pem")
        finally:
            cc.CONFIG_FILE = original
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)


# ===================================================================
# 12. Web rate limiting constants
# ===================================================================

class TestWebRateLimitConstants(unittest.TestCase):
    """Pin down web app rate limit values."""

    def test_ip_window(self):
        from web.app import _IP_WINDOW
        self.assertEqual(_IP_WINDOW, 300)

    def test_ip_max(self):
        from web.app import _IP_MAX
        self.assertEqual(_IP_MAX, 10)

    def test_acct_max(self):
        from web.app import _ACCT_MAX
        self.assertEqual(_ACCT_MAX, 5)

    def test_acct_lockout(self):
        from web.app import _ACCT_LOCKOUT
        self.assertEqual(_ACCT_LOCKOUT, 900)


class TestAuditIntegrityConfigDefaults(unittest.TestCase):
    """Verify the integrity monitor config keys are present with correct defaults."""

    def test_integrity_interval_default(self):
        from core.config import _DEFAULTS
        self.assertIn("integrity_check_interval_seconds", _DEFAULTS["audit"])
        self.assertEqual(_DEFAULTS["audit"]["integrity_check_interval_seconds"], 60)

    def test_integrity_full_scan_default(self):
        from core.config import _DEFAULTS
        self.assertIn("integrity_full_scan_every_n_polls", _DEFAULTS["audit"])
        self.assertEqual(_DEFAULTS["audit"]["integrity_full_scan_every_n_polls"], 10)

    def test_integrity_keys_in_loaded_config(self):
        from core.config import load_server_config
        cfg = load_server_config()
        self.assertIn("integrity_check_interval_seconds", cfg["audit"])
        self.assertIn("integrity_full_scan_every_n_polls", cfg["audit"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
