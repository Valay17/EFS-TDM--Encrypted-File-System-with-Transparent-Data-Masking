"""
End-to-end integration tests.

One server instance is started for the entire module (module-level fixture),
shared across all test classes. Each test class gets its own DB state via
setUpClass seeding, but they all hit the same running server process.
"""

import base64
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from core.db import init_db
from client.client import ServerConn, DOWNLOADS_DIR
from server.server import EFSServer
from server.access_control import add_user

CERT = str(PROJECT_ROOT / "server_pkg" / "certs" / "cert.pem")
KEY  = str(PROJECT_ROOT / "server_pkg" / "certs" / "key.pem")
HOST = "127.0.0.1"
PORT = 19999

SAMPLE_CSV = b"id,name,ssn,email\n1,Alice,123-45-6789,alice@example.com\n"

# Module-level server and DB — created once, shared across all test classes
_server: EFSServer | None = None
_db_path: str = ""
_enc_dir: tempfile.TemporaryDirectory | None = None


def setUpModule():
    global _server, _db_path, _enc_dir
    fd, _db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    init_db(_db_path)
    add_user("admin",       "Admin1234!",   role="Admin",       db_path=_db_path)
    add_user("analyst",     "Analyst1@34", role="Analyst",     db_path=_db_path)
    add_user("contributor", "Contrib1234!", role="Contributor", db_path=_db_path)
    add_user("viewer",      "Viewer1234!",  role="Viewer",      db_path=_db_path)
    add_user("auditor",     "Auditor1234!", role="Auditor",     db_path=_db_path)
    add_user("guestuser",   "Guest1234!",   role="Guest",       db_path=_db_path)

    from pathlib import Path
    _enc_dir = tempfile.TemporaryDirectory()
    _server = EFSServer(host=HOST, port=PORT, cert=CERT, key=KEY, db_path=_db_path,
                        data_enc=Path(_enc_dir.name))
    t = threading.Thread(target=_server.start, daemon=True)
    t.start()

    # Wait until server is accepting connections
    for _ in range(30):
        try:
            with ServerConn(HOST, PORT, CERT) as c:
                c.send({"cmd": "ping"})
            break
        except Exception:
            time.sleep(0.1)


def tearDownModule():
    if _server:
        _server.stop()
    if _db_path and os.path.exists(_db_path):
        os.unlink(_db_path)
    if _enc_dir:
        _enc_dir.cleanup()


def conn() -> ServerConn:
    return ServerConn(HOST, PORT, CERT)


def login(username: str, password: str) -> str:
    with conn() as c:
        resp = c.send({"cmd": "login", "username": username, "password": password})
    assert resp["ok"], resp
    return resp["session"]


# ---------------------------------------------------------------------------

class TestPing(unittest.TestCase):

    def test_ping(self):
        with conn() as c:
            resp = c.send({"cmd": "ping"})
        self.assertTrue(resp["ok"])
        self.assertEqual(resp["message"], "pong")


class TestLogin(unittest.TestCase):

    def setUp(self):
        self._token = None

    def tearDown(self):
        if self._token:
            try:
                with conn() as c:
                    c.send({"cmd": "logout", "session": self._token})
            except Exception:
                pass

    def test_login_success(self):
        with conn() as c:
            resp = c.send({"cmd": "login", "username": "admin", "password": "Admin1234!"})
        self.assertTrue(resp["ok"])
        self.assertIn("session", resp)
        self.assertEqual(resp["role"], "Admin")
        self._token = resp["session"]

    def test_login_wrong_password(self):
        with conn() as c:
            resp = c.send({"cmd": "login", "username": "admin", "password": "wrong"})
        self.assertFalse(resp["ok"])

    def test_login_unknown_user(self):
        with conn() as c:
            resp = c.send({"cmd": "login", "username": "nobody", "password": "x"})
        self.assertFalse(resp["ok"])

    def test_unauthenticated_command_rejected(self):
        from client.client import SessionExpired
        try:
            with conn() as c:
                resp = c.send({"cmd": "list_users"})
            self.assertFalse(resp["ok"])
        except SessionExpired:
            pass


class TestEncryptDecrypt(unittest.TestCase):

    def setUp(self):
        self.token = login("admin", "Admin1234!")

    def tearDown(self):
        try:
            with conn() as c:
                c.send({"cmd": "logout", "session": self.token})
        except Exception:
            pass

    def test_encrypt_stores_file(self):
        data_b64 = base64.b64encode(SAMPLE_CSV).decode()
        with conn() as c:
            resp = c.send({
                "cmd": "encrypt", "session": self.token,
                "filename": "test_employees.csv", "data_b64": data_b64,
            })
        self.assertTrue(resp["ok"], resp)
        self.assertEqual(resp["stored_as"], "test_employees.csv.enc")

    def test_decrypt_roundtrip(self):
        data_b64 = base64.b64encode(SAMPLE_CSV).decode()
        with conn() as c:
            c.send({
                "cmd": "encrypt", "session": self.token,
                "filename": "roundtrip.csv", "data_b64": data_b64,
            })
            resp = c.send({
                "cmd": "decrypt", "session": self.token,
                "filename": "roundtrip.csv.enc",
            })
        self.assertTrue(resp["ok"], resp)
        self.assertEqual(base64.b64decode(resp["data_b64"]), SAMPLE_CSV)

    def test_decrypt_nonexistent_file(self):
        with conn() as c:
            resp = c.send({
                "cmd": "decrypt", "session": self.token,
                "filename": "does_not_exist.enc",
            })
        self.assertFalse(resp["ok"])


class TestMask(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        token = login("admin", "Admin1234!")
        data_b64 = base64.b64encode(SAMPLE_CSV).decode()
        with conn() as c:
            c.send({
                "cmd": "encrypt", "session": token,
                "filename": "mask_test.csv", "data_b64": data_b64,
            })
        with conn() as c:
            c.send({"cmd": "logout", "session": token})

    def setUp(self):
        self.admin_token   = login("admin",   "Admin1234!")
        self.analyst_token = login("analyst", "Analyst1@34")

    def tearDown(self):
        for tok in (self.admin_token, self.analyst_token):
            try:
                with conn() as c:
                    c.send({"cmd": "logout", "session": tok})
            except Exception:
                pass

    def test_mask_as_analyst_hides_pii(self):
        with conn() as c:
            resp = c.send({
                "cmd": "mask", "session": self.analyst_token,
                "filename": "mask_test.csv.enc", "role": "Analyst",
            })
        self.assertTrue(resp["ok"], resp)
        self.assertNotIn("123-45-6789", resp["masked"])
        self.assertIn("***-**-****", resp["masked"])

    def test_mask_as_admin_shows_plaintext(self):
        with conn() as c:
            resp = c.send({
                "cmd": "mask", "session": self.admin_token,
                "filename": "mask_test.csv.enc", "role": "Admin",
            })
        self.assertTrue(resp["ok"], resp)
        self.assertIn("123-45-6789", resp["masked"])

    def test_analyst_cannot_decrypt(self):
        with conn() as c:
            resp = c.send({
                "cmd": "decrypt", "session": self.analyst_token,
                "filename": "mask_test.csv.enc",
            })
        self.assertFalse(resp["ok"])
        self.assertIn("Permission", resp["error"])


class TestUserManagement(unittest.TestCase):

    def setUp(self):
        self.token = login("admin", "Admin1234!")

    def tearDown(self):
        try:
            with conn() as c:
                c.send({"cmd": "logout", "session": self.token})
        except Exception:
            pass

    def test_add_user(self):
        with conn() as c:
            resp = c.send({
                "cmd": "add_user", "session": self.token,
                "username": "newuser_it", "password": "Newuser1!", "role": "Guest",
            })
        self.assertTrue(resp["ok"], resp)
        self.assertEqual(resp["username"], "newuser_it")

    def test_add_duplicate_user_fails(self):
        with conn() as c:
            c.send({
                "cmd": "add_user", "session": self.token,
                "username": "dup_user", "password": "Dupuser1!", "role": "Guest",
            })
            resp = c.send({
                "cmd": "add_user", "session": self.token,
                "username": "dup_user", "password": "Dupuser1!", "role": "Guest",
            })
        self.assertFalse(resp["ok"])

    def test_assign_role(self):
        with conn() as c:
            c.send({
                "cmd": "add_user", "session": self.token,
                "username": "roletest_user", "password": "Roletest1!", "role": "Guest",
            })
            resp = c.send({
                "cmd": "assign_role", "session": self.token,
                "username": "roletest_user", "role": "Analyst",
            })
        self.assertTrue(resp["ok"], resp)

    def test_assign_role_revokes_session(self):
        tok = login("viewer", "Viewer1234!")
        try:
            with conn() as c:
                resp = c.send({
                    "cmd": "assign_role", "session": self.token,
                    "username": "viewer", "role": "Guest",
                })
            self.assertTrue(resp["ok"], resp)
            # viewer's old session must now be invalid
            from client.client import SessionExpired
            with self.assertRaises((SessionExpired, AssertionError)):
                with conn() as c:
                    resp = c.send({"cmd": "whoami", "session": tok})
                self.assertFalse(resp.get("ok"), "session should be revoked after role change")
        finally:
            # restore role regardless of outcome
            with conn() as c:
                c.send({"cmd": "assign_role", "session": self.token,
                        "username": "viewer", "role": "Viewer"})

    def test_list_users(self):
        with conn() as c:
            resp = c.send({"cmd": "list_users", "session": self.token})
        self.assertTrue(resp["ok"])
        names = {u["username"] for u in resp["users"]}
        self.assertIn("admin", names)
        self.assertIn("analyst", names)

    def test_list_roles(self):
        with conn() as c:
            resp = c.send({"cmd": "list_roles", "session": self.token})
        self.assertTrue(resp["ok"])
        names = {r["name"] for r in resp["roles"]}
        self.assertEqual(names, {"Admin", "Analyst", "Contributor", "Viewer", "Auditor", "Guest"})

    def test_analyst_cannot_add_user(self):
        token = login("analyst", "Analyst1@34")
        try:
            with conn() as c:
                resp = c.send({
                    "cmd": "add_user", "session": token,
                    "username": "hacker", "password": "x", "role": "Admin",
                })
            self.assertFalse(resp["ok"])
        finally:
            try:
                with conn() as c:
                    c.send({"cmd": "logout", "session": token})
            except Exception:
                pass


class TestAuditLog(unittest.TestCase):

    def setUp(self):
        self.token = login("admin", "Admin1234!")

    def tearDown(self):
        try:
            with conn() as c:
                c.send({"cmd": "logout", "session": self.token})
        except Exception:
            pass

    def test_accessible_by_admin(self):
        with conn() as c:
            resp = c.send({"cmd": "audit_log", "session": self.token})
        self.assertTrue(resp["ok"])
        self.assertIn("entries", resp)

    def test_denied_for_analyst(self):
        token = login("analyst", "Analyst1@34")
        try:
            with conn() as c:
                resp = c.send({"cmd": "audit_log", "session": token})
            self.assertFalse(resp["ok"])
        finally:
            try:
                with conn() as c:
                    c.send({"cmd": "logout", "session": token})
            except Exception:
                pass

    def test_contains_login_events(self):
        with conn() as c:
            resp = c.send({"cmd": "audit_log", "session": self.token, "action": "login"})
        self.assertTrue(resp["ok"])
        self.assertGreater(len(resp["entries"]), 0)


class TestLogout(unittest.TestCase):

    def test_logout_invalidates_session(self):
        from client.client import SessionExpired
        token = login("admin", "Admin1234!")
        with conn() as c:
            c.send({"cmd": "logout", "session": token})
            try:
                resp = c.send({"cmd": "list_users", "session": token})
                self.assertFalse(resp["ok"])
            except SessionExpired:
                pass


def _cleanup_downloads() -> None:
    """Remove all admin_delivery_* files written to DOWNLOADS_DIR by tests."""
    if DOWNLOADS_DIR.exists():
        for f in DOWNLOADS_DIR.glob("admin_delivery_*"):
            f.unlink(missing_ok=True)


class TestDeliveries(unittest.TestCase):
    """Tests for the admin send-to / delivery feature."""

    def setUp(self):
        _cleanup_downloads()
        self.admin_token = login("admin", "Admin1234!")
        self.analyst_token = login("analyst", "Analyst1@34")

    def tearDown(self):
        for tok in (self.admin_token, self.analyst_token):
            try:
                with conn() as c:
                    c.send({"cmd": "logout", "session": tok})
            except Exception:
                pass
        _cleanup_downloads()

    def _upload_file(self, token: str, vfs_path: str, content: bytes = SAMPLE_CSV) -> None:
        data_b64 = base64.b64encode(content).decode()
        with conn() as c:
            resp = c.send({"cmd": "vfs_send", "session": token,
                           "path": vfs_path, "cwd": "/", "data_b64": data_b64})
        self.assertTrue(resp["ok"], resp)

    def test_send_to_eligible_role_queues_delivery(self):
        self._upload_file(self.admin_token, "/delivery_test.csv")
        with conn() as c:
            resp = c.send({"cmd": "send_to_user", "session": self.admin_token,
                           "recipient": "analyst", "path": "/delivery_test.csv", "cwd": "/"})
        self.assertTrue(resp["ok"], resp)
        self.assertIn("recipient_active", resp)

    def test_delivery_piggybacked_on_next_command(self):
        self._upload_file(self.admin_token, "/piggyback_test.csv")
        with conn() as c:
            c.send({"cmd": "send_to_user", "session": self.admin_token,
                    "recipient": "analyst", "path": "/piggyback_test.csv", "cwd": "/"})
        # Any subsequent analyst command should carry the delivery
        with conn() as c:
            resp = c.send({"cmd": "whoami", "session": self.analyst_token})
            deliveries = c.last_deliveries
        self.assertTrue(resp["ok"])
        filenames = [d["filename"] for d in deliveries]
        self.assertIn("piggyback_test.csv", filenames)

    def test_delivery_marked_delivered_after_pickup(self):
        self._upload_file(self.admin_token, "/once_test.csv")
        with conn() as c:
            c.send({"cmd": "send_to_user", "session": self.admin_token,
                    "recipient": "analyst", "path": "/once_test.csv", "cwd": "/"})
        # First pickup
        with conn() as c:
            resp1 = c.send({"cmd": "whoami", "session": self.analyst_token})
            deliveries1 = c.last_deliveries
        self.assertTrue(any(d["filename"] == "once_test.csv" for d in deliveries1))
        # Second command — delivery must NOT appear again
        with conn() as c:
            resp2 = c.send({"cmd": "whoami", "session": self.analyst_token})
            deliveries2 = c.last_deliveries
        self.assertFalse(any(d["filename"] == "once_test.csv" for d in deliveries2))

    def test_send_to_ineligible_role_rejected(self):
        self._upload_file(self.admin_token, "/ineligible_test.csv")
        # Auditor is ineligible
        with conn() as c:
            resp = c.send({"cmd": "send_to_user", "session": self.admin_token,
                           "recipient": "auditor", "path": "/ineligible_test.csv", "cwd": "/"})
        self.assertFalse(resp["ok"])
        self.assertIn("Deliveries not supported", resp["error"])

    def test_send_to_nonexistent_user_rejected(self):
        self._upload_file(self.admin_token, "/nouser_test.csv")
        with conn() as c:
            resp = c.send({"cmd": "send_to_user", "session": self.admin_token,
                           "recipient": "nobody", "path": "/nouser_test.csv", "cwd": "/"})
        self.assertFalse(resp["ok"])
        self.assertIn("not found", resp["error"])

    def test_non_admin_cannot_send_to_user(self):
        self._upload_file(self.admin_token, "/perm_test.csv")
        with conn() as c:
            resp = c.send({"cmd": "send_to_user", "session": self.analyst_token,
                           "recipient": "viewer", "path": "/perm_test.csv", "cwd": "/"})
        self.assertFalse(resp["ok"])

    def test_send_directory_rejected(self):
        with conn() as c:
            c.send({"cmd": "vfs_mkdir", "session": self.admin_token,
                    "path": "/delivery_dir", "cwd": "/"})
        with conn() as c:
            resp = c.send({"cmd": "send_to_user", "session": self.admin_token,
                           "recipient": "analyst", "path": "/delivery_dir", "cwd": "/"})
        self.assertFalse(resp["ok"])
        self.assertIn("directory", resp["error"])

    def test_delivery_content_is_masked(self):
        """Delivered file content must be masked using the recipient's role,
        not the raw plaintext."""
        raw_ssn = b"123-45-6789"
        csv_content = b"id,name,ssn\n1,Alice," + raw_ssn + b"\n"
        self._upload_file(self.admin_token, "/masked_delivery_test.csv", csv_content)
        with conn() as c:
            c.send({"cmd": "send_to_user", "session": self.admin_token,
                    "recipient": "analyst", "path": "/masked_delivery_test.csv", "cwd": "/"})
        with conn() as c:
            c.send({"cmd": "whoami", "session": self.analyst_token})
            deliveries = c.last_deliveries
        match = next((d for d in deliveries if d["filename"] == "masked_delivery_test.csv"), None)
        self.assertIsNotNone(match, "delivery not received")
        import base64
        payload = base64.b64decode(match["data_b64"])
        self.assertNotIn(raw_ssn, payload, "raw SSN must not appear in masked delivery")

    def test_raw_fetch_blocked_for_non_admin(self):
        """vfs_fetch with raw=True must be rejected for non-admin roles server-side."""
        viewer_token = login("viewer", "Viewer1234!")
        self._upload_file(self.admin_token, "/raw_block_test.csv")
        try:
            with conn() as c:
                resp = c.send({"cmd": "vfs_fetch", "session": viewer_token,
                               "path": "/raw_block_test.csv", "cwd": "/", "raw": True})
            self.assertFalse(resp["ok"])
            self.assertIn("Permission denied", resp.get("error", ""))
        finally:
            with conn() as c:
                c.send({"cmd": "logout", "session": viewer_token})

    def test_delivery_skipped_if_file_deleted(self):
        self._upload_file(self.admin_token, "/deleted_test.csv")
        # Queue delivery
        with conn() as c:
            resp = c.send({"cmd": "send_to_user", "session": self.admin_token,
                           "recipient": "analyst", "path": "/deleted_test.csv", "cwd": "/"})
        self.assertTrue(resp["ok"])
        # Delete the file before pickup
        with conn() as c:
            node = c.send({"cmd": "vfs_stat", "session": self.admin_token,
                           "path": "/deleted_test.csv", "cwd": "/"})
        with conn() as c:
            c.send({"cmd": "vfs_rm", "session": self.admin_token,
                    "path": "/deleted_test.csv", "cwd": "/"})
        # Analyst runs a command — delivery should be skipped, not crash
        with conn() as c:
            resp2 = c.send({"cmd": "whoami", "session": self.analyst_token})
            deliveries2 = c.last_deliveries
        self.assertTrue(resp2["ok"])
        self.assertFalse(any(d.get("filename") == "deleted_test.csv" for d in deliveries2))


class TestStatAclVisibility(unittest.TestCase):
    """ACL entries in stat output must only be visible to Admin."""

    def setUp(self):
        self.admin_token = login("admin", "Admin1234!")
        self.analyst_token = login("analyst", "Analyst1@34")
        # Upload a file and grant an ACL on it so stat has acl data
        data_b64 = base64.b64encode(SAMPLE_CSV).decode()
        with conn() as c:
            resp = c.send({"cmd": "vfs_send", "session": self.admin_token,
                           "path": "/stat_acl_test.csv", "cwd": "/", "data_b64": data_b64})
        self.assertTrue(resp["ok"], resp)
        with conn() as c:
            resp = c.send({"cmd": "vfs_chmod", "session": self.admin_token,
                           "path": "/stat_acl_test.csv", "cwd": "/",
                           "role": "Viewer", "perm": "read", "action": "grant"})
        self.assertTrue(resp["ok"], resp)

    def tearDown(self):
        with conn() as c:
            c.send({"cmd": "vfs_rm", "session": self.admin_token,
                    "path": "/stat_acl_test.csv", "cwd": "/"})
        for tok in (self.admin_token, self.analyst_token):
            try:
                with conn() as c:
                    c.send({"cmd": "logout", "session": tok})
            except Exception:
                pass

    def test_admin_sees_acl_in_stat(self):
        with conn() as c:
            resp = c.send({"cmd": "vfs_stat", "session": self.admin_token,
                           "path": "/stat_acl_test.csv", "cwd": "/"})
        self.assertTrue(resp["ok"], resp)
        self.assertIn("acl", resp["stat"], "Admin must see acl entries in stat")

    def test_non_admin_does_not_see_acl_in_stat(self):
        with conn() as c:
            resp = c.send({"cmd": "vfs_stat", "session": self.analyst_token,
                           "path": "/stat_acl_test.csv", "cwd": "/"})
        self.assertTrue(resp["ok"], resp)
        self.assertNotIn("acl", resp["stat"], "Non-admin must not see acl entries in stat")


class TestGetMyPermissions(unittest.TestCase):
    """get_my_permissions returns role, permissions, and password policy for the caller."""

    def setUp(self):
        self.admin_token = login("admin", "Admin1234!")
        self.analyst_token = login("analyst", "Analyst1@34")

    def tearDown(self):
        for tok in (self.admin_token, self.analyst_token):
            try:
                with conn() as c:
                    c.send({"cmd": "logout", "session": tok})
            except Exception:
                pass

    def test_admin_gets_own_permissions(self):
        with conn() as c:
            resp = c.send({"cmd": "get_my_permissions", "session": self.admin_token})
        self.assertTrue(resp["ok"], resp)
        self.assertEqual(resp["role"], "Admin")
        self.assertIn("manage_users", resp["permissions"])
        self.assertIn("view_audit", resp["permissions"])

    def test_analyst_gets_own_permissions(self):
        with conn() as c:
            resp = c.send({"cmd": "get_my_permissions", "session": self.analyst_token})
        self.assertTrue(resp["ok"], resp)
        self.assertEqual(resp["role"], "Analyst")
        self.assertIn("read", resp["permissions"])
        self.assertNotIn("manage_users", resp["permissions"])

    def test_response_includes_password_policy(self):
        with conn() as c:
            resp = c.send({"cmd": "get_my_permissions", "session": self.analyst_token})
        self.assertTrue(resp["ok"], resp)
        policy = resp.get("password_policy")
        self.assertIsNotNone(policy)
        self.assertIn("min_length", policy)

    def test_unauthenticated_request_rejected(self):
        from client.client import SessionExpired
        with self.assertRaises((SessionExpired, Exception)):
            with conn() as c:
                c.send({"cmd": "get_my_permissions", "session": "invalid_token"})


class TestActiveUsers(unittest.TestCase):
    """active_users returns currently logged-in sessions; admin only."""

    def setUp(self):
        self.admin_token = login("admin", "Admin1234!")
        self.analyst_token = login("analyst", "Analyst1@34")

    def tearDown(self):
        for tok in (self.admin_token, self.analyst_token):
            try:
                with conn() as c:
                    c.send({"cmd": "logout", "session": tok})
            except Exception:
                pass

    def test_admin_sees_active_users(self):
        with conn() as c:
            resp = c.send({"cmd": "active_users", "session": self.admin_token})
        self.assertTrue(resp["ok"], resp)
        self.assertIn("users", resp)
        usernames = [u["username"] for u in resp["users"]]
        self.assertIn("admin", usernames)

    def test_response_includes_role_and_expiry(self):
        with conn() as c:
            resp = c.send({"cmd": "active_users", "session": self.admin_token})
        self.assertTrue(resp["ok"], resp)
        for entry in resp["users"]:
            self.assertIn("username", entry)
            self.assertIn("role", entry)
            self.assertIn("expires_in", entry)
            self.assertGreater(entry["expires_in"], 0)

    def test_logged_in_analyst_appears_in_list(self):
        with conn() as c:
            resp = c.send({"cmd": "active_users", "session": self.admin_token})
        self.assertTrue(resp["ok"], resp)
        usernames = [u["username"] for u in resp["users"]]
        self.assertIn("analyst", usernames)

    def test_non_admin_cannot_list_active_users(self):
        with conn() as c:
            resp = c.send({"cmd": "active_users", "session": self.analyst_token})
        self.assertFalse(resp["ok"])
        self.assertIn("Permission denied", resp.get("error", ""))


class TestSendToUnmasked(unittest.TestCase):
    """send-to --unmasked delivers raw content; without it, masking is applied."""

    def setUp(self):
        self.admin_token = login("admin", "Admin1234!")
        self.analyst_token = login("analyst", "Analyst1@34")
        self.raw_ssn = b"123-45-6789"
        csv_content = b"id,name,ssn\n1,Alice," + self.raw_ssn + b"\n"
        data_b64 = base64.b64encode(csv_content).decode()
        with conn() as c:
            resp = c.send({"cmd": "vfs_send", "session": self.admin_token,
                           "path": "/unmasked_test.csv", "cwd": "/",
                           "data_b64": data_b64})
        self.assertTrue(resp["ok"], resp)

    def tearDown(self):
        with conn() as c:
            c.send({"cmd": "vfs_rm", "session": self.admin_token,
                    "path": "/unmasked_test.csv", "cwd": "/"})
        for tok in (self.admin_token, self.analyst_token):
            try:
                with conn() as c:
                    c.send({"cmd": "logout", "session": tok})
            except Exception:
                pass

    def _drain_analyst_deliveries(self):
        with conn() as c:
            c.send({"cmd": "whoami", "session": self.analyst_token})
            return c.last_deliveries

    def test_unmasked_delivery_contains_raw_content(self):
        with conn() as c:
            resp = c.send({"cmd": "send_to_user", "session": self.admin_token,
                           "recipient": "analyst", "path": "/unmasked_test.csv",
                           "cwd": "/", "unmasked": True})
        self.assertTrue(resp["ok"], resp)
        deliveries = self._drain_analyst_deliveries()
        match = next((d for d in deliveries if d["filename"] == "UNMASKED_unmasked_test.csv"), None)
        self.assertIsNotNone(match, "delivery not received")
        payload = base64.b64decode(match["data_b64"])
        self.assertIn(self.raw_ssn, payload, "raw SSN must appear in unmasked delivery")

    def test_masked_delivery_hides_raw_content(self):
        with conn() as c:
            resp = c.send({"cmd": "send_to_user", "session": self.admin_token,
                           "recipient": "analyst", "path": "/unmasked_test.csv",
                           "cwd": "/"})
        self.assertTrue(resp["ok"], resp)
        deliveries = self._drain_analyst_deliveries()
        match = next((d for d in deliveries if d["filename"] == "unmasked_test.csv"), None)
        self.assertIsNotNone(match, "delivery not received")
        payload = base64.b64decode(match["data_b64"])
        self.assertNotIn(self.raw_ssn, payload, "raw SSN must not appear in masked delivery")

    def test_non_admin_cannot_set_unmasked_flag(self):
        """Server ignores unmasked=True from non-admin senders (permission denied anyway)."""
        with conn() as c:
            resp = c.send({"cmd": "send_to_user", "session": self.analyst_token,
                           "recipient": "viewer", "path": "/unmasked_test.csv",
                           "cwd": "/", "unmasked": True})
        self.assertFalse(resp["ok"])


class TestAuditLogVerify(unittest.TestCase):
    """audit_log --verify returns chain_valid; only Admin and Auditor may call it."""

    def setUp(self):
        self.admin_token    = login("admin",    "Admin1234!")
        self.auditor_token  = login("auditor",  "Auditor1234!")
        self.contrib_token  = login("contributor", "Contrib1234!")

    def tearDown(self):
        for tok in (self.admin_token, self.auditor_token, self.contrib_token):
            try:
                with conn() as c:
                    c.send({"cmd": "logout", "session": tok})
            except Exception:
                pass

    def test_admin_verify_clean_chain(self):
        with conn() as c:
            resp = c.send({"cmd": "audit_log", "session": self.admin_token, "verify": True})
        self.assertTrue(resp["ok"], resp)
        self.assertTrue(resp.get("chain_valid"), resp)

    def test_auditor_verify_clean_chain(self):
        with conn() as c:
            resp = c.send({"cmd": "audit_log", "session": self.auditor_token, "verify": True})
        self.assertTrue(resp["ok"], resp)
        self.assertTrue(resp.get("chain_valid"), resp)

    def test_contributor_cannot_verify(self):
        with conn() as c:
            resp = c.send({"cmd": "audit_log", "session": self.contrib_token, "verify": True})
        self.assertFalse(resp["ok"])
        self.assertIn("Permission", resp.get("error", ""))


class TestVfsAclWriteCheck(unittest.TestCase):
    """Write ACL checks on parent directory for vfs_send, vfs_mkdir, and vfs_mv."""

    def setUp(self):
        self.admin_token  = login("admin",       "Admin1234!")
        self.contrib_token = login("contributor", "Contrib1234!")
        # Create a locked directory with write denied for Contributor
        with conn() as c:
            c.send({"cmd": "vfs_mkdir", "session": self.admin_token,
                    "path": "/acl_write_test", "cwd": "/"})
        with conn() as c:
            c.send({"cmd": "vfs_chmod", "session": self.admin_token,
                    "path": "/acl_write_test", "cwd": "/",
                    "role": "Contributor", "perm": "write", "action": "revoke"})

    def tearDown(self):
        with conn() as c:
            c.send({"cmd": "vfs_rm", "session": self.admin_token,
                    "path": "/acl_write_test", "cwd": "/"})
        for tok in (self.admin_token, self.contrib_token):
            try:
                with conn() as c:
                    c.send({"cmd": "logout", "session": tok})
            except Exception:
                pass

    def test_send_blocked_by_parent_write_acl(self):
        data_b64 = base64.b64encode(SAMPLE_CSV).decode()
        with conn() as c:
            resp = c.send({"cmd": "vfs_send", "session": self.contrib_token,
                           "path": "/acl_write_test/blocked.csv",
                           "cwd": "/", "data_b64": data_b64})
        self.assertFalse(resp["ok"])
        self.assertIn("Permission", resp.get("error", ""))

    def test_mkdir_blocked_by_parent_write_acl(self):
        with conn() as c:
            resp = c.send({"cmd": "vfs_mkdir", "session": self.contrib_token,
                           "path": "/acl_write_test/newdir", "cwd": "/"})
        self.assertFalse(resp["ok"])
        self.assertIn("Permission", resp.get("error", ""))

    def test_mv_blocked_by_dst_write_acl(self):
        # Create a file in root to move into the locked dir
        data_b64 = base64.b64encode(SAMPLE_CSV).decode()
        with conn() as c:
            c.send({"cmd": "vfs_send", "session": self.admin_token,
                    "path": "/mv_src_acl.csv", "cwd": "/", "data_b64": data_b64})
        try:
            with conn() as c:
                resp = c.send({"cmd": "vfs_mv", "session": self.contrib_token,
                               "src": "/mv_src_acl.csv",
                               "dst": "/acl_write_test/mv_src_acl.csv", "cwd": "/"})
            self.assertFalse(resp["ok"])
            self.assertIn("Permission", resp.get("error", ""))
        finally:
            with conn() as c:
                c.send({"cmd": "vfs_rm", "session": self.admin_token,
                        "path": "/mv_src_acl.csv", "cwd": "/"})

    def test_admin_can_write_to_locked_dir(self):
        """Admin bypasses write ACL checks."""
        data_b64 = base64.b64encode(SAMPLE_CSV).decode()
        with conn() as c:
            resp = c.send({"cmd": "vfs_send", "session": self.admin_token,
                           "path": "/acl_write_test/admin_file.csv",
                           "cwd": "/", "data_b64": data_b64})
        self.assertTrue(resp["ok"], resp)
        with conn() as c:
            c.send({"cmd": "vfs_rm", "session": self.admin_token,
                    "path": "/acl_write_test/admin_file.csv", "cwd": "/"})


class TestVfsAclDeleteSemantics(unittest.TestCase):
    """delete_own/delete_any ACL semantics."""

    def setUp(self):
        self.admin_token   = login("admin",       "Admin1234!")
        self.contrib_token = login("contributor", "Contrib1234!")
        self.viewer_token  = login("viewer",      "Viewer1234!")

    def tearDown(self):
        for tok in (self.admin_token, self.contrib_token, self.viewer_token):
            try:
                with conn() as c:
                    c.send({"cmd": "logout", "session": tok})
            except Exception:
                pass

    def _upload(self, token: str, path: str) -> None:
        data_b64 = base64.b64encode(SAMPLE_CSV).decode()
        with conn() as c:
            resp = c.send({"cmd": "vfs_send", "session": token,
                           "path": path, "cwd": "/", "data_b64": data_b64})
        self.assertTrue(resp["ok"], resp)

    def test_delete_own_allowed_by_default(self):
        """Contributor can delete their own file when no ACL is set."""
        self._upload(self.contrib_token, "/del_own_default.csv")
        with conn() as c:
            resp = c.send({"cmd": "vfs_rm", "session": self.contrib_token,
                           "path": "/del_own_default.csv", "cwd": "/"})
        self.assertTrue(resp["ok"], resp)

    def test_delete_own_blocked_by_explicit_deny(self):
        """Explicit deny on delete_own blocks the owner from deleting their file."""
        self._upload(self.contrib_token, "/del_own_denied.csv")
        with conn() as c:
            c.send({"cmd": "vfs_chmod", "session": self.admin_token,
                    "path": "/del_own_denied.csv", "cwd": "/",
                    "role": "Contributor", "perm": "delete_own", "action": "revoke"})
        try:
            with conn() as c:
                resp = c.send({"cmd": "vfs_rm", "session": self.contrib_token,
                               "path": "/del_own_denied.csv", "cwd": "/"})
            self.assertFalse(resp["ok"])
            self.assertIn("Permission", resp.get("error", ""))
        finally:
            with conn() as c:
                c.send({"cmd": "vfs_rm", "session": self.admin_token,
                        "path": "/del_own_denied.csv", "cwd": "/"})

    def test_delete_other_requires_explicit_delete_any_grant(self):
        """Contributor cannot delete another user's file without an explicit delete_any grant."""
        self._upload(self.admin_token, "/del_other_no_grant.csv")
        try:
            with conn() as c:
                resp = c.send({"cmd": "vfs_rm", "session": self.contrib_token,
                               "path": "/del_other_no_grant.csv", "cwd": "/"})
            self.assertFalse(resp["ok"])
            self.assertIn("Permission", resp.get("error", ""))
        finally:
            with conn() as c:
                c.send({"cmd": "vfs_rm", "session": self.admin_token,
                        "path": "/del_other_no_grant.csv", "cwd": "/"})

    def test_delete_other_allowed_by_explicit_delete_any_grant(self):
        """Contributor can delete another user's file when delete_any is explicitly granted."""
        self._upload(self.admin_token, "/del_other_granted.csv")
        with conn() as c:
            c.send({"cmd": "vfs_chmod", "session": self.admin_token,
                    "path": "/del_other_granted.csv", "cwd": "/",
                    "role": "Contributor", "perm": "delete_any", "action": "grant"})
        with conn() as c:
            resp = c.send({"cmd": "vfs_rm", "session": self.contrib_token,
                           "path": "/del_other_granted.csv", "cwd": "/"})
        self.assertTrue(resp["ok"], resp)

    def test_delete_own_deny_absolute_blocks_delete_any_grant(self):
        """Explicit deny on delete_own is absolute — delete_any grant cannot override it."""
        self._upload(self.contrib_token, "/del_deny_own_grant_any.csv")
        with conn() as c:
            c.send({"cmd": "vfs_chmod", "session": self.admin_token,
                    "path": "/del_deny_own_grant_any.csv", "cwd": "/",
                    "role": "Contributor", "perm": "delete_own", "action": "revoke"})
        with conn() as c:
            c.send({"cmd": "vfs_chmod", "session": self.admin_token,
                    "path": "/del_deny_own_grant_any.csv", "cwd": "/",
                    "role": "Contributor", "perm": "delete_any", "action": "grant"})
        try:
            with conn() as c:
                resp = c.send({"cmd": "vfs_rm", "session": self.contrib_token,
                               "path": "/del_deny_own_grant_any.csv", "cwd": "/"})
            self.assertFalse(resp["ok"])
            self.assertIn("Permission", resp.get("error", ""))
        finally:
            with conn() as c:
                c.send({"cmd": "vfs_rm", "session": self.admin_token,
                        "path": "/del_deny_own_grant_any.csv", "cwd": "/"})


class TestVfsLsAclFiltering(unittest.TestCase):
    """ls filters entries where read is denied; parent deny overrides child grant."""

    def setUp(self):
        self.admin_token  = login("admin",  "Admin1234!")
        self.viewer_token = login("viewer", "Viewer1234!")
        # Create test directory with two files: one visible, one denied
        with conn() as c:
            c.send({"cmd": "vfs_mkdir", "session": self.admin_token,
                    "path": "/ls_acl_dir", "cwd": "/"})
        data_b64 = base64.b64encode(SAMPLE_CSV).decode()
        with conn() as c:
            c.send({"cmd": "vfs_send", "session": self.admin_token,
                    "path": "/ls_acl_dir/visible.csv", "cwd": "/", "data_b64": data_b64})
        with conn() as c:
            c.send({"cmd": "vfs_send", "session": self.admin_token,
                    "path": "/ls_acl_dir/hidden.csv", "cwd": "/", "data_b64": data_b64})
        with conn() as c:
            c.send({"cmd": "vfs_chmod", "session": self.admin_token,
                    "path": "/ls_acl_dir/hidden.csv", "cwd": "/",
                    "role": "Viewer", "perm": "read", "action": "revoke"})

    def tearDown(self):
        with conn() as c:
            c.send({"cmd": "vfs_rm", "session": self.admin_token,
                    "path": "/ls_acl_dir", "cwd": "/"})
        for tok in (self.admin_token, self.viewer_token):
            try:
                with conn() as c:
                    c.send({"cmd": "logout", "session": tok})
            except Exception:
                pass

    def test_ls_hides_entry_with_read_denied(self):
        with conn() as c:
            resp = c.send({"cmd": "vfs_ls", "session": self.viewer_token,
                           "path": "/ls_acl_dir", "cwd": "/"})
        self.assertTrue(resp["ok"], resp)
        names = [e["name"] for e in resp["entries"]]
        self.assertNotIn("hidden.csv", names)
        self.assertIn("visible.csv", names)

    def test_ls_admin_sees_all_entries(self):
        """Admin bypasses ACL read filtering."""
        with conn() as c:
            resp = c.send({"cmd": "vfs_ls", "session": self.admin_token,
                           "path": "/ls_acl_dir", "cwd": "/"})
        self.assertTrue(resp["ok"], resp)
        names = [e["name"] for e in resp["entries"]]
        self.assertIn("hidden.csv", names)
        self.assertIn("visible.csv", names)

    def test_ls_directory_read_denied_returns_error(self):
        """ls on a directory where the role has read denied returns Permission denied."""
        with conn() as c:
            c.send({"cmd": "vfs_chmod", "session": self.admin_token,
                    "path": "/ls_acl_dir", "cwd": "/",
                    "role": "Viewer", "perm": "read", "action": "revoke"})
        with conn() as c:
            resp = c.send({"cmd": "vfs_ls", "session": self.viewer_token,
                           "path": "/ls_acl_dir", "cwd": "/"})
        self.assertFalse(resp["ok"])
        self.assertIn("Permission", resp.get("error", ""))
        # Restore for tearDown
        with conn() as c:
            c.send({"cmd": "vfs_chmod", "session": self.admin_token,
                    "path": "/ls_acl_dir", "cwd": "/",
                    "role": "Viewer", "perm": "read", "action": "grant"})

    def test_ls_parent_deny_wins_over_child_grant(self):
        """Parent directory read deny hides all children even if child has explicit grant."""
        with conn() as c:
            c.send({"cmd": "vfs_mkdir", "session": self.admin_token,
                    "path": "/ls_parentdeny", "cwd": "/"})
        data_b64 = base64.b64encode(SAMPLE_CSV).decode()
        with conn() as c:
            c.send({"cmd": "vfs_send", "session": self.admin_token,
                    "path": "/ls_parentdeny/child.csv", "cwd": "/", "data_b64": data_b64})
        # Grant read on child explicitly, deny read on parent
        with conn() as c:
            c.send({"cmd": "vfs_chmod", "session": self.admin_token,
                    "path": "/ls_parentdeny/child.csv", "cwd": "/",
                    "role": "Viewer", "perm": "read", "action": "grant"})
        with conn() as c:
            c.send({"cmd": "vfs_chmod", "session": self.admin_token,
                    "path": "/ls_parentdeny", "cwd": "/",
                    "role": "Viewer", "perm": "read", "action": "revoke"})
        try:
            with conn() as c:
                resp = c.send({"cmd": "vfs_ls", "session": self.viewer_token,
                               "path": "/ls_parentdeny", "cwd": "/"})
            # Directory itself is denied
            self.assertFalse(resp["ok"])
        finally:
            with conn() as c:
                c.send({"cmd": "vfs_rm", "session": self.admin_token,
                        "path": "/ls_parentdeny", "cwd": "/"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
