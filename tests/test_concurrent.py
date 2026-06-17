"""
Concurrent and multi-user tests.

Verifies that the server handles simultaneous connections from multiple users
correctly — no session bleed, no data corruption, no race conditions on shared
VFS/DB state.

Each test class uses its own dedicated user accounts so that the server's
one-session-per-user enforcement never causes cross-test interference.

Coverage:
  1. Concurrent logins — N distinct users authenticate in parallel, each gets a distinct token
  2. One-session-per-user enforcement — second login for same user is rejected
  3. Concurrent encrypt — multiple users encrypt different files simultaneously
  4. Concurrent decrypt roundtrip — parallel decryption of pre-encrypted files
  5. Concurrent VFS mkdir — parallel directory creation under the same parent
  6. Concurrent VFS send — parallel file uploads to different VFS paths
  7. Concurrent read (fetch) — multiple users reading the same VFS file simultaneously
  8. VFS mv race — two clients rename the same node; exactly one wins
  9. Session isolation — commands from one session cannot affect another
 10. Logout invalidates only own session
 11. Revoked token rejected under concurrent load
 12. Role enforcement under concurrency — non-admin actions denied
 13. Concurrent audit log writes — chain intact after parallel events
 14. Parallel add of distinct users all succeed
 15. Duplicate add race — only one succeeds
"""

import base64
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from core.db import init_db, verify_audit_chain
from client.client import ServerConn
from server.server import EFSServer
from server.access_control import add_user

CERT = str(PROJECT_ROOT / "server_pkg" / "certs" / "cert.pem")
KEY  = str(PROJECT_ROOT / "server_pkg" / "certs" / "key.pem")
HOST = "127.0.0.1"

SAMPLE_CSV  = b"id,name,ssn,email\n1,Alice,123-45-6789,alice@example.com\n"
SAMPLE_TEXT = b"Hello from concurrent test\n" * 10

_server = None
_db_path = ""
_port = 0
_enc_dir = None


def setUpModule():
    global _server, _db_path, _port, _enc_dir
    import socket
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        _port = s.getsockname()[1]

    fd, _db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    init_db(_db_path)

    # Each test class gets its own dedicated users to avoid session conflicts.
    # Naming: c<class_abbrev>_<role>_<n>

    # TestConcurrentLogins
    for i in range(1, 6):
        add_user(f"clogin_u{i}", f"Login_U{i}_1!", role="Contributor", db_path=_db_path)

    # TestOneSessionPerUser
    add_user("c1sess_u1", "C1sess_U1_1!", role="Contributor", db_path=_db_path)

    # TestConcurrentEncrypt
    add_user("cenc_admin", "CEncAdmin1!", role="Admin", db_path=_db_path)

    # TestConcurrentVFS
    add_user("cvfs_admin",  "CVfsAdmin1!",  role="Admin",       db_path=_db_path)
    add_user("cvfs_user1",  "CVfsUser1_1!", role="Contributor", db_path=_db_path)
    add_user("cvfs_user2",  "CVfsUser2_1!", role="Contributor", db_path=_db_path)
    add_user("cvfs_user3",  "CVfsUser3_1!", role="Contributor", db_path=_db_path)

    # TestSessionIsolation
    add_user("cisol_u1", "CIsolU1_1!", role="Contributor", db_path=_db_path)
    add_user("cisol_u2", "CIsolU2_1!", role="Contributor", db_path=_db_path)
    add_user("cisol_u3", "CIsolU3_1!", role="Contributor", db_path=_db_path)

    # TestRoleEnforcementConcurrent
    add_user("crole_analyst",  "CRoleAnal1!",  role="Analyst",     db_path=_db_path)
    add_user("crole_guest",    "CRoleGuest1!", role="Guest",        db_path=_db_path)
    add_user("crole_contrib",  "CRoleCont1!",  role="Contributor",  db_path=_db_path)
    add_user("crole_contrib2", "CRoleCon2_1!", role="Contributor",  db_path=_db_path)
    add_user("crole_contrib3", "CRoleCon3_1!", role="Contributor",  db_path=_db_path)

    # TestAuditLogIntegrity
    add_user("caudit_admin", "CAuditAdm1!", role="Admin", db_path=_db_path)

    # TestConcurrentUserManagement
    add_user("cmgmt_admin", "CMgmtAdm1!", role="Admin", db_path=_db_path)

    from pathlib import Path
    _enc_dir = tempfile.TemporaryDirectory()
    _server = EFSServer(host=HOST, port=_port, cert=CERT, key=KEY, db_path=_db_path,
                        data_enc=Path(_enc_dir.name))
    t = threading.Thread(target=_server.start, daemon=True)
    t.start()

    for _ in range(50):
        try:
            with ServerConn(HOST, _port, CERT) as c:
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


def _conn():
    return ServerConn(HOST, _port, CERT)


def _login(username, password):
    with _conn() as c:
        r = c.send({"cmd": "login", "username": username, "password": password})
    assert r["ok"], f"login failed for {username}: {r}"
    return r["session"]


def _logout(token):
    try:
        with _conn() as c:
            c.send({"cmd": "logout", "session": token})
    except Exception:
        pass


class TestConcurrentLogins(unittest.TestCase):

    def test_parallel_logins_return_distinct_tokens(self):
        users = [(f"clogin_u{i}", f"Login_U{i}_1!") for i in range(1, 6)]
        errors = []

        def do_login(u, p):
            try:
                return _login(u, p)
            except Exception as e:
                errors.append(str(e))
                return None

        with ThreadPoolExecutor(max_workers=len(users)) as ex:
            futs = [ex.submit(do_login, u, p) for u, p in users]
            tokens = [f.result() for f in as_completed(futs)]

        self.assertEqual(errors, [])
        tokens = [t for t in tokens if t]
        self.assertEqual(len(set(tokens)), len(tokens), "tokens must all be distinct")

        for t in tokens:
            _logout(t)


class TestOneSessionPerUser(unittest.TestCase):

    def test_second_login_revokes_first_session(self):
        tok1 = _login("c1sess_u1", "C1sess_U1_1!")

        with _conn() as c:
            r = c.send({"cmd": "login", "username": "c1sess_u1",
                        "password": "C1sess_U1_1!"})
        self.assertTrue(r["ok"])
        tok2 = r["session"]
        self.addCleanup(_logout, tok2)
        self.assertNotEqual(tok1, tok2)

        # tok1 should now be revoked
        from client.client import SessionExpired
        with _conn() as c:
            try:
                r2 = c.send({"cmd": "whoami", "session": tok1})
                self.assertFalse(r2["ok"])
            except SessionExpired:
                pass  # expected — server reports Not authenticated

    def test_login_allowed_after_logout(self):
        tok1 = _login("c1sess_u1", "C1sess_U1_1!")
        _logout(tok1)

        tok2 = _login("c1sess_u1", "C1sess_U1_1!")
        self.addCleanup(_logout, tok2)
        self.assertIsNotNone(tok2)
        self.assertNotEqual(tok1, tok2)


class TestConcurrentEncrypt(unittest.TestCase):

    def setUp(self):
        self.token = _login("cenc_admin", "CEncAdmin1!")
        self.addCleanup(_logout, self.token)

    def test_parallel_encrypts_all_succeed(self):
        data_b64 = base64.b64encode(SAMPLE_CSV).decode()
        errors = []

        def do_encrypt(i):
            try:
                with _conn() as c:
                    r = c.send({
                        "cmd": "encrypt",
                        "session": self.token,
                        "filename": f"concurrent_{i}.csv",
                        "data_b64": data_b64,
                    })
                return r
            except Exception as e:
                errors.append(str(e))
                return None

        with ThreadPoolExecutor(max_workers=8) as ex:
            futs = [ex.submit(do_encrypt, i) for i in range(8)]
            results = [f.result() for f in as_completed(futs)]

        self.assertEqual(errors, [])
        ok_results = [r for r in results if r and r.get("ok")]
        self.assertEqual(len(ok_results), 8)
        stored = {r["stored_as"] for r in ok_results}
        self.assertEqual(len(stored), 8, "each file must have a unique stored name")

    def test_parallel_decrypt_roundtrip(self):
        data_b64 = base64.b64encode(SAMPLE_CSV).decode()
        filenames = []
        for i in range(4):
            with _conn() as c:
                r = c.send({
                    "cmd": "encrypt",
                    "session": self.token,
                    "filename": f"roundtrip_{i}.csv",
                    "data_b64": data_b64,
                })
            self.assertTrue(r["ok"])
            filenames.append(r["stored_as"])

        errors = []

        def do_decrypt(fname):
            try:
                with _conn() as c:
                    return c.send({"cmd": "decrypt", "session": self.token,
                                   "filename": fname})
            except Exception as e:
                errors.append(str(e))
                return None

        with ThreadPoolExecutor(max_workers=4) as ex:
            futs = [ex.submit(do_decrypt, fn) for fn in filenames]
            results = [f.result() for f in as_completed(futs)]

        self.assertEqual(errors, [])
        for r in results:
            self.assertTrue(r and r.get("ok"), r)
            self.assertEqual(base64.b64decode(r["data_b64"]), SAMPLE_CSV)


class TestConcurrentVFS(unittest.TestCase):

    def setUp(self):
        self.admin = _login("cvfs_admin", "CVfsAdmin1!")
        self.users = [
            _login("cvfs_user1", "CVfsUser1_1!"),
            _login("cvfs_user2", "CVfsUser2_1!"),
            _login("cvfs_user3", "CVfsUser3_1!"),
        ]
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        _logout(self.admin)
        for t in self.users:
            _logout(t)

    def test_parallel_mkdir_under_same_parent(self):
        with _conn() as c:
            c.send({"cmd": "vfs_mkdir", "session": self.admin,
                    "path": "/cvfs_dirs", "cwd": "/"})

        errors = []

        def do_mkdir(i):
            try:
                with _conn() as c:
                    return c.send({"cmd": "vfs_mkdir", "session": self.admin,
                                   "path": f"/cvfs_dirs/sub_{i}", "cwd": "/"})
            except Exception as e:
                errors.append(str(e))
                return None

        with ThreadPoolExecutor(max_workers=6) as ex:
            futs = [ex.submit(do_mkdir, i) for i in range(6)]
            results = [f.result() for f in as_completed(futs)]

        self.assertEqual(errors, [])
        self.assertEqual(sum(1 for r in results if r and r.get("ok")), 6)

        with _conn() as c:
            ls = c.send({"cmd": "vfs_ls", "session": self.admin,
                         "path": "/cvfs_dirs", "cwd": "/"})
        self.assertTrue(ls["ok"])
        self.assertEqual(len(ls["entries"]), 6)

    def test_parallel_send_to_different_paths(self):
        with _conn() as c:
            c.send({"cmd": "vfs_mkdir", "session": self.admin,
                    "path": "/cvfs_uploads", "cwd": "/"})

        data_b64 = base64.b64encode(SAMPLE_TEXT).decode()
        errors = []

        def do_send(token, i):
            try:
                with _conn() as c:
                    return c.send({
                        "cmd": "vfs_send",
                        "session": token,
                        "path": f"/cvfs_uploads/file_{i}.txt",
                        "cwd": "/",
                        "data_b64": data_b64,
                    })
            except Exception as e:
                errors.append(str(e))
                return None

        tasks = [(self.users[i % 3], i) for i in range(6)]
        with ThreadPoolExecutor(max_workers=6) as ex:
            futs = [ex.submit(do_send, tok, i) for tok, i in tasks]
            results = [f.result() for f in as_completed(futs)]

        self.assertEqual(errors, [])
        self.assertEqual(sum(1 for r in results if r and r.get("ok")), 6)

    def test_parallel_fetch_same_file(self):
        data_b64 = base64.b64encode(SAMPLE_TEXT).decode()
        with _conn() as c:
            r = c.send({"cmd": "vfs_send", "session": self.admin,
                        "path": "/cvfs_shared.txt", "cwd": "/",
                        "data_b64": data_b64})
        self.assertTrue(r["ok"])

        errors = []

        def do_fetch(token):
            try:
                with _conn() as c:
                    return c.send({"cmd": "vfs_fetch", "session": token,
                                   "path": "/cvfs_shared.txt", "cwd": "/",
                                   "raw": False})
            except Exception as e:
                errors.append(str(e))
                return None

        tokens = [self.admin] + self.users
        with ThreadPoolExecutor(max_workers=4) as ex:
            futs = [ex.submit(do_fetch, t) for t in tokens]
            results = [f.result() for f in as_completed(futs)]

        self.assertEqual(errors, [])
        for r in results:
            self.assertTrue(r and r.get("ok"), r)

    def test_parallel_mv_race_exactly_one_wins(self):
        with _conn() as c:
            c.send({"cmd": "vfs_mkdir", "session": self.admin,
                    "path": "/cvfs_race_src", "cwd": "/"})
            c.send({"cmd": "vfs_mkdir", "session": self.admin,
                    "path": "/cvfs_race_a", "cwd": "/"})
            c.send({"cmd": "vfs_mkdir", "session": self.admin,
                    "path": "/cvfs_race_b", "cwd": "/"})

        results = []

        def do_mv(dst):
            try:
                with _conn() as c:
                    return c.send({"cmd": "vfs_mv", "session": self.admin,
                                   "src": "/cvfs_race_src", "dst": dst, "cwd": "/"})
            except Exception as e:
                return {"ok": False, "error": str(e)}

        with ThreadPoolExecutor(max_workers=2) as ex:
            futs = [ex.submit(do_mv, "/cvfs_race_a"),
                    ex.submit(do_mv, "/cvfs_race_b")]
            results = [f.result() for f in as_completed(futs)]

        ok_count = sum(1 for r in results if r.get("ok"))
        self.assertEqual(ok_count, 1, "exactly one mv must succeed")


class TestSessionIsolation(unittest.TestCase):

    def test_sessions_show_correct_owner(self):
        tok1 = _login("cisol_u1", "CIsolU1_1!")
        tok2 = _login("cisol_u2", "CIsolU2_1!")
        self.addCleanup(_logout, tok1)
        self.addCleanup(_logout, tok2)

        with _conn() as c:
            r1 = c.send({"cmd": "whoami", "session": tok1})
        with _conn() as c:
            r2 = c.send({"cmd": "whoami", "session": tok2})

        self.assertEqual(r1["username"], "cisol_u1")
        self.assertEqual(r2["username"], "cisol_u2")

    def test_logout_invalidates_only_own_session(self):
        tok1 = _login("cisol_u1", "CIsolU1_1!")
        tok2 = _login("cisol_u2", "CIsolU2_1!")
        self.addCleanup(_logout, tok2)

        _logout(tok1)

        with _conn() as c:
            r2 = c.send({"cmd": "whoami", "session": tok2})
        self.assertTrue(r2["ok"], "tok2 must still be valid after tok1 logout")

    def test_revoked_token_rejected_concurrently(self):
        tok = _login("cisol_u3", "CIsolU3_1!")
        _logout(tok)

        rejected = []

        def try_use():
            try:
                with _conn() as c:
                    r = c.send({"cmd": "whoami", "session": tok})
                rejected.append(not r.get("ok"))
            except Exception:
                rejected.append(True)

        with ThreadPoolExecutor(max_workers=5) as ex:
            futs = [ex.submit(try_use) for _ in range(5)]
            for f in as_completed(futs):
                f.result()

        self.assertTrue(all(rejected), "all uses of a revoked token must be rejected")


class TestRoleEnforcementConcurrent(unittest.TestCase):

    def test_concurrent_non_admin_cannot_add_user(self):
        tokens = [
            _login("crole_analyst",  "CRoleAnal1!"),
            _login("crole_guest",    "CRoleGuest1!"),
            _login("crole_contrib",  "CRoleCont1!"),
        ]
        for t in tokens:
            self.addCleanup(_logout, t)

        results = []

        def try_add(token):
            with _conn() as c:
                return c.send({"cmd": "add_user", "session": token,
                               "username": "rogue", "password": "Rogue1234!",
                               "role": "Admin"})

        with ThreadPoolExecutor(max_workers=3) as ex:
            futs = [ex.submit(try_add, t) for t in tokens]
            results = [f.result() for f in as_completed(futs)]

        for r in results:
            self.assertFalse(r["ok"])

    def test_concurrent_audit_log_denied_for_non_auditor(self):
        tokens = [
            _login("crole_contrib",  "CRoleCont1!"),
            _login("crole_contrib2", "CRoleCon2_1!"),
            _login("crole_contrib3", "CRoleCon3_1!"),
        ]
        for t in tokens:
            self.addCleanup(_logout, t)

        results = []

        def try_audit(token):
            with _conn() as c:
                return c.send({"cmd": "audit_log", "session": token})

        with ThreadPoolExecutor(max_workers=3) as ex:
            futs = [ex.submit(try_audit, t) for t in tokens]
            results = [f.result() for f in as_completed(futs)]

        for r in results:
            self.assertFalse(r["ok"])


class TestAuditLogIntegrityUnderConcurrency(unittest.TestCase):

    def test_audit_chain_intact_after_concurrent_writes(self):
        token = _login("caudit_admin", "CAuditAdm1!")
        self.addCleanup(_logout, token)

        data_b64 = base64.b64encode(SAMPLE_CSV).decode()

        def do_encrypt(i):
            with _conn() as c:
                c.send({"cmd": "encrypt", "session": token,
                        "filename": f"audit_chain_{i}.csv",
                        "data_b64": data_b64})

        with ThreadPoolExecutor(max_workers=8) as ex:
            futs = [ex.submit(do_encrypt, i) for i in range(8)]
            for f in as_completed(futs):
                f.result()

        self.assertTrue(verify_audit_chain(_db_path), "audit chain broken")


class TestConcurrentUserManagement(unittest.TestCase):

    def setUp(self):
        self.token = _login("cmgmt_admin", "CMgmtAdm1!")
        self.addCleanup(_logout, self.token)

    def test_parallel_add_distinct_users(self):
        errors = []

        def add_req(i):
            try:
                with _conn() as c:
                    return c.send({"cmd": "add_user", "session": self.token,
                                   "username": f"tmpuser_{i}",
                                   "password": f"TmpUser{i}_1!",
                                   "role": "Guest"})
            except Exception as e:
                errors.append(str(e))
                return None

        with ThreadPoolExecutor(max_workers=5) as ex:
            futs = [ex.submit(add_req, i) for i in range(5)]
            results = [f.result() for f in as_completed(futs)]

        self.assertEqual(errors, [])
        self.assertEqual(sum(1 for r in results if r and r.get("ok")), 5)

        with _conn() as c:
            lu = c.send({"cmd": "list_users", "session": self.token})
        names = {u["username"] for u in lu["users"]}
        for i in range(5):
            self.assertIn(f"tmpuser_{i}", names)

    def test_duplicate_add_only_one_succeeds(self):
        results = []

        def add_dup():
            with _conn() as c:
                return c.send({"cmd": "add_user", "session": self.token,
                               "username": "duprace",
                               "password": "DupRace1_!",
                               "role": "Guest"})

        with ThreadPoolExecutor(max_workers=4) as ex:
            futs = [ex.submit(add_dup) for _ in range(4)]
            results = [f.result() for f in as_completed(futs)]

        self.assertEqual(sum(1 for r in results if r.get("ok")), 1,
                         "only one duplicate-name add should succeed")


class TestMixedConcurrentLoad(unittest.TestCase):
    """
    All-at-once stress test: multiple users running different operations
    simultaneously against a live server — encrypt, VFS send/fetch, user
    management, audit log, and role-enforcement checks all in parallel.

    This catches race conditions that per-class isolated tests cannot detect.
    """

    def setUp(self):
        # Use dedicated users to avoid session conflicts with other test classes
        self.admin   = _login("cmgmt_admin",  "CMgmtAdm1!")
        self.contrib = _login("cvfs_user1",   "CVfsUser1_1!")
        self.analyst = _login("crole_analyst", "CRoleAnal1!")
        self.auditor = None  # logged in per-test to avoid re-use issues

    def tearDown(self):
        for tok in [self.admin, self.contrib, self.analyst]:
            if tok:
                _logout(tok)

    def test_mixed_operations_all_succeed_or_fail_correctly(self):
        """
        Fires 7 concurrent workers each doing a different category of operation:
          1. Admin encrypts a file
          2. Contributor sends a VFS file
          3. Contributor fetches a VFS file (pre-uploaded)
          4. Admin lists users
          5. Analyst tries to add a user (must be denied)
          6. Admin does a whoami
          7. Contributor creates a VFS directory

        Asserts:
          - No unhandled exceptions from any worker
          - Permitted operations succeed
          - Denied operations return ok=False (not crash)
        """
        # Pre-upload a file for the fetch worker
        data_b64 = base64.b64encode(SAMPLE_TEXT).decode()
        with _conn() as c:
            r = c.send({"cmd": "vfs_send", "session": self.admin,
                        "path": "/mixed_shared.txt", "cwd": "/",
                        "data_b64": data_b64})
        self.assertTrue(r["ok"], f"pre-upload failed: {r}")

        results = {}
        errors  = {}

        def worker_encrypt():
            try:
                with _conn() as c:
                    return c.send({"cmd": "encrypt", "session": self.admin,
                                   "filename": "mixed_enc.csv",
                                   "data_b64": base64.b64encode(SAMPLE_CSV).decode()})
            except Exception as e:
                return {"ok": False, "error": str(e)}

        def worker_vfs_send():
            try:
                with _conn() as c:
                    return c.send({"cmd": "vfs_send", "session": self.contrib,
                                   "path": "/mixed_contrib.txt", "cwd": "/",
                                   "data_b64": data_b64})
            except Exception as e:
                return {"ok": False, "error": str(e)}

        def worker_vfs_fetch():
            try:
                with _conn() as c:
                    return c.send({"cmd": "vfs_fetch", "session": self.contrib,
                                   "path": "/mixed_shared.txt", "cwd": "/",
                                   "raw": False})
            except Exception as e:
                return {"ok": False, "error": str(e)}

        def worker_list_users():
            try:
                with _conn() as c:
                    return c.send({"cmd": "list_users", "session": self.admin})
            except Exception as e:
                return {"ok": False, "error": str(e)}

        def worker_analyst_add_user():
            # Must be denied — analyst lacks manage_users
            try:
                with _conn() as c:
                    return c.send({"cmd": "add_user", "session": self.analyst,
                                   "username": "mixed_rogue", "password": "Rogue1_!",
                                   "role": "Guest"})
            except Exception as e:
                return {"ok": False, "error": str(e)}

        def worker_whoami():
            try:
                with _conn() as c:
                    return c.send({"cmd": "whoami", "session": self.admin})
            except Exception as e:
                return {"ok": False, "error": str(e)}

        def worker_vfs_mkdir():
            try:
                with _conn() as c:
                    return c.send({"cmd": "vfs_mkdir", "session": self.contrib,
                                   "path": "/mixed_dir", "cwd": "/"})
            except Exception as e:
                return {"ok": False, "error": str(e)}

        workers = {
            "encrypt":          worker_encrypt,
            "vfs_send":         worker_vfs_send,
            "vfs_fetch":        worker_vfs_fetch,
            "list_users":       worker_list_users,
            "analyst_add_user": worker_analyst_add_user,
            "whoami":           worker_whoami,
            "vfs_mkdir":        worker_vfs_mkdir,
        }

        with ThreadPoolExecutor(max_workers=len(workers)) as ex:
            futs = {name: ex.submit(fn) for name, fn in workers.items()}
            for name, fut in futs.items():
                try:
                    results[name] = fut.result(timeout=15)
                except Exception as e:
                    errors[name] = str(e)

        self.assertEqual(errors, {}, f"workers raised exceptions: {errors}")

        # Permitted operations must succeed
        for op in ("encrypt", "vfs_send", "vfs_fetch", "list_users", "whoami", "vfs_mkdir"):
            self.assertTrue(results[op].get("ok"),
                            f"{op} should succeed but got: {results[op]}")

        # Denied operation must fail cleanly (not crash)
        self.assertFalse(results["analyst_add_user"].get("ok"),
                         "analyst add_user should be denied")
        self.assertIn("Permission denied", results["analyst_add_user"].get("error", ""))


if __name__ == "__main__":
    unittest.main(verbosity=2)
