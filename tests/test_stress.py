"""
Stress tests for EFS-TDM.

Each test class uses its own dedicated admin/user accounts so that the
server's one-session-per-user enforcement never causes cross-test interference.
addCleanup() is used throughout so sessions are always released even on failure.

Coverage:
  1. High-volume sequential encrypt/decrypt — 50 files back-to-back
  2. High-volume sequential mask — 20 calls, correctness verified each time
  3. Medium file (32 KB) encrypt/decrypt roundtrip
  4. Large file (~960 KB) encrypt/decrypt roundtrip
  5. Large VFS send/fetch roundtrip
  6. 20 rapid login/logout cycles — no session leak
  7. 30 workers pinging simultaneously
  8. 20 workers mixed read/write — each worker uses its own session
  9. Deep VFS directory tree (10 levels)
 10. Large directory listing (30 files)
 11. VFS tree on populated structure
 12. Audit log queryable after many entries
 13. Audit log user-filter correct under concurrent writes
 14. Active session survives background load from other users
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

from core.db import init_db
from client.client import ServerConn
from server.server import EFSServer
from server.access_control import add_user

CERT = str(PROJECT_ROOT / "server_pkg" / "certs" / "cert.pem")
KEY  = str(PROJECT_ROOT / "server_pkg" / "certs" / "key.pem")
HOST = "127.0.0.1"

SMALL_PAYLOAD  = b"id,name,ssn\n1,Alice,123-45-6789\n" * 10
MEDIUM_PAYLOAD = SMALL_PAYLOAD * 100     # ~32 KB
LARGE_PAYLOAD  = SMALL_PAYLOAD * 3000    # ~960 KB

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

    # TestHighVolumeSequential
    add_user("sseq_admin",  "SSeqAdmin1!",  role="Admin", db_path=_db_path)

    # TestLargeFiles
    add_user("slarge_admin", "SLrgAdmin1!", role="Admin", db_path=_db_path)

    # TestRapidLoginLogout
    add_user("srlol_u1", "SRlolU1_1!", role="Contributor", db_path=_db_path)

    # TestSustainedConcurrent — one admin + 20 individual workers
    add_user("sconc_admin", "SConcAdm1!", role="Admin", db_path=_db_path)
    for i in range(1, 21):
        add_user(f"sconc_w{i}", f"SConcW{i}_1!", role="Contributor", db_path=_db_path)

    # TestVFSAtScale
    add_user("svfs_admin", "SVfsAdm1!", role="Admin", db_path=_db_path)

    # TestAuditLogAtScale
    add_user("saudit_admin", "SAuditAdm1!", role="Admin",       db_path=_db_path)
    add_user("saudit_user",  "SAuditUsr1!", role="Contributor", db_path=_db_path)

    # TestSessionSurvivesLoad — one subject + background workers
    add_user("ssurv_admin", "SSurvAdm1!", role="Admin", db_path=_db_path)
    for i in range(1, 6):
        add_user(f"ssurv_w{i}", f"SSurvW{i}_1!", role="Contributor", db_path=_db_path)

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


class TestHighVolumeSequential(unittest.TestCase):

    def setUp(self):
        self.token = _login("sseq_admin", "SSeqAdmin1!")
        self.addCleanup(_logout, self.token)

    def test_50_sequential_encrypt_decrypt_roundtrips(self):
        data_b64 = base64.b64encode(SMALL_PAYLOAD).decode()
        stored = []

        for i in range(50):
            with _conn() as c:
                r = c.send({"cmd": "encrypt", "session": self.token,
                            "filename": f"stress_seq_{i}.csv",
                            "data_b64": data_b64})
            self.assertTrue(r["ok"], f"encrypt {i} failed: {r}")
            stored.append(r["stored_as"])

        for fname in stored:
            with _conn() as c:
                r = c.send({"cmd": "decrypt", "session": self.token,
                            "filename": fname})
            self.assertTrue(r["ok"], f"decrypt {fname} failed")
            self.assertEqual(base64.b64decode(r["data_b64"]), SMALL_PAYLOAD)

    def test_20_sequential_mask_calls_correct(self):
        data_b64 = base64.b64encode(SMALL_PAYLOAD).decode()
        with _conn() as c:
            r = c.send({"cmd": "encrypt", "session": self.token,
                        "filename": "stress_mask_base.csv",
                        "data_b64": data_b64})
        self.assertTrue(r["ok"])
        fname = r["stored_as"]

        for _ in range(20):
            with _conn() as c:
                r = c.send({"cmd": "mask", "session": self.token,
                            "filename": fname, "role": "Analyst"})
            self.assertTrue(r["ok"])
            self.assertNotIn("123-45-6789", r["masked"])


class TestLargeFiles(unittest.TestCase):

    def setUp(self):
        self.token = _login("slarge_admin", "SLrgAdmin1!")
        self.addCleanup(_logout, self.token)

    def test_medium_file_roundtrip(self):
        data_b64 = base64.b64encode(MEDIUM_PAYLOAD).decode()
        with _conn() as c:
            r = c.send({"cmd": "encrypt", "session": self.token,
                        "filename": "stress_medium.csv", "data_b64": data_b64})
        self.assertTrue(r["ok"])

        with _conn() as c:
            r = c.send({"cmd": "decrypt", "session": self.token,
                        "filename": r["stored_as"]})
        self.assertTrue(r["ok"])
        self.assertEqual(base64.b64decode(r["data_b64"]), MEDIUM_PAYLOAD)

    def test_large_file_roundtrip(self):
        data_b64 = base64.b64encode(LARGE_PAYLOAD).decode()
        with _conn() as c:
            r = c.send({"cmd": "encrypt", "session": self.token,
                        "filename": "stress_large.csv", "data_b64": data_b64})
        self.assertTrue(r["ok"])

        with _conn() as c:
            r = c.send({"cmd": "decrypt", "session": self.token,
                        "filename": r["stored_as"]})
        self.assertTrue(r["ok"])
        self.assertEqual(base64.b64decode(r["data_b64"]), LARGE_PAYLOAD)

    def test_large_vfs_send_fetch_roundtrip(self):
        data_b64 = base64.b64encode(LARGE_PAYLOAD).decode()
        with _conn() as c:
            r = c.send({"cmd": "vfs_send", "session": self.token,
                        "path": "/stress_large_vfs.csv", "cwd": "/",
                        "data_b64": data_b64})
        self.assertTrue(r["ok"])

        with _conn() as c:
            r = c.send({"cmd": "vfs_fetch", "session": self.token,
                        "path": "/stress_large_vfs.csv", "cwd": "/", "raw": True})
        self.assertTrue(r["ok"])
        self.assertEqual(base64.b64decode(r["data_b64"]), LARGE_PAYLOAD)


class TestRapidLoginLogout(unittest.TestCase):

    def test_20_rapid_cycles_no_leak(self):
        from client.client import SessionExpired
        for i in range(20):
            token = _login("srlol_u1", "SRlolU1_1!")
            with _conn() as c:
                r = c.send({"cmd": "whoami", "session": token})
            self.assertTrue(r["ok"])
            _logout(token)

            rejected = False
            try:
                with _conn() as c:
                    r = c.send({"cmd": "whoami", "session": token})
                rejected = not r.get("ok")
            except SessionExpired:
                rejected = True
            self.assertTrue(rejected, f"revoked token accepted on cycle {i}")


class TestSustainedConcurrentConnections(unittest.TestCase):

    def test_30_workers_ping_simultaneously(self):
        errors = []

        def do_ping():
            try:
                with _conn() as c:
                    return c.send({"cmd": "ping"})
            except Exception as e:
                errors.append(str(e))
                return None

        with ThreadPoolExecutor(max_workers=30) as ex:
            futs = [ex.submit(do_ping) for _ in range(30)]
            results = [f.result() for f in as_completed(futs)]

        self.assertEqual(errors, [])
        for r in results:
            self.assertTrue(r and r.get("ok"))
            self.assertEqual(r["message"], "pong")

    def test_20_workers_each_own_session(self):
        data_b64 = base64.b64encode(SMALL_PAYLOAD).decode()
        errors = []

        def worker(i):
            try:
                creds = (f"sconc_w{i}", f"SConcW{i}_1!")
                token = _login(*creds)
                try:
                    with _conn() as c:
                        r = c.send({"cmd": "vfs_send", "session": token,
                                    "path": f"/sconc_w{i}.csv",
                                    "cwd": "/", "data_b64": data_b64})
                    assert r["ok"], f"vfs_send failed for worker {i}: {r}"
                finally:
                    _logout(token)
            except Exception as e:
                errors.append(str(e))

        with ThreadPoolExecutor(max_workers=20) as ex:
            futs = [ex.submit(worker, i) for i in range(1, 21)]
            for f in as_completed(futs):
                f.result()

        self.assertEqual(errors, [])


class TestVFSAtScale(unittest.TestCase):

    def setUp(self):
        self.token = _login("svfs_admin", "SVfsAdm1!")
        self.addCleanup(_logout, self.token)

    def test_deep_directory_tree_10_levels(self):
        path = ""
        for depth in range(10):
            path += f"/sdepth_{depth}"
            with _conn() as c:
                r = c.send({"cmd": "vfs_mkdir", "session": self.token,
                            "path": path, "cwd": "/"})
            self.assertTrue(r["ok"], f"mkdir failed at depth {depth}: {r}")

        with _conn() as c:
            r = c.send({"cmd": "vfs_stat", "session": self.token,
                        "path": path, "cwd": "/"})
        self.assertTrue(r["ok"])
        self.assertEqual(r["stat"]["type"], "dir")

    def test_large_directory_listing_30_files(self):
        with _conn() as c:
            c.send({"cmd": "vfs_mkdir", "session": self.token,
                    "path": "/sbigdir", "cwd": "/"})

        data_b64 = base64.b64encode(SMALL_PAYLOAD).decode()
        for i in range(30):
            with _conn() as c:
                c.send({"cmd": "vfs_send", "session": self.token,
                        "path": f"/sbigdir/file_{i:03d}.csv",
                        "cwd": "/", "data_b64": data_b64})

        with _conn() as c:
            r = c.send({"cmd": "vfs_ls", "session": self.token,
                        "path": "/sbigdir", "cwd": "/"})
        self.assertTrue(r["ok"])
        self.assertEqual(len(r["entries"]), 30)

    def test_tree_returns_all_entries(self):
        with _conn() as c:
            r = c.send({"cmd": "vfs_tree", "session": self.token,
                        "path": "/", "cwd": "/"})
        self.assertTrue(r["ok"])
        self.assertIsInstance(r["tree"], list)
        self.assertGreater(len(r["tree"]), 0)


class TestAuditLogAtScale(unittest.TestCase):

    def test_log_queryable_after_many_entries(self):
        token = _login("saudit_admin", "SAuditAdm1!")
        self.addCleanup(_logout, token)
        data_b64 = base64.b64encode(SMALL_PAYLOAD).decode()

        for i in range(30):
            with _conn() as c:
                c.send({"cmd": "encrypt", "session": token,
                        "filename": f"audit_scale_{i}.csv",
                        "data_b64": data_b64})

        with _conn() as c:
            r = c.send({"cmd": "audit_log", "session": token, "limit": 20})
        self.assertTrue(r["ok"])
        self.assertEqual(len(r["entries"]), 20)

        with _conn() as c:
            r = c.send({"cmd": "audit_log", "session": token, "action": "encrypt"})
        self.assertTrue(r["ok"])
        for entry in r["entries"]:
            self.assertEqual(entry["action"], "encrypt")

    def test_user_filter_correct_under_concurrent_writes(self):
        admin_token = _login("saudit_admin", "SAuditAdm1!")
        user_token  = _login("saudit_user",  "SAuditUsr1!")
        self.addCleanup(_logout, admin_token)
        self.addCleanup(_logout, user_token)

        data_b64 = base64.b64encode(SMALL_PAYLOAD).decode()

        def enc_batch(token, prefix, count):
            for i in range(count):
                with _conn() as c:
                    c.send({"cmd": "encrypt", "session": token,
                            "filename": f"{prefix}_{i}.csv",
                            "data_b64": data_b64})

        t1 = threading.Thread(target=enc_batch,
                              args=(admin_token, "saudit_admin_f", 10))
        t2 = threading.Thread(target=enc_batch,
                              args=(user_token,  "saudit_user_f",  10))
        t1.start(); t2.start()
        t1.join();  t2.join()

        with _conn() as c:
            r = c.send({"cmd": "audit_log", "session": admin_token,
                        "username": "saudit_admin"})
        self.assertTrue(r["ok"])
        for entry in r["entries"]:
            self.assertEqual(entry["username"], "saudit_admin")


class TestSessionSurvivesLoad(unittest.TestCase):

    def test_session_valid_while_other_users_create_load(self):
        subject_token = _login("ssurv_admin", "SSurvAdm1!")
        self.addCleanup(_logout, subject_token)

        stop = threading.Event()
        errors = []

        def background(i):
            while not stop.is_set():
                try:
                    tok = _login(f"ssurv_w{i}", f"SSurvW{i}_1!")
                    with _conn() as c:
                        c.send({"cmd": "ping"})
                    _logout(tok)
                except Exception as e:
                    errors.append(str(e))

        workers = [threading.Thread(target=background, args=(i,), daemon=True)
                   for i in range(1, 6)]
        for w in workers:
            w.start()

        time.sleep(0.5)

        with _conn() as c:
            r = c.send({"cmd": "whoami", "session": subject_token})
        self.assertTrue(r["ok"],
                        "subject session must remain valid under background load")
        self.assertEqual(r["username"], "ssurv_admin")

        stop.set()
        for w in workers:
            w.join(timeout=3)

        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
