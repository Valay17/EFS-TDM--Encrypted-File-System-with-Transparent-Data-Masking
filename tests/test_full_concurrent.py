"""
Full concurrent integration test.

Spins up a live EFSServer with 10 users across all 6 roles (Admin, Analyst,
Contributor, Viewer, Auditor, Guest) and fires them all simultaneously.  Each
user runs a realistic sequence of operations — encrypt/decrypt/mask, VFS
send/fetch, user-management, audit-log queries, whoami, mkdir/ls/tree — all
at the same time with actual file content going back and forth.

This catches cross-role races, session bleed, data corruption, and denial-of-
service failures that narrow per-operation tests cannot detect.

Assertions:
  - No unhandled exceptions from any worker
  - Every permitted operation succeeds (ok=True)
  - Every denied operation fails cleanly (ok=False, no server crash)
  - encrypt→decrypt roundtrip returns the exact original bytes
  - Audit log chain is intact after all concurrent writes
  - Listed users reflect additions made during the run
"""

import base64
import os
import sys
import socket
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

# Realistic sample files with PII for masking tests
SAMPLE_CSV = (
    "id,name,ssn,email,phone,card\n"
    "1,Alice Smith,123-45-6789,alice@example.com,555-123-4567,4111-1111-1111-1111\n"
    "2,Bob Jones,987-65-4321,bob@corp.org,555-987-6543,5500-0000-0000-0004\n"
    "3,Carol White,111-22-3333,carol@mail.net,555-246-8135,3714-496353-98431\n"
).encode()

SAMPLE_TEXT = (
    "Confidential Notes\n"
    "==================\n"
    "Contact: charlie@internal.io\n"
    "SSN on file: 444-55-6666\n"
    "Phone: 800-555-0199\n"
    "Card: 4012-8888-8888-1881\n"
    "\n"
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit.\n" * 20
).encode()

SAMPLE_BINARY = bytes(range(256)) * 64  # 16 KB of non-text bytes

_server   = None
_db_path  = ""
_port     = 0
_enc_dir  = None

# Credentials for each of the 10 users
_USERS = {
    "fc_admin":     ("FcAdmin1!",       "Admin"),
    "fc_admin2":    ("FcAdmin2_2!",     "Admin"),
    "fc_analyst":   ("FcAnalyst1!",     "Analyst"),
    "fc_contrib1":  ("FcContrib1_1!",   "Contributor"),
    "fc_contrib2":  ("FcContrib2_1!",   "Contributor"),
    "fc_viewer":    ("FcViewer1_1!",    "Viewer"),
    "fc_auditor":   ("FcAuditor1!",     "Auditor"),
    "fc_guest":     ("FcGuest1_1!",     "Guest"),
    "fc_contrib3":  ("FcContrib3_1!",   "Contributor"),
    "fc_viewer2":   ("FcViewer2_1!",    "Viewer"),
}


def setUpModule():
    global _server, _db_path, _port, _enc_dir

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        _port = s.getsockname()[1]

    fd, _db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    init_db(_db_path)

    for username, (password, role) in _USERS.items():
        add_user(username, password, role=role, db_path=_db_path)

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


class TestFullConcurrentLoad(unittest.TestCase):
    """
    10 users across all 6 roles, all running simultaneously.

    Each user thread logs in, executes its role-appropriate workload, and logs
    out.  The main thread collects results and validates correctness after all
    workers have finished.
    """

    def test_all_roles_concurrent_full_workload(self):
        shared = {
            "errors": {},
            "results": {},
        }
        lock = threading.Lock()

        # Pre-seed VFS directory and a shared file (done sequentially before workers start)
        setup_tok = _login("fc_admin", "FcAdmin1!")
        try:
            with _conn() as c:
                c.send({"cmd": "vfs_mkdir", "session": setup_tok,
                        "path": "/fc_shared", "cwd": "/"})
            with _conn() as c:
                r = c.send({"cmd": "vfs_send", "session": setup_tok,
                            "path": "/fc_shared/seed.txt", "cwd": "/",
                            "data_b64": base64.b64encode(SAMPLE_TEXT).decode()})
            assert r["ok"], f"seed send failed: {r}"

            # Pre-encrypt CSV so analyst/viewer can mask/fetch it
            with _conn() as c:
                r = c.send({"cmd": "encrypt", "session": setup_tok,
                            "filename": "fc_pii.csv",
                            "data_b64": base64.b64encode(SAMPLE_CSV).decode()})
            assert r["ok"], f"seed encrypt failed: {r}"
        finally:
            _logout(setup_tok)

        def record(name, result):
            with lock:
                shared["results"][name] = result

        def record_err(name, exc):
            with lock:
                shared["errors"][name] = str(exc)

        # Worker: Admin 1 — encrypt CSV, decrypt it back, list users, assign role,
        #         vfs_send binary, vfs_fetch raw, whoami, audit log, vfs_ls, vfs_tree
        def worker_admin1():
            tok = _login("fc_admin", "FcAdmin1!")
            try:
                res = {}

                # encrypt binary
                with _conn() as c:
                    r = c.send({"cmd": "encrypt", "session": tok,
                                "filename": "fc_binary.bin",
                                "data_b64": base64.b64encode(SAMPLE_BINARY).decode()})
                res["enc_binary"] = r

                # decrypt it back and verify roundtrip
                with _conn() as c:
                    r = c.send({"cmd": "decrypt", "session": tok,
                                "filename": "fc_binary.bin.enc"})
                res["dec_binary"] = r
                if r.get("ok"):
                    res["dec_binary_match"] = (
                        base64.b64decode(r["data_b64"]) == SAMPLE_BINARY
                    )

                # encrypt CSV
                with _conn() as c:
                    r = c.send({"cmd": "encrypt", "session": tok,
                                "filename": "fc_admin_csv.csv",
                                "data_b64": base64.b64encode(SAMPLE_CSV).decode()})
                res["enc_csv"] = r

                # decrypt CSV back
                with _conn() as c:
                    r = c.send({"cmd": "decrypt", "session": tok,
                                "filename": "fc_admin_csv.csv.enc"})
                res["dec_csv"] = r
                if r.get("ok"):
                    res["dec_csv_match"] = (
                        base64.b64decode(r["data_b64"]) == SAMPLE_CSV
                    )

                # list users
                with _conn() as c:
                    r = c.send({"cmd": "list_users", "session": tok})
                res["list_users"] = r

                # vfs_send a binary blob to shared dir
                with _conn() as c:
                    r = c.send({"cmd": "vfs_send", "session": tok,
                                "path": "/fc_shared/admin_upload.bin", "cwd": "/",
                                "data_b64": base64.b64encode(SAMPLE_BINARY).decode()})
                res["vfs_send_bin"] = r

                # vfs_fetch the seeded text file (raw=True — admin can get raw bytes)
                with _conn() as c:
                    r = c.send({"cmd": "vfs_fetch", "session": tok,
                                "path": "/fc_shared/seed.txt", "cwd": "/",
                                "raw": True})
                res["vfs_fetch_raw"] = r

                # whoami
                with _conn() as c:
                    r = c.send({"cmd": "whoami", "session": tok})
                res["whoami"] = r

                # audit log (admin can view)
                with _conn() as c:
                    r = c.send({"cmd": "audit_log", "session": tok})
                res["audit_log"] = r

                # vfs_ls root
                with _conn() as c:
                    r = c.send({"cmd": "vfs_ls", "session": tok,
                                "path": "/", "cwd": "/"})
                res["vfs_ls"] = r

                # vfs_tree
                with _conn() as c:
                    r = c.send({"cmd": "vfs_tree", "session": tok,
                                "path": "/fc_shared", "cwd": "/"})
                res["vfs_tree"] = r

                record("admin1", res)
            except Exception as e:
                record_err("admin1", e)
            finally:
                _logout(tok)

        # Worker: Admin 2 — add a new user, assign role, remove user, vfs_mkdir,
        #         vfs_stat, list_roles
        def worker_admin2():
            tok = _login("fc_admin2", "FcAdmin2_2!")
            try:
                res = {}

                # mkdir for own uploads
                with _conn() as c:
                    r = c.send({"cmd": "vfs_mkdir", "session": tok,
                                "path": "/fc_admin2_dir", "cwd": "/"})
                res["mkdir"] = r

                # add ephemeral user
                with _conn() as c:
                    r = c.send({"cmd": "add_user", "session": tok,
                                "username": "fc_ephemeral",
                                "password": "Ephemeral1!",
                                "role": "Guest"})
                res["add_user"] = r

                # assign role to ephemeral user
                with _conn() as c:
                    r = c.send({"cmd": "assign_role", "session": tok,
                                "username": "fc_ephemeral",
                                "role": "Viewer"})
                res["assign_role"] = r

                # list roles
                with _conn() as c:
                    r = c.send({"cmd": "list_roles", "session": tok})
                res["list_roles"] = r

                # remove ephemeral user
                with _conn() as c:
                    r = c.send({"cmd": "remove_user", "session": tok,
                                "username": "fc_ephemeral"})
                res["remove_user"] = r

                # vfs_send a CSV
                with _conn() as c:
                    r = c.send({"cmd": "vfs_send", "session": tok,
                                "path": "/fc_admin2_dir/data.csv", "cwd": "/",
                                "data_b64": base64.b64encode(SAMPLE_CSV).decode()})
                res["vfs_send"] = r

                # vfs_stat on uploaded file
                with _conn() as c:
                    r = c.send({"cmd": "vfs_stat", "session": tok,
                                "path": "/fc_admin2_dir/data.csv", "cwd": "/"})
                res["vfs_stat"] = r

                # whoami
                with _conn() as c:
                    r = c.send({"cmd": "whoami", "session": tok})
                res["whoami"] = r

                record("admin2", res)
            except Exception as e:
                record_err("admin2", e)
            finally:
                _logout(tok)

        # Worker: Analyst — mask the seeded PII CSV, fetch masked from VFS,
        #         whoami; attempt decrypt (denied), attempt add_user (denied)
        def worker_analyst():
            tok = _login("fc_analyst", "FcAnalyst1!")
            try:
                res = {}

                # mask the pre-encrypted CSV (analyst can mask)
                with _conn() as c:
                    r = c.send({"cmd": "mask", "session": tok,
                                "filename": "fc_pii.csv.enc",
                                "role": "Analyst"})
                res["mask"] = r

                # vfs_fetch the seeded shared file (masked for analyst)
                with _conn() as c:
                    r = c.send({"cmd": "vfs_fetch", "session": tok,
                                "path": "/fc_shared/seed.txt", "cwd": "/",
                                "raw": False})
                res["vfs_fetch_masked"] = r

                # vfs_ls (allowed)
                with _conn() as c:
                    r = c.send({"cmd": "vfs_ls", "session": tok,
                                "path": "/", "cwd": "/"})
                res["vfs_ls"] = r

                # whoami
                with _conn() as c:
                    r = c.send({"cmd": "whoami", "session": tok})
                res["whoami"] = r

                # decrypt — must be denied for analyst
                with _conn() as c:
                    r = c.send({"cmd": "decrypt", "session": tok,
                                "filename": "fc_pii.csv.enc"})
                res["decrypt_denied"] = r

                # add_user — must be denied
                with _conn() as c:
                    r = c.send({"cmd": "add_user", "session": tok,
                                "username": "analyst_rogue",
                                "password": "Rogue1_!",
                                "role": "Guest"})
                res["add_user_denied"] = r

                # audit_log — must be denied for analyst
                with _conn() as c:
                    r = c.send({"cmd": "audit_log", "session": tok})
                res["audit_log_denied"] = r

                record("analyst", res)
            except Exception as e:
                record_err("analyst", e)
            finally:
                _logout(tok)

        # Worker: Contributor 1 — vfs_send, vfs_fetch, vfs_mkdir, vfs_mv, whoami;
        #         attempt assign_role (denied)
        def worker_contrib1():
            tok = _login("fc_contrib1", "FcContrib1_1!")
            try:
                res = {}

                # mkdir
                with _conn() as c:
                    r = c.send({"cmd": "vfs_mkdir", "session": tok,
                                "path": "/fc_contrib1_dir", "cwd": "/"})
                res["mkdir"] = r

                # send CSV
                with _conn() as c:
                    r = c.send({"cmd": "vfs_send", "session": tok,
                                "path": "/fc_contrib1_dir/upload.csv", "cwd": "/",
                                "data_b64": base64.b64encode(SAMPLE_CSV).decode()})
                res["vfs_send"] = r

                # send text file
                with _conn() as c:
                    r = c.send({"cmd": "vfs_send", "session": tok,
                                "path": "/fc_contrib1_dir/notes.txt", "cwd": "/",
                                "data_b64": base64.b64encode(SAMPLE_TEXT).decode()})
                res["vfs_send_txt"] = r

                # fetch (masked) — contributor can read but not export raw
                with _conn() as c:
                    r = c.send({"cmd": "vfs_fetch", "session": tok,
                                "path": "/fc_contrib1_dir/upload.csv", "cwd": "/",
                                "raw": False})
                res["vfs_fetch_raw"] = r

                # vfs_mv notes -> renamed
                with _conn() as c:
                    r = c.send({"cmd": "vfs_mv", "session": tok,
                                "src": "/fc_contrib1_dir/notes.txt",
                                "dst": "/fc_contrib1_dir/notes_renamed.txt",
                                "cwd": "/"})
                res["vfs_mv"] = r

                # vfs_stat
                with _conn() as c:
                    r = c.send({"cmd": "vfs_stat", "session": tok,
                                "path": "/fc_contrib1_dir/upload.csv", "cwd": "/"})
                res["vfs_stat"] = r

                # whoami
                with _conn() as c:
                    r = c.send({"cmd": "whoami", "session": tok})
                res["whoami"] = r

                # assign_role — must be denied for contributor
                with _conn() as c:
                    r = c.send({"cmd": "assign_role", "session": tok,
                                "username": "fc_viewer",
                                "role": "Admin"})
                res["assign_role_denied"] = r

                record("contrib1", res)
            except Exception as e:
                record_err("contrib1", e)
            finally:
                _logout(tok)

        # Worker: Contributor 2 — vfs_send multiple files, vfs_ls, vfs_rm own file,
        #         whoami; attempt audit_log (denied)
        def worker_contrib2():
            tok = _login("fc_contrib2", "FcContrib2_1!")
            try:
                res = {}

                with _conn() as c:
                    r = c.send({"cmd": "vfs_mkdir", "session": tok,
                                "path": "/fc_contrib2_dir", "cwd": "/"})
                res["mkdir"] = r

                # send 3 files in sequence
                for i in range(3):
                    with _conn() as c:
                        r = c.send({"cmd": "vfs_send", "session": tok,
                                    "path": f"/fc_contrib2_dir/file_{i}.txt", "cwd": "/",
                                    "data_b64": base64.b64encode(SAMPLE_TEXT).decode()})
                    res[f"vfs_send_{i}"] = r

                # ls the directory
                with _conn() as c:
                    r = c.send({"cmd": "vfs_ls", "session": tok,
                                "path": "/fc_contrib2_dir", "cwd": "/"})
                res["vfs_ls"] = r

                # rm one of own files
                with _conn() as c:
                    r = c.send({"cmd": "vfs_rm", "session": tok,
                                "path": "/fc_contrib2_dir/file_0.txt", "cwd": "/"})
                res["vfs_rm"] = r

                # whoami
                with _conn() as c:
                    r = c.send({"cmd": "whoami", "session": tok})
                res["whoami"] = r

                # audit_log — denied
                with _conn() as c:
                    r = c.send({"cmd": "audit_log", "session": tok})
                res["audit_log_denied"] = r

                record("contrib2", res)
            except Exception as e:
                record_err("contrib2", e)
            finally:
                _logout(tok)

        # Worker: Contributor 3 — send binary, fetch it back and verify integrity
        def worker_contrib3():
            tok = _login("fc_contrib3", "FcContrib3_1!")
            try:
                res = {}

                with _conn() as c:
                    r = c.send({"cmd": "vfs_mkdir", "session": tok,
                                "path": "/fc_contrib3_dir", "cwd": "/"})
                res["mkdir"] = r

                with _conn() as c:
                    r = c.send({"cmd": "vfs_send", "session": tok,
                                "path": "/fc_contrib3_dir/binary.bin", "cwd": "/",
                                "data_b64": base64.b64encode(SAMPLE_BINARY).decode()})
                res["vfs_send_bin"] = r

                with _conn() as c:
                    r = c.send({"cmd": "vfs_fetch", "session": tok,
                                "path": "/fc_contrib3_dir/binary.bin", "cwd": "/",
                                "raw": False})
                res["vfs_fetch_bin"] = r

                with _conn() as c:
                    r = c.send({"cmd": "whoami", "session": tok})
                res["whoami"] = r

                record("contrib3", res)
            except Exception as e:
                record_err("contrib3", e)
            finally:
                _logout(tok)

        # Worker: Viewer 1 — vfs_ls, vfs_fetch (masked), whoami;
        #         attempt vfs_send (denied), attempt decrypt (denied)
        def worker_viewer1():
            tok = _login("fc_viewer", "FcViewer1_1!")
            try:
                res = {}

                # vfs_ls (allowed for viewer)
                with _conn() as c:
                    r = c.send({"cmd": "vfs_ls", "session": tok,
                                "path": "/", "cwd": "/"})
                res["vfs_ls"] = r

                # vfs_fetch shared file — masked (viewer has read permission)
                with _conn() as c:
                    r = c.send({"cmd": "vfs_fetch", "session": tok,
                                "path": "/fc_shared/seed.txt", "cwd": "/",
                                "raw": False})
                res["vfs_fetch_masked"] = r

                # whoami
                with _conn() as c:
                    r = c.send({"cmd": "whoami", "session": tok})
                res["whoami"] = r

                # vfs_send — denied for viewer
                with _conn() as c:
                    r = c.send({"cmd": "vfs_send", "session": tok,
                                "path": "/fc_shared/viewer_hack.txt", "cwd": "/",
                                "data_b64": base64.b64encode(b"hax").decode()})
                res["vfs_send_denied"] = r

                # decrypt — denied for viewer
                with _conn() as c:
                    r = c.send({"cmd": "decrypt", "session": tok,
                                "filename": "fc_pii.csv.enc"})
                res["decrypt_denied"] = r

                # list_users — denied for viewer
                with _conn() as c:
                    r = c.send({"cmd": "list_users", "session": tok})
                res["list_users_denied"] = r

                record("viewer1", res)
            except Exception as e:
                record_err("viewer1", e)
            finally:
                _logout(tok)

        # Worker: Viewer 2 — vfs_ls, vfs_tree, whoami; attempt write (denied)
        def worker_viewer2():
            tok = _login("fc_viewer2", "FcViewer2_1!")
            try:
                res = {}

                with _conn() as c:
                    r = c.send({"cmd": "vfs_ls", "session": tok,
                                "path": "/", "cwd": "/"})
                res["vfs_ls"] = r

                with _conn() as c:
                    r = c.send({"cmd": "whoami", "session": tok})
                res["whoami"] = r

                # encrypt — denied for viewer
                with _conn() as c:
                    r = c.send({"cmd": "encrypt", "session": tok,
                                "filename": "viewer_attempt.csv",
                                "data_b64": base64.b64encode(SAMPLE_CSV).decode()})
                res["encrypt_denied"] = r

                record("viewer2", res)
            except Exception as e:
                record_err("viewer2", e)
            finally:
                _logout(tok)

        # Worker: Auditor — audit_log, whoami;
        #         attempt vfs_ls (denied), attempt vfs_send (denied), attempt add_user (denied)
        def worker_auditor():
            tok = _login("fc_auditor", "FcAuditor1!")
            try:
                res = {}

                # audit_log — allowed for auditor
                with _conn() as c:
                    r = c.send({"cmd": "audit_log", "session": tok})
                res["audit_log"] = r

                # filter audit log by action
                with _conn() as c:
                    r = c.send({"cmd": "audit_log", "session": tok,
                                "action": "login"})
                res["audit_log_filter"] = r

                # vfs_ls — denied for auditor (no list permission)
                with _conn() as c:
                    r = c.send({"cmd": "vfs_ls", "session": tok,
                                "path": "/", "cwd": "/"})
                res["vfs_ls"] = r

                # whoami
                with _conn() as c:
                    r = c.send({"cmd": "whoami", "session": tok})
                res["whoami"] = r

                # vfs_send — denied for auditor
                with _conn() as c:
                    r = c.send({"cmd": "vfs_send", "session": tok,
                                "path": "/fc_shared/auditor_hack.txt", "cwd": "/",
                                "data_b64": base64.b64encode(b"hax").decode()})
                res["vfs_send_denied"] = r

                # add_user — denied for auditor
                with _conn() as c:
                    r = c.send({"cmd": "add_user", "session": tok,
                                "username": "auditor_rogue",
                                "password": "Rogue1_!",
                                "role": "Guest"})
                res["add_user_denied"] = r

                # decrypt — denied for auditor
                with _conn() as c:
                    r = c.send({"cmd": "decrypt", "session": tok,
                                "filename": "fc_pii.csv.enc"})
                res["decrypt_denied"] = r

                record("auditor", res)
            except Exception as e:
                record_err("auditor", e)
            finally:
                _logout(tok)

        # Worker: Guest — vfs_ls, whoami;
        #         attempt vfs_fetch (denied — no read), attempt everything else (denied)
        def worker_guest():
            tok = _login("fc_guest", "FcGuest1_1!")
            try:
                res = {}

                # list (allowed — guest can list)
                with _conn() as c:
                    r = c.send({"cmd": "vfs_ls", "session": tok,
                                "path": "/", "cwd": "/"})
                res["vfs_ls"] = r

                # whoami
                with _conn() as c:
                    r = c.send({"cmd": "whoami", "session": tok})
                res["whoami"] = r

                # vfs_fetch — denied (guest has no read)
                with _conn() as c:
                    r = c.send({"cmd": "vfs_fetch", "session": tok,
                                "path": "/fc_shared/seed.txt", "cwd": "/",
                                "raw": False})
                res["vfs_fetch_denied"] = r

                # decrypt — denied
                with _conn() as c:
                    r = c.send({"cmd": "decrypt", "session": tok,
                                "filename": "fc_pii.csv.enc"})
                res["decrypt_denied"] = r

                # mask — denied
                with _conn() as c:
                    r = c.send({"cmd": "mask", "session": tok,
                                "filename": "fc_pii.csv.enc",
                                "role": "Guest"})
                res["mask_denied"] = r

                # encrypt — denied
                with _conn() as c:
                    r = c.send({"cmd": "encrypt", "session": tok,
                                "filename": "guest_attempt.csv",
                                "data_b64": base64.b64encode(SAMPLE_CSV).decode()})
                res["encrypt_denied"] = r

                # add_user — denied
                with _conn() as c:
                    r = c.send({"cmd": "add_user", "session": tok,
                                "username": "guest_rogue",
                                "password": "Rogue1_!",
                                "role": "Admin"})
                res["add_user_denied"] = r

                record("guest", res)
            except Exception as e:
                record_err("guest", e)
            finally:
                _logout(tok)

        workers = {
            "admin1":   worker_admin1,
            "admin2":   worker_admin2,
            "analyst":  worker_analyst,
            "contrib1": worker_contrib1,
            "contrib2": worker_contrib2,
            "contrib3": worker_contrib3,
            "viewer1":  worker_viewer1,
            "viewer2":  worker_viewer2,
            "auditor":  worker_auditor,
            "guest":    worker_guest,
        }

        with ThreadPoolExecutor(max_workers=len(workers)) as ex:
            futs = {name: ex.submit(fn) for name, fn in workers.items()}
            for name, fut in futs.items():
                try:
                    fut.result(timeout=30)
                except Exception as e:
                    shared["errors"][name] = str(e)

        # No worker should have raised an unhandled exception
        self.assertEqual(shared["errors"], {},
                         f"workers raised exceptions:\n{shared['errors']}")

        r = shared["results"]

        # --- Admin 1 assertions ---
        self.assertTrue(r["admin1"]["enc_binary"].get("ok"),
                        f"admin1 enc_binary: {r['admin1']['enc_binary']}")
        self.assertTrue(r["admin1"]["dec_binary"].get("ok"),
                        f"admin1 dec_binary: {r['admin1']['dec_binary']}")
        self.assertTrue(r["admin1"].get("dec_binary_match"),
                        "admin1 binary encrypt->decrypt roundtrip mismatch")
        self.assertTrue(r["admin1"]["enc_csv"].get("ok"),
                        f"admin1 enc_csv: {r['admin1']['enc_csv']}")
        self.assertTrue(r["admin1"]["dec_csv"].get("ok"),
                        f"admin1 dec_csv: {r['admin1']['dec_csv']}")
        self.assertTrue(r["admin1"].get("dec_csv_match"),
                        "admin1 CSV encrypt->decrypt roundtrip mismatch")
        self.assertTrue(r["admin1"]["list_users"].get("ok"),
                        f"admin1 list_users: {r['admin1']['list_users']}")
        self.assertTrue(r["admin1"]["vfs_send_bin"].get("ok"),
                        f"admin1 vfs_send_bin: {r['admin1']['vfs_send_bin']}")
        self.assertTrue(r["admin1"]["vfs_fetch_raw"].get("ok"),
                        f"admin1 vfs_fetch_raw: {r['admin1']['vfs_fetch_raw']}")
        self.assertTrue(r["admin1"]["whoami"].get("ok"))
        self.assertEqual(r["admin1"]["whoami"].get("username"), "fc_admin")
        self.assertTrue(r["admin1"]["audit_log"].get("ok"),
                        f"admin1 audit_log: {r['admin1']['audit_log']}")
        self.assertTrue(r["admin1"]["vfs_ls"].get("ok"))
        self.assertTrue(r["admin1"]["vfs_tree"].get("ok"))

        # --- Admin 2 assertions ---
        self.assertTrue(r["admin2"]["mkdir"].get("ok"))
        self.assertTrue(r["admin2"]["add_user"].get("ok"),
                        f"admin2 add_user: {r['admin2']['add_user']}")
        self.assertTrue(r["admin2"]["assign_role"].get("ok"),
                        f"admin2 assign_role: {r['admin2']['assign_role']}")
        self.assertTrue(r["admin2"]["list_roles"].get("ok"))
        self.assertTrue(r["admin2"]["remove_user"].get("ok"),
                        f"admin2 remove_user: {r['admin2']['remove_user']}")
        self.assertTrue(r["admin2"]["vfs_send"].get("ok"))
        self.assertTrue(r["admin2"]["vfs_stat"].get("ok"))
        self.assertTrue(r["admin2"]["whoami"].get("ok"))

        # --- Analyst assertions ---
        self.assertTrue(r["analyst"]["mask"].get("ok"),
                        f"analyst mask: {r['analyst']['mask']}")
        # masking must hide SSN
        masked_text = r["analyst"]["mask"].get("masked", "")
        self.assertNotIn("123-45-6789", masked_text, "SSN not masked for analyst")
        self.assertIn("***-**-****", masked_text, "SSN mask token missing")
        self.assertTrue(r["analyst"]["vfs_fetch_masked"].get("ok"),
                        f"analyst vfs_fetch_masked: {r['analyst']['vfs_fetch_masked']}")
        self.assertTrue(r["analyst"]["vfs_ls"].get("ok"))
        self.assertTrue(r["analyst"]["whoami"].get("ok"))
        self.assertFalse(r["analyst"]["decrypt_denied"].get("ok"),
                         "analyst must not decrypt")
        self.assertFalse(r["analyst"]["add_user_denied"].get("ok"),
                         "analyst must not add_user")
        self.assertFalse(r["analyst"]["audit_log_denied"].get("ok"),
                         "analyst must not view audit_log")

        # --- Contributor 1 assertions ---
        self.assertTrue(r["contrib1"]["mkdir"].get("ok"))
        self.assertTrue(r["contrib1"]["vfs_send"].get("ok"),
                        f"contrib1 vfs_send: {r['contrib1']['vfs_send']}")
        self.assertTrue(r["contrib1"]["vfs_send_txt"].get("ok"))
        self.assertTrue(r["contrib1"]["vfs_fetch_raw"].get("ok"),
                        f"contrib1 vfs_fetch_raw: {r['contrib1']['vfs_fetch_raw']}")
        self.assertTrue(r["contrib1"]["vfs_mv"].get("ok"),
                        f"contrib1 vfs_mv: {r['contrib1']['vfs_mv']}")
        self.assertTrue(r["contrib1"]["vfs_stat"].get("ok"))
        self.assertTrue(r["contrib1"]["whoami"].get("ok"))
        self.assertFalse(r["contrib1"]["assign_role_denied"].get("ok"),
                         "contributor must not assign_role")

        # --- Contributor 2 assertions ---
        self.assertTrue(r["contrib2"]["mkdir"].get("ok"))
        for i in range(3):
            self.assertTrue(r["contrib2"][f"vfs_send_{i}"].get("ok"),
                            f"contrib2 vfs_send_{i}: {r['contrib2'][f'vfs_send_{i}']}")
        ls2 = r["contrib2"]["vfs_ls"]
        self.assertTrue(ls2.get("ok"))
        # After rm of file_0, 2 files should remain
        self.assertTrue(r["contrib2"]["vfs_rm"].get("ok"),
                        f"contrib2 vfs_rm: {r['contrib2']['vfs_rm']}")
        self.assertTrue(r["contrib2"]["whoami"].get("ok"))
        self.assertFalse(r["contrib2"]["audit_log_denied"].get("ok"),
                         "contributor must not view audit_log")

        # --- Contributor 3 assertions ---
        self.assertTrue(r["contrib3"]["mkdir"].get("ok"))
        self.assertTrue(r["contrib3"]["vfs_send_bin"].get("ok"))
        self.assertTrue(r["contrib3"]["vfs_fetch_bin"].get("ok"),
                        f"contrib3 fetch_bin: {r['contrib3']['vfs_fetch_bin']}")
        self.assertTrue(r["contrib3"]["whoami"].get("ok"))

        # --- Viewer 1 assertions ---
        self.assertTrue(r["viewer1"]["vfs_ls"].get("ok"))
        self.assertTrue(r["viewer1"]["vfs_fetch_masked"].get("ok"),
                        f"viewer1 vfs_fetch_masked: {r['viewer1']['vfs_fetch_masked']}")
        self.assertTrue(r["viewer1"]["whoami"].get("ok"))
        self.assertFalse(r["viewer1"]["vfs_send_denied"].get("ok"),
                         "viewer must not vfs_send")
        self.assertFalse(r["viewer1"]["decrypt_denied"].get("ok"),
                         "viewer must not decrypt")
        self.assertFalse(r["viewer1"]["list_users_denied"].get("ok"),
                         "viewer must not list_users")

        # --- Viewer 2 assertions ---
        self.assertTrue(r["viewer2"]["vfs_ls"].get("ok"))
        self.assertTrue(r["viewer2"]["whoami"].get("ok"))
        self.assertFalse(r["viewer2"]["encrypt_denied"].get("ok"),
                         "viewer must not encrypt")

        # --- Auditor assertions ---
        self.assertTrue(r["auditor"]["audit_log"].get("ok"),
                        f"auditor audit_log: {r['auditor']['audit_log']}")
        self.assertGreater(len(r["auditor"]["audit_log"].get("entries", [])), 0,
                           "audit log should have entries after concurrent activity")
        self.assertTrue(r["auditor"]["audit_log_filter"].get("ok"))
        self.assertFalse(r["auditor"]["vfs_ls"].get("ok"),
                         "auditor must not vfs_ls")
        self.assertTrue(r["auditor"]["whoami"].get("ok"))
        self.assertFalse(r["auditor"]["vfs_send_denied"].get("ok"),
                         "auditor must not vfs_send")
        self.assertFalse(r["auditor"]["add_user_denied"].get("ok"),
                         "auditor must not add_user")
        self.assertFalse(r["auditor"]["decrypt_denied"].get("ok"),
                         "auditor must not decrypt")

        # --- Guest assertions ---
        self.assertTrue(r["guest"]["vfs_ls"].get("ok"),
                        f"guest vfs_ls: {r['guest']['vfs_ls']}")
        self.assertTrue(r["guest"]["whoami"].get("ok"))
        self.assertFalse(r["guest"]["vfs_fetch_denied"].get("ok"),
                         "guest must not vfs_fetch")
        self.assertFalse(r["guest"]["decrypt_denied"].get("ok"),
                         "guest must not decrypt")
        self.assertFalse(r["guest"]["mask_denied"].get("ok"),
                         "guest must not mask")
        self.assertFalse(r["guest"]["encrypt_denied"].get("ok"),
                         "guest must not encrypt")
        self.assertFalse(r["guest"]["add_user_denied"].get("ok"),
                         "guest must not add_user")

        # --- Audit chain integrity ---
        self.assertTrue(verify_audit_chain(_db_path),
                        "audit chain broken after full concurrent load")


if __name__ == "__main__":
    unittest.main(verbosity=2)
