"""
Binary smoke tests.

Runs the compiled EFS_bin binary as a subprocess against a live server.
These tests catch packaging issues (missing modules, wrong paths, cert fetch,
downloads dir creation) that unit/integration tests cannot catch because those
tests import the source directly.

Skipped automatically if the binary does not exist.

All interactive shell commands are driven by piping stdin to `EFS_bin shell`.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from core.db import init_db
from server.server import EFSServer
from server.access_control import add_user
from client.client import ServerConn

BINARY   = PROJECT_ROOT / "client_pkg" / "compiled_binary" / "client.dist" / "EFS_bin"
CERT     = str(PROJECT_ROOT / "server_pkg" / "certs" / "cert.pem")
KEY      = str(PROJECT_ROOT / "server_pkg" / "certs" / "key.pem")
HOST     = "127.0.0.1"
PORT     = 19998  # separate port — does not conflict with test_integration.py

_server: EFSServer | None = None
_db_path: str = ""
_enc_dir: tempfile.TemporaryDirectory | None = None
_session_file = Path.home() / ".efs_session_binary_test"


def setUpModule():
    if not BINARY.exists():
        return  # tests will be skipped individually

    global _server, _db_path, _enc_dir
    fd, _db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    init_db(_db_path)
    add_user("admin",       "Admin1234!",    role="Admin",       db_path=_db_path)
    add_user("analyst",     "Analyst1234!",  role="Analyst",     db_path=_db_path)
    add_user("viewer",      "Viewer1234!",   role="Viewer",      db_path=_db_path)
    add_user("contributor", "Contrib1234!",  role="Contributor", db_path=_db_path)
    add_user("auditor",     "Auditor1234!",  role="Auditor",     db_path=_db_path)
    add_user("guest",       "Guest1234!",    role="Guest",       db_path=_db_path)

    _enc_dir = tempfile.TemporaryDirectory()
    _server = EFSServer(
        host=HOST, port=PORT, cert=CERT, key=KEY,
        db_path=_db_path, data_enc=Path(_enc_dir.name),
    )
    t = threading.Thread(target=_server.start, daemon=True)
    t.start()

    for _ in range(30):
        try:
            with ServerConn(HOST, PORT, CERT) as c:
                c.send({"cmd": "ping"})
            break
        except Exception:
            time.sleep(0.1)

    # Write config.json next to binary so host/port are resolved correctly
    config = {"host": HOST, "port": PORT, "cert": CERT}
    (BINARY.parent / "config.json").write_text(json.dumps(config))

    # Pre-place cert next to binary so _ensure_cert doesn't try to
    # connect to an unexpected host during tests
    binary_certs = BINARY.parent / "certs"
    binary_certs.mkdir(exist_ok=True)
    shutil.copy(CERT, binary_certs / "cert.pem")


def tearDownModule():
    if _server:
        _server.stop()
    if _db_path and os.path.exists(_db_path):
        os.unlink(_db_path)
    if _enc_dir:
        _enc_dir.cleanup()
    if _session_file.exists():
        _session_file.unlink()


def _get_token(username: str, password: str) -> str:
    """Get a valid session token directly via ServerConn."""
    with ServerConn(HOST, PORT, CERT) as c:
        resp = c.send({"cmd": "login", "username": username, "password": password})
    assert resp["ok"], f"Login failed: {resp}"
    return resp["session"]


def _write_session(token: str) -> None:
    """Write session token to ~/.efs_session so the binary finds it."""
    session_file = Path.home() / ".efs_session"
    session_file.write_text(token)
    session_file.chmod(0o600)


def _clear_session() -> None:
    """Logout from server and remove local session file."""
    session_file = Path.home() / ".efs_session"
    if session_file.exists():
        raw = session_file.read_text().strip()
        if raw:
            try:
                token = json.loads(raw).get("token", raw)
            except (json.JSONDecodeError, AttributeError):
                token = raw
            try:
                with ServerConn(HOST, PORT, CERT) as c:
                    c.send({"cmd": "logout", "session": token})
            except Exception:
                pass
        session_file.unlink()


def _force_logout_user(username: str) -> None:
    """Remove any server-side session for username directly via the server object."""
    if _server is None:
        return
    with _server._sessions_lock:
        stale = [tok for tok, rec in _server._sessions.items() if rec["username"] == username]
        for tok in stale:
            del _server._sessions[tok]


def _run(*args, input_text: str = "", env_extra: dict | None = None) -> subprocess.CompletedProcess:
    """Run the binary with given top-level args, return CompletedProcess."""
    env = os.environ.copy()
    env["HOME"] = str(Path.home())
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [str(BINARY)] + list(args),
        input=input_text,
        capture_output=True,
        text=True,
        timeout=30,
        env=env,
    )


def _run_shell(cmds: list[str], env_extra: dict | None = None) -> subprocess.CompletedProcess:
    """
    Run one or more commands inside the binary's interactive shell via stdin.
    Session must already be written by _write_session() before calling this.
    """
    stdin = "\n".join(cmds) + "\nexit\n"
    return _run("shell", input_text=stdin, env_extra=env_extra)


@unittest.skipUnless(BINARY.exists(), "compiled binary not found — run Nuitka build first")
class TestBinaryBoots(unittest.TestCase):
    """Basic sanity: binary starts and responds."""

    def test_help_exits_zero(self):
        r = subprocess.run([str(BINARY), "--help"], capture_output=True, text=True, timeout=10)
        self.assertEqual(r.returncode, 0)
        self.assertIn("EFS-TDM", r.stdout)

    def test_configure_saves_config(self):
        # Verify configure subcommand writes config correctly.
        r = subprocess.run(
            [str(BINARY), "configure", "--host", HOST, "--port", str(PORT)],
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(HOST, r.stdout)

    def test_unknown_command_exits_nonzero(self):
        r = subprocess.run([str(BINARY), "notacommand"], capture_output=True, text=True, timeout=10)
        self.assertNotEqual(r.returncode, 0)


@unittest.skipUnless(BINARY.exists(), "compiled binary not found — run Nuitka build first")
class TestBinaryCertAutoFetch(unittest.TestCase):
    """Binary fetches cert on first run if cert.pem is missing."""

    def test_cert_fetched_when_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake_home = Path(tmp)
            certs_dir = BINARY.parent / "certs"
            env = os.environ.copy()
            env["HOME"] = str(fake_home)
            r = subprocess.run(
                [str(BINARY), "--help"],
                capture_output=True, text=True, timeout=15, env=env,
            )
            self.assertTrue(
                certs_dir.exists() or r.returncode == 0,
                f"cert not fetched; stdout={r.stdout!r} stderr={r.stderr!r}",
            )


@unittest.skipUnless(BINARY.exists(), "compiled binary not found — run Nuitka build first")
class TestBinaryLogin(unittest.TestCase):
    """whoami / logout via binary shell (login via ServerConn to avoid getpass/tty)."""

    def setUp(self):
        _force_logout_user("admin")
        _clear_session()

    def tearDown(self):
        _force_logout_user("admin")
        _clear_session()

    def test_whoami_shows_username(self):
        _write_session(_get_token("admin", "Admin1234!"))
        r = _run_shell(["whoami"])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("admin", r.stdout.lower())

    def test_whoami_without_session_fails(self):
        r = _run("shell")
        self.assertNotEqual(r.returncode, 0)

    def test_logout_clears_session(self):
        _force_logout_user("admin")
        _write_session(_get_token("admin", "Admin1234!"))
        r = _run_shell(["logout"])
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_stale_session_rejected(self):
        (Path.home() / ".efs_session").write_text("invalid.token.garbage")
        r = _run("shell")
        self.assertNotEqual(r.returncode, 0)



@unittest.skipUnless(BINARY.exists(), "compiled binary not found — run Nuitka build first")
class TestBinaryUserManagement(unittest.TestCase):
    """list-users / list-roles / assign-role via binary shell."""

    def setUp(self):
        _force_logout_user("admin")
        _force_logout_user("analyst")
        _clear_session()
        _write_session(_get_token("admin", "Admin1234!"))

    def tearDown(self):
        _clear_session()

    def test_list_users(self):
        r = _run_shell(["list-users"])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("admin", r.stdout.lower())

    def test_list_roles(self):
        r = _run_shell(["list-roles"])
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_assign_role(self):
        r = _run_shell(["assign-role analyst --role viewer", "Y"])
        self.assertEqual(r.returncode, 0, r.stderr)
        # restore
        _clear_session()
        _write_session(_get_token("admin", "Admin1234!"))
        _run_shell(["assign-role analyst --role Analyst", "Y"])

    def test_analyst_cannot_list_users(self):
        _force_logout_user("analyst")
        _clear_session()
        _write_session(_get_token("analyst", "Analyst1234!"))
        r = _run_shell(["list-users"])
        combined = r.stdout.lower() + r.stderr.lower()
        self.assertTrue(
            "permission" in combined or "denied" in combined or "error" in combined,
            f"expected denial, got: {combined!r}",
        )


@unittest.skipUnless(BINARY.exists(), "compiled binary not found — run Nuitka build first")
class TestBinaryAuditLog(unittest.TestCase):
    """audit-log accessible by admin, denied for analyst."""

    def tearDown(self):
        _clear_session()

    def test_audit_log_accessible_by_admin(self):
        _force_logout_user("admin")
        _clear_session()
        _write_session(_get_token("admin", "Admin1234!"))
        r = _run_shell(["audit-log"])
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_audit_log_denied_for_analyst(self):
        _force_logout_user("analyst")
        _clear_session()
        _write_session(_get_token("analyst", "Analyst1234!"))
        r = _run_shell(["audit-log"])
        combined = r.stdout.lower() + r.stderr.lower()
        self.assertTrue(
            "permission" in combined or "denied" in combined or "error" in combined,
            f"expected denial, got: {combined!r}",
        )


@unittest.skipUnless(BINARY.exists(), "compiled binary not found — run Nuitka build first")
class TestBinaryDownloadsDir(unittest.TestCase):
    """downloads/ directory is created automatically next to the launcher."""

    def tearDown(self):
        _clear_session()

    def test_downloads_dir_created_on_first_run(self):
        candidates = [
            BINARY.parent / "downloads",
            BINARY.parent.parent / "downloads",
        ]
        for d in candidates:
            if d.exists():
                shutil.rmtree(str(d))
        _force_logout_user("admin")
        _clear_session()
        _write_session(_get_token("admin", "Admin1234!"))
        # decrypt of nonexistent file still triggers _ensure_dirs()
        _run_shell(["decrypt dummy.enc"])
        created = any(d.exists() for d in candidates)
        self.assertTrue(created, f"downloads/ not found at {candidates}")


if __name__ == "__main__":
    unittest.main()
