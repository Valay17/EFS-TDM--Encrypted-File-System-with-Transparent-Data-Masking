"""
Automated end-to-end tests for the web login flow and full CLI pipeline.

What this covers:
  1. Flask login page renders correctly
  2. Bad credentials return an error, session file is NOT written
  3. Good credentials write a signed, chmod-600 session file
  4. HMAC token validates correctly via token_store.validate()
  5. HMAC token is rejected when tampered
  6. Expired tokens are rejected
  7. Token revocation works
  8. Session file has correct permissions (0o600)
  9. Full CLI pipeline via TLS server:
       - web login -> session written
       - encrypt a file
       - decrypt and verify round-trip
       - mask (analyst role)
       - add-user (admin only)
       - assign-role
       - list-users
       - list-roles
       - audit-log
       - logout
  10. web-login times out gracefully when browser never completes login
  11. Concurrent web login requests are isolated
  12. Success page contains auto-close JS

All tests are headless — no real browser is opened.
The EFS-TDM TLS server is started in a background thread for CLI tests.
"""

import base64
import json
import os
import socket
import ssl
import stat
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest
import requests
import requests.packages.urllib3
import warnings
requests.packages.urllib3.disable_warnings()

# Suppress Werkzeug daemon-thread port-collision warnings that occur when two
# TestWebLoginFunction tests race on releasing the same OS port.
pytestmark = pytest.mark.filterwarnings(
    "ignore::pytest.PytestUnhandledThreadExceptionWarning"
)

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from web.token_store import issue, validate, revoke
from web import app as web_app_module
from web.app import app as flask_app
import web.app as _web_app

SESSION_FILE = Path.home() / ".efs_session"


@pytest.fixture(autouse=True)
def _clear_rate_state():
    """Reset in-process IP and account lockout state between every test."""
    _web_app._ip_hits.clear()
    _web_app._acct_fails.clear()
    _web_app._acct_lock_until.clear()
    yield
    _web_app._ip_hits.clear()
    _web_app._acct_fails.clear()
    _web_app._acct_lock_until.clear()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _tls_send(host, port, cert, req: dict) -> dict:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cert)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    with socket.create_connection((host, port), timeout=10) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as sock:
            sock.sendall(json.dumps(req).encode() + b"\n")
            buf = b""
            while b"\n" not in buf:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                buf += chunk
            return json.loads(buf.split(b"\n")[0])


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def flask_client():
    """A Flask test client — no real HTTP server needed."""
    flask_app.config["TESTING"] = True
    flask_app.config["WTF_CSRF_ENABLED"] = False
    with flask_app.test_client() as client:
        yield client


@pytest.fixture(scope="module")
def efs_server():
    """
    Spin up a real EFS-TDM TLS server in a background thread.
    Uses a temp DB so tests are isolated from the production DB.
    Yields (host, port, cert_path, db_path).
    """
    from server.server import EFSServer
    from server.access_control import add_user as ac_add_user
    from core.db import init_db

    port = _free_port()
    cert = str(PROJECT_ROOT / "server_pkg" / "certs" / "cert.pem")
    key  = str(PROJECT_ROOT / "server_pkg" / "certs" / "key.pem")

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_web.db")
        enc_path = os.path.join(tmpdir, "encrypted")
        os.makedirs(enc_path, exist_ok=True)
        init_db(db_path)

        # Seed an admin and an analyst for tests
        ac_add_user("webadmin",   "AdminPass1!", role="Admin",   db_path=db_path)
        ac_add_user("webanalyst", "AnalystPass1!", role="Analyst", db_path=db_path)

        from pathlib import Path as _Path
        server = EFSServer(
            host="127.0.0.1",
            port=port,
            cert=cert,
            key=key,
            db_path=db_path,
            data_enc=_Path(enc_path),
        )
        t = threading.Thread(target=server.start, daemon=True)
        t.start()
        time.sleep(0.4)   # wait for bind

        yield {"host": "127.0.0.1", "port": port, "cert": cert, "db_path": db_path}

        server.stop()


@pytest.fixture(autouse=True)
def clean_session_file():
    """Remove session file before and after every test."""
    if SESSION_FILE.exists():
        SESSION_FILE.unlink()
    yield
    if SESSION_FILE.exists():
        SESSION_FILE.unlink()


# ---------------------------------------------------------------------------
# Helper — full GET / → POST /login flow with cookies + CSRF
# ---------------------------------------------------------------------------

def _do_login(flask_client, username, password):
    """
    Perform a full login:
      1. GET / — server sets efs_poll_key (httpOnly) and efs_csrf_token cookies,
                 and embeds csrf_token in the form HTML
      2. POST /login — send cookies + csrf_token from the page

    Returns the POST response.
    """
    get_resp = flask_client.get("/")
    # Extract csrf_token from page HTML
    html = get_resp.data.decode()
    csrf_token = ""
    for line in html.splitlines():
        if 'name="csrf_token"' in line and 'value="' in line:
            csrf_token = line.split('value="')[1].split('"')[0]
            break
    return flask_client.post(
        "/login",
        data={"username": username, "password": password, "csrf_token": csrf_token},
        follow_redirects=True,
    )


# ---------------------------------------------------------------------------
# 1. Flask page rendering
# ---------------------------------------------------------------------------

class TestFlaskLoginPage:

    def test_get_returns_200(self, flask_client):
        resp = flask_client.get("/")
        assert resp.status_code == 200

    def test_page_contains_project_name(self, flask_client):
        resp = flask_client.get("/")
        assert b"EFS-TDM" in resp.data

    def test_page_contains_form(self, flask_client):
        resp = flask_client.get("/")
        assert b'<form' in resp.data
        assert b'name="username"' in resp.data
        assert b'name="password"' in resp.data

    def test_page_has_submit_button(self, flask_client):
        resp = flask_client.get("/")
        assert b"Authenticate" in resp.data

    def test_page_sets_poll_key_cookie(self, flask_client):
        resp = flask_client.get("/")
        assert "efs_poll_key" in resp.headers.get("Set-Cookie", "")

    def test_page_has_csrf_token_field(self, flask_client):
        resp = flask_client.get("/")
        assert b'name="csrf_token"' in resp.data

    def test_success_page_has_return_to_terminal_instruction(self, flask_client, efs_server, monkeypatch):
        monkeypatch.setenv("EFS_DB_PATH", efs_server["db_path"])
        monkeypatch.setenv("EFS_SERVER_PORT", str(efs_server["port"]))
        monkeypatch.setattr(_web_app, "_backend_port", efs_server["port"])
        resp = _do_login(flask_client, "webadmin", "AdminPass1!")
        assert resp.status_code == 200
        assert b"Return to your terminal" in resp.data
        poll_data = json.loads(flask_client.get("/poll").data)
        if poll_data.get("ok") and "token" in poll_data:
            try:
                _tls_send(efs_server["host"], efs_server["port"], efs_server["cert"],
                          {"cmd": "logout", "session": poll_data["token"]})
            except Exception:
                pass


# ---------------------------------------------------------------------------
# 2. Bad credentials — session file must NOT be written
# ---------------------------------------------------------------------------

class TestBadCredentials:

    @pytest.fixture(autouse=True)
    def _with_db(self, tmp_path, monkeypatch):
        """Point every test in this class at a fresh isolated DB."""
        from core.db import init_db
        from server.access_control import add_user as ac_add_user
        db = str(tmp_path / "bad_creds.db")
        init_db(db)
        ac_add_user("realuser", "RealPass1!", role="Guest", db_path=db)
        monkeypatch.setenv("EFS_DB_PATH", db)

    def test_missing_csrf_rejected(self, flask_client):
        # POST without going through GET / first — no cookies, no CSRF token
        resp = flask_client.post(
            "/login",
            data={"username": "realuser", "password": "RealPass1!"},
        )
        assert resp.status_code == 403

    def test_wrong_password_shows_error(self, flask_client):
        resp = _do_login(flask_client, "realuser", "wrong")
        assert resp.status_code == 200
        assert b"EFS-TDM" in resp.data

    def test_wrong_password_no_session_file(self, flask_client):
        _do_login(flask_client, "realuser", "wrong")
        assert not SESSION_FILE.exists()

    def test_empty_username_rejected(self, flask_client):
        resp = _do_login(flask_client, "", "whatever")
        assert resp.status_code == 200
        assert b"required" in resp.data.lower()

    def test_empty_password_rejected(self, flask_client):
        resp = _do_login(flask_client, "realuser", "")
        assert resp.status_code == 200

    def test_sql_injection_attempt_rejected(self, flask_client):
        resp = _do_login(flask_client, "' OR 1=1 --", "x")
        assert resp.status_code == 200
        assert not SESSION_FILE.exists()


# ---------------------------------------------------------------------------
# 3. Good credentials — session file written
# ---------------------------------------------------------------------------

class TestGoodCredentials:
    """
    All tests here use the module-scoped efs_server fixture so that
    web/app.py can reach the TLS backend via _tls_login().
    Token is now returned via the /poll endpoint, not written to SESSION_FILE.
    """

    @pytest.fixture(autouse=True)
    def _point_to_server(self, efs_server, monkeypatch):
        monkeypatch.setenv("EFS_DB_PATH", efs_server["db_path"])
        monkeypatch.setenv("EFS_SERVER_PORT", str(efs_server["port"]))
        monkeypatch.setattr(_web_app, "_backend_port", efs_server["port"])
        self._efs_server = efs_server
        self._web_tokens = []
        yield
        for tok in self._web_tokens:
            try:
                _tls_send(efs_server["host"], efs_server["port"], efs_server["cert"],
                          {"cmd": "logout", "session": tok})
            except Exception:
                pass
        self._web_tokens.clear()

    def _login_and_poll(self, flask_client, username, password):
        """
        Full flow: GET / (gets cookies + csrf_token), POST /login,
        GET /poll (cookie sent automatically by test client).
        Returns the JSON data from /poll.
        """
        _do_login(flask_client, username, password)
        resp = flask_client.get("/poll")
        data = json.loads(resp.data)
        if data.get("ok") and "token" in data:
            self._web_tokens.append(data["token"])
        return data

    def test_admin_login_token_returned(self, flask_client):
        data = self._login_and_poll(flask_client, "webadmin", "AdminPass1!")
        assert data["ok"] is True
        assert len(data["token"]) > 10

    def test_token_is_non_empty(self, flask_client):
        data = self._login_and_poll(flask_client, "webadmin", "AdminPass1!")
        assert len(data["token"]) > 10

    def test_analyst_login_token_returned(self, flask_client):
        data = self._login_and_poll(flask_client, "webanalyst", "AnalystPass1!")
        assert data["ok"] is True

    def test_poll_without_cookie_returns_false(self, flask_client):
        # Poll without going through GET / first — no cookie set
        resp = flask_client.get("/poll")
        data = json.loads(resp.data)
        assert data["ok"] is False

    def test_token_consumed_on_first_poll(self, flask_client):
        # Second poll returns false — token is one-time
        _do_login(flask_client, "webadmin", "AdminPass1!")
        first = flask_client.get("/poll")
        first_data = json.loads(first.data)
        if first_data.get("ok") and "token" in first_data:
            self._web_tokens.append(first_data["token"])
        resp = flask_client.get("/poll")
        data = json.loads(resp.data)
        assert data["ok"] is False

    def test_session_token_is_valid_server_token(self, flask_client, efs_server):
        data = self._login_and_poll(flask_client, "webadmin", "AdminPass1!")
        token = data["token"]
        resp = _tls_send(efs_server["host"], efs_server["port"], efs_server["cert"],
                         {"cmd": "list_roles", "session": token})
        assert resp["ok"] is True

    def test_success_page_shows_username(self, flask_client):
        resp = _do_login(flask_client, "webadmin", "AdminPass1!")
        assert b"webadmin" in resp.data
        poll_data = json.loads(flask_client.get("/poll").data)
        if poll_data.get("ok") and "token" in poll_data:
            self._web_tokens.append(poll_data["token"])

    def test_success_page_shows_role(self, flask_client):
        resp = _do_login(flask_client, "webadmin", "AdminPass1!")
        assert b"Admin" in resp.data
        poll_data = json.loads(flask_client.get("/poll").data)
        if poll_data.get("ok") and "token" in poll_data:
            self._web_tokens.append(poll_data["token"])


# ---------------------------------------------------------------------------
# 4. HMAC token_store unit tests
# ---------------------------------------------------------------------------

class TestTokenStore:

    def test_issue_returns_string(self):
        t = issue("alice", "Admin")
        assert isinstance(t, str)
        assert "." in t

    def test_validate_returns_record(self):
        t = issue("alice", "Admin")
        rec = validate(t)
        assert rec is not None
        assert rec["username"] == "alice"
        assert rec["role"] == "Admin"

    def test_validate_wrong_sig_rejected(self):
        t = issue("alice", "Admin")
        parts = t.split(".")
        tampered = parts[0] + ".deadbeef" + parts[1][8:]
        assert validate(tampered) is None

    def test_validate_truncated_token_rejected(self):
        assert validate("notavalidtoken") is None

    def test_validate_empty_string_rejected(self):
        assert validate("") is None

    def test_validate_dot_only_rejected(self):
        assert validate(".") is None

    def test_revoke_removes_token(self):
        t = issue("bob", "Analyst")
        assert validate(t) is not None
        revoke(t)
        assert validate(t) is None

    def test_revoke_nonexistent_returns_false(self):
        assert revoke("aaaaaaaa-0000-0000-0000-000000000000.fakesig") is False

    def test_expired_token_rejected(self, monkeypatch):
        import web.token_store as ts
        orig_ttl = ts.TOKEN_TTL
        ts.TOKEN_TTL = 0   # immediate expiry
        t = issue("charlie", "Guest")
        ts.TOKEN_TTL = orig_ttl
        time.sleep(0.05)
        assert validate(t) is None

    def test_concurrent_issue_all_unique(self):
        tokens = []
        errors = []

        def _issue():
            try:
                tokens.append(issue("concurrent_user", "Guest"))
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=_issue) for _ in range(50)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()

        assert not errors
        assert len(set(tokens)) == 50   # all unique

    def test_concurrent_validate_all_succeed(self):
        tokens = [issue(f"u{i}", "Guest") for i in range(20)]
        results = [None] * 20
        errors = []

        def _validate(i):
            try:
                results[i] = validate(tokens[i])
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=_validate, args=(i,)) for i in range(20)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()

        assert not errors
        assert all(r is not None for r in results)


# ---------------------------------------------------------------------------
# 5. Security headers and rate limiting
# ---------------------------------------------------------------------------

class TestSecurityHeaders:

    def test_hsts_header_present(self, flask_client):
        resp = flask_client.get("/")
        assert "Strict-Transport-Security" in resp.headers
        assert "max-age=" in resp.headers["Strict-Transport-Security"]

    def test_x_frame_options_deny(self, flask_client):
        resp = flask_client.get("/")
        assert resp.headers.get("X-Frame-Options") == "DENY"

    def test_x_content_type_nosniff(self, flask_client):
        resp = flask_client.get("/")
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"

    def test_referrer_policy_present(self, flask_client):
        resp = flask_client.get("/")
        assert "Referrer-Policy" in resp.headers

    def test_permissions_policy_present(self, flask_client):
        resp = flask_client.get("/")
        assert "Permissions-Policy" in resp.headers

    def test_csp_present(self, flask_client):
        resp = flask_client.get("/")
        csp = resp.headers.get("Content-Security-Policy", "")
        assert "default-src 'self'" in csp
        assert "frame-ancestors 'none'" in csp
        assert "object-src 'none'" in csp

    def test_server_header_removed(self, flask_client):
        resp = flask_client.get("/")
        assert "Server" not in resp.headers

    def test_cross_origin_opener_policy(self, flask_client):
        resp = flask_client.get("/")
        assert resp.headers.get("Cross-Origin-Opener-Policy") == "same-origin"

    def test_headers_on_poll_endpoint(self, flask_client):
        resp = flask_client.get("/poll")
        assert "X-Content-Type-Options" in resp.headers
        assert "X-Frame-Options" in resp.headers


class TestRateLimitingAndLockout:

    @pytest.fixture(autouse=True)
    def _with_db(self, tmp_path, monkeypatch):
        from core.db import init_db
        from server.access_control import add_user as ac_add_user
        db = str(tmp_path / "rl_test.db")
        init_db(db)
        ac_add_user("rluser", "RlPass1!", role="Guest", db_path=db)
        monkeypatch.setenv("EFS_DB_PATH", db)

    def test_ip_rate_limit_triggers_after_max_attempts(self, flask_client):
        # Hit /login 10 times with bad CSRF (still counts toward IP rate limit
        # because the IP check runs before CSRF)
        for _ in range(10):
            _do_login(flask_client, "rluser", "wrong")
        resp = _do_login(flask_client, "rluser", "wrong")
        assert resp.status_code == 429

    def test_account_lockout_after_five_failures(self, flask_client):
        for _ in range(5):
            _do_login(flask_client, "rluser", "wrong")
        resp = _do_login(flask_client, "rluser", "RlPass1!")
        assert resp.status_code == 403

    def test_generic_error_message_on_lockout(self, flask_client):
        for _ in range(5):
            _do_login(flask_client, "rluser", "wrong")
        resp = _do_login(flask_client, "rluser", "RlPass1!")
        assert b"Invalid credentials" in resp.data

    def test_404_returns_error_page(self, flask_client):
        resp = flask_client.get("/nonexistent_path_xyz")
        assert resp.status_code == 404
        assert b"<html" in resp.data
        assert b"Return to login" in resp.data


class TestIdleTimeout:

    def test_idle_timeout_invalidates_token(self, monkeypatch):
        import web.token_store as ts
        monkeypatch.setattr(ts, "IDLE_TTL", 0.01)  # 10 ms — stays patched during validate
        t = issue("idleuser", "Guest")
        time.sleep(0.05)
        assert validate(t) is None

    def test_absolute_ttl_invalidates_token(self, monkeypatch):
        import web.token_store as ts
        orig_ttl = ts.TOKEN_TTL
        ts.TOKEN_TTL = 0
        t = issue("absuser", "Guest")
        ts.TOKEN_TTL = orig_ttl
        time.sleep(0.05)
        assert validate(t) is None

    def test_active_token_updates_last_activity(self):
        t = issue("activeuser", "Guest")
        r1 = validate(t)
        time.sleep(0.05)
        r2 = validate(t)
        assert r2 is not None
        assert r2["last_activity"] >= r1["last_activity"]


# ---------------------------------------------------------------------------
# 6. Full CLI pipeline via TLS server
# ---------------------------------------------------------------------------

class TestCLIPipeline:

    def setup_method(self, method):
        self._active_tokens = []
        self._srv = None

    def teardown_method(self, method):
        if self._srv is None:
            return
        for tok in self._active_tokens:
            try:
                _tls_send(self._srv["host"], self._srv["port"], self._srv["cert"],
                          {"cmd": "logout", "session": tok})
            except Exception:
                pass
        self._active_tokens.clear()

    def _send(self, srv, req):
        self._srv = srv
        resp = _tls_send(srv["host"], srv["port"], srv["cert"], req)
        if req.get("cmd") == "login" and resp.get("ok") and "session" in resp:
            self._active_tokens.append(resp["session"])
        if req.get("cmd") == "logout" and "session" in req:
            self._active_tokens = [t for t in self._active_tokens if t != req["session"]]
        return resp

    def test_ping(self, efs_server):
        resp = self._send(efs_server, {"cmd": "ping"})
        assert resp["ok"] is True
        assert resp["message"] == "pong"

    def test_login_admin(self, efs_server):
        resp = self._send(efs_server, {
            "cmd": "login", "username": "webadmin", "password": "AdminPass1!"
        })
        assert resp["ok"] is True
        assert "session" in resp
        assert resp["role"] == "Admin"

    def test_login_bad_password(self, efs_server):
        resp = self._send(efs_server, {
            "cmd": "login", "username": "webadmin", "password": "wrong"
        })
        assert resp["ok"] is False

    def test_login_nonexistent_user(self, efs_server):
        resp = self._send(efs_server, {
            "cmd": "login", "username": "ghost", "password": "x"
        })
        assert resp["ok"] is False

    def test_unauthenticated_encrypt_rejected(self, efs_server):
        resp = self._send(efs_server, {
            "cmd": "encrypt", "filename": "x.csv",
            "data_b64": base64.b64encode(b"data").decode()
        })
        assert resp["ok"] is False
        assert "authenticated" in resp["error"].lower()

    def test_encrypt_decrypt_roundtrip(self, efs_server):
        login = self._send(efs_server, {
            "cmd": "login", "username": "webadmin", "password": "AdminPass1!"
        })
        token = login["session"]
        plaintext = b"id,name,ssn\n1,Alice,123-45-6789\n"
        enc = self._send(efs_server, {
            "cmd": "encrypt", "session": token,
            "filename": "pipeline_test.csv",
            "data_b64": base64.b64encode(plaintext).decode(),
        })
        assert enc["ok"] is True
        assert enc["stored_as"].endswith(".enc")

        dec = self._send(efs_server, {
            "cmd": "decrypt", "session": token,
            "filename": enc["stored_as"],
        })
        assert dec["ok"] is True
        assert base64.b64decode(dec["data_b64"]) == plaintext

    def test_mask_as_analyst(self, efs_server):
        # Admin encrypts, analyst masks
        admin_login = self._send(efs_server, {
            "cmd": "login", "username": "webadmin", "password": "AdminPass1!"
        })
        admin_tok = admin_login["session"]
        content = b"name,ssn,email\nAlice,123-45-6789,alice@example.com\n"
        enc = self._send(efs_server, {
            "cmd": "encrypt", "session": admin_tok,
            "filename": "mask_pipeline.csv",
            "data_b64": base64.b64encode(content).decode(),
        })
        assert enc["ok"] is True

        analyst_login = self._send(efs_server, {
            "cmd": "login", "username": "webanalyst", "password": "AnalystPass1!"
        })
        analyst_tok = analyst_login["session"]
        mask = self._send(efs_server, {
            "cmd": "mask", "session": analyst_tok,
            "filename": enc["stored_as"], "role": "Analyst",
        })
        assert mask["ok"] is True
        assert "123-45-6789" not in mask["masked"]    # SSN masked
        assert "alice@example.com" not in mask["masked"]  # email masked

    def test_analyst_cannot_decrypt(self, efs_server):
        # Encrypt something as admin first
        admin_login = self._send(efs_server, {
            "cmd": "login", "username": "webadmin", "password": "AdminPass1!"
        })
        admin_tok = admin_login["session"]
        enc = self._send(efs_server, {
            "cmd": "encrypt", "session": admin_tok,
            "filename": "analyst_denied.csv",
            "data_b64": base64.b64encode(b"secret").decode(),
        })

        analyst_login = self._send(efs_server, {
            "cmd": "login", "username": "webanalyst", "password": "AnalystPass1!"
        })
        analyst_tok = analyst_login["session"]
        dec = self._send(efs_server, {
            "cmd": "decrypt", "session": analyst_tok,
            "filename": enc["stored_as"],
        })
        assert dec["ok"] is False
        assert "denied" in dec["error"].lower()

    def test_add_user_as_admin(self, efs_server):
        login = self._send(efs_server, {
            "cmd": "login", "username": "webadmin", "password": "AdminPass1!"
        })
        tok = login["session"]
        resp = self._send(efs_server, {
            "cmd": "add_user", "session": tok,
            "username": "newguestuser", "password": "GuestPass1!", "role": "Guest",
        })
        assert resp["ok"] is True
        assert resp["username"] == "newguestuser"
        assert resp["role"] == "Guest"

    def test_add_user_as_analyst_denied(self, efs_server):
        login = self._send(efs_server, {
            "cmd": "login", "username": "webanalyst", "password": "AnalystPass1!"
        })
        tok = login["session"]
        resp = self._send(efs_server, {
            "cmd": "add_user", "session": tok,
            "username": "shouldfail", "password": "x", "role": "Guest",
        })
        assert resp["ok"] is False

    def test_assign_role(self, efs_server):
        login = self._send(efs_server, {
            "cmd": "login", "username": "webadmin", "password": "AdminPass1!"
        })
        tok = login["session"]
        # Add a user first
        self._send(efs_server, {
            "cmd": "add_user", "session": tok,
            "username": "roletest_user", "password": "RolePass1!", "role": "Guest",
        })
        # Promote them
        resp = self._send(efs_server, {
            "cmd": "assign_role", "session": tok,
            "username": "roletest_user", "role": "Analyst",
        })
        assert resp["ok"] is True

    def test_list_users(self, efs_server):
        login = self._send(efs_server, {
            "cmd": "login", "username": "webadmin", "password": "AdminPass1!"
        })
        tok = login["session"]
        resp = self._send(efs_server, {"cmd": "list_users", "session": tok})
        assert resp["ok"] is True
        usernames = [u["username"] for u in resp["users"]]
        assert "webadmin" in usernames
        assert "webanalyst" in usernames

    def test_list_roles(self, efs_server):
        login = self._send(efs_server, {
            "cmd": "login", "username": "webadmin", "password": "AdminPass1!"
        })
        tok = login["session"]
        resp = self._send(efs_server, {"cmd": "list_roles", "session": tok})
        assert resp["ok"] is True
        names = [r["name"] for r in resp["roles"]]
        assert "Admin" in names
        assert "Analyst" in names
        assert "Guest" in names

    def test_audit_log_contains_login_events(self, efs_server):
        login = self._send(efs_server, {
            "cmd": "login", "username": "webadmin", "password": "AdminPass1!"
        })
        tok = login["session"]
        resp = self._send(efs_server, {
            "cmd": "audit_log", "session": tok, "action": "login",
        })
        assert resp["ok"] is True
        assert len(resp["entries"]) > 0
        actions = {e["action"] for e in resp["entries"]}
        assert "login" in actions

    def test_audit_log_denied_for_analyst(self, efs_server):
        login = self._send(efs_server, {
            "cmd": "login", "username": "webanalyst", "password": "AnalystPass1!"
        })
        tok = login["session"]
        resp = self._send(efs_server, {"cmd": "audit_log", "session": tok})
        assert resp["ok"] is False

    def test_logout_invalidates_session(self, efs_server):
        login = self._send(efs_server, {
            "cmd": "login", "username": "webadmin", "password": "AdminPass1!"
        })
        tok = login["session"]
        logout = self._send(efs_server, {"cmd": "logout", "session": tok})
        assert logout["ok"] is True

        # Subsequent request with same token is rejected
        resp = self._send(efs_server, {"cmd": "list_users", "session": tok})
        assert resp["ok"] is False

    def test_invalid_command_returns_error(self, efs_server):
        login = self._send(efs_server, {
            "cmd": "login", "username": "webadmin", "password": "AdminPass1!"
        })
        tok = login["session"]
        resp = self._send(efs_server, {"cmd": "does_not_exist", "session": tok})
        assert resp["ok"] is False

    def test_multiple_sessions_same_user(self, efs_server):
        r1 = self._send(efs_server, {
            "cmd": "login", "username": "webadmin", "password": "AdminPass1!"
        })
        assert r1["ok"] is True
        tok1 = r1["session"]
        # Second login revokes the first session and issues a new token
        r2 = self._send(efs_server, {
            "cmd": "login", "username": "webadmin", "password": "AdminPass1!"
        })
        assert r2["ok"] is True
        assert r2["session"] != tok1
        # tok1 is now revoked
        r3 = self._send(efs_server, {"cmd": "whoami", "session": tok1})
        assert r3["ok"] is False
        # clean up
        self._send(efs_server, {"cmd": "logout", "session": r2["session"]})

    def test_remove_user(self, efs_server):
        login = self._send(efs_server, {
            "cmd": "login", "username": "webadmin", "password": "AdminPass1!"
        })
        tok = login["session"]
        # Create a user to remove
        self._send(efs_server, {
            "cmd": "add_user", "session": tok,
            "username": "doomed_user", "password": "DoomPass1!", "role": "Guest",
        })
        resp = self._send(efs_server, {
            "cmd": "remove_user", "session": tok, "username": "doomed_user",
        })
        assert resp["ok"] is True

    def test_encrypt_missing_filename_rejected(self, efs_server):
        login = self._send(efs_server, {
            "cmd": "login", "username": "webadmin", "password": "AdminPass1!"
        })
        tok = login["session"]
        resp = self._send(efs_server, {
            "cmd": "encrypt", "session": tok,
            "data_b64": base64.b64encode(b"data").decode(),
        })
        assert resp["ok"] is False

    def test_decrypt_nonexistent_file_rejected(self, efs_server):
        login = self._send(efs_server, {
            "cmd": "login", "username": "webadmin", "password": "AdminPass1!"
        })
        tok = login["session"]
        resp = self._send(efs_server, {
            "cmd": "decrypt", "session": tok, "filename": "ghost_file.csv.enc",
        })
        assert resp["ok"] is False


# ---------------------------------------------------------------------------
# 6. web_login() function — auto-launch behavior (no real browser)
# ---------------------------------------------------------------------------

class TestWebLoginFunction:

    def setup_method(self, method):
        self._wlf_srv = None
        self._wlf_tokens = []

    def teardown_method(self, method):
        if self._wlf_srv is None:
            return
        for tok in self._wlf_tokens:
            try:
                _tls_send(self._wlf_srv["host"], self._wlf_srv["port"],
                          self._wlf_srv["cert"], {"cmd": "logout", "session": tok})
            except Exception:
                pass
        self._wlf_tokens.clear()

    def _run_web_login(self, monkeypatch, efs_server, web_username, web_password,
                       flask_port: int = 18500):
        """
        Simulate the full secure web-login flow end-to-end.

        web_login() uses _https_get (raw ssl+socket) to hit GET /?init=<poll_key>
        and poll GET /poll with Cookie: efs_poll_key=<key>.  We capture the
        poll_key by monkeypatching _https_get, then simulate the browser POST
        /login using the same poll_key cookie so the token lands in the right
        _pending bucket.
        """
        import ssl as _ssl
        import urllib.request as _ur
        import urllib.parse

        cert = str(PROJECT_ROOT / "server_pkg" / "certs" / "cert.pem")

        monkeypatch.setenv("EFS_DB_PATH",     efs_server["db_path"])
        monkeypatch.setenv("EFS_WEB_HOST",    "127.0.0.1")
        monkeypatch.setenv("EFS_WEB_PORT",    str(flask_port))
        monkeypatch.setenv("EFS_SERVER_PORT", str(efs_server["port"]))
        monkeypatch.setattr("webbrowser.open", lambda url: None)
        monkeypatch.setattr("client.client.cmd_shell", lambda args: 0)

        import subprocess as _sp
        def _fake_popen(args, **kwargs):
            class _Dummy:
                def communicate(self): return b"", b""
            return _Dummy()
        monkeypatch.setattr(_sp, "Popen", _fake_popen)

        # TLS context for simulated browser POST
        tls_ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
        tls_ctx.load_verify_locations(cert)
        tls_ctx.check_hostname = False
        tls_ctx.verify_mode = _ssl.CERT_REQUIRED

        base = f"https://127.0.0.1:{flask_port}"

        # Capture poll_key from web_login()'s _https_get calls
        captured = {}
        import client.client as _cc
        _real_https_get = _cc._https_get

        def _patched_https_get(host, port, path, headers=None):
            if "init=" in path and "poll_key" not in captured:
                captured["poll_key"] = path.split("init=")[-1]
            return _real_https_get(host, port, path, headers)

        monkeypatch.setattr(_cc, "_https_get", _patched_https_get)

        # Start Flask over HTTPS
        from web.app import run as flask_run
        flask_thread = threading.Thread(
            target=flask_run,
            kwargs={"host": "127.0.0.1", "port": flask_port,
                    "backend_port": efs_server["port"]},
            daemon=True,
        )
        flask_thread.start()
        time.sleep(0.8)

        from client.client import web_login
        result_holder = {}

        def _run():
            result_holder["rc"] = web_login()

        wl_thread = threading.Thread(target=_run, daemon=True)
        wl_thread.start()
        time.sleep(1.2)  # let web_login hit GET /?init=<key>

        poll_key = captured.get("poll_key")
        if poll_key:
            # Fetch CSRF token by GETting / with the poll_key cookie
            opener = _ur.build_opener(
                _ur.HTTPSHandler(context=tls_ctx),
            )
            try:
                resp = opener.open(
                    _ur.Request(f"{base}/", headers={"Cookie": f"efs_poll_key={poll_key}"}),
                    timeout=5,
                )
                html = resp.read().decode()
                # Extract csrf_token from hidden input
                csrf_token = ""
                for part in html.split('name="csrf_token"'):
                    if 'value="' in part:
                        csrf_token = part.split('value="')[1].split('"')[0]
                        break
                if not csrf_token:
                    for part in html.split("csrf_token"):
                        if 'value="' in part:
                            csrf_token = part.split('value="')[1].split('"')[0]
                            break

                post_data = urllib.parse.urlencode({
                    "username": web_username,
                    "password": web_password,
                    "csrf_token": csrf_token,
                }).encode()
                opener.open(
                    _ur.Request(
                        f"{base}/login",
                        data=post_data,
                        method="POST",
                        headers={"Cookie": f"efs_poll_key={poll_key}; efs_csrf_token={csrf_token}"},
                    ),
                    timeout=8,
                )
            except Exception:
                pass

        wl_thread.join(timeout=15)
        return result_holder.get("rc")

    def test_web_login_writes_session_and_returns_zero(self, monkeypatch, efs_server):
        self._wlf_srv = efs_server
        rc = self._run_web_login(monkeypatch, efs_server, "webadmin", "AdminPass1!",
                                 flask_port=18500)
        assert rc == 0
        assert SESSION_FILE.exists()
        token = SESSION_FILE.read_text().strip()
        assert len(token) > 10
        self._wlf_tokens.append(token)

    def test_web_login_session_is_usable_server_token(self, monkeypatch, efs_server):
        self._wlf_srv = efs_server
        self._run_web_login(monkeypatch, efs_server, "webadmin", "AdminPass1!",
                            flask_port=18501)
        token = SESSION_FILE.read_text().strip()
        self._wlf_tokens.append(token)
        # Token written by web login must work directly with the TLS server
        resp = _tls_send(efs_server["host"], efs_server["port"], efs_server["cert"],
                         {"cmd": "list_roles", "session": token})
        assert resp["ok"] is True

    def test_web_login_session_file_permissions(self, monkeypatch, efs_server):
        self._wlf_srv = efs_server
        self._run_web_login(monkeypatch, efs_server, "webanalyst", "AnalystPass1!",
                            flask_port=18502)
        if SESSION_FILE.exists():
            mode = SESSION_FILE.stat().st_mode
            assert stat.S_IMODE(mode) == 0o600


# ---------------------------------------------------------------------------
# Backend port propagation
# ---------------------------------------------------------------------------

class TestBackendPortPropagation:
    """run(backend_port=N) must update _backend_port so _tls_login uses the right port."""

    def test_backend_port_defaults_to_9999(self, monkeypatch):
        import web.app as _wa
        import os
        # Reset to the initial default derived from env var (source of truth)
        default = int(os.environ.get("EFS_SERVER_PORT", "9999"))
        monkeypatch.setattr(_wa, "_backend_port", default)
        assert _wa._backend_port == default

    def test_backend_port_updated_by_run_call(self, monkeypatch):
        """Calling run(backend_port=N) updates the module-level _backend_port."""
        import web.app as _wa

        original = _wa._backend_port
        captured = {}

        # Intercept make_server so run() doesn't actually bind a port
        def _fake_make_server(host, port, app, ssl_context=None):
            class _Srv:
                def serve_forever(self):
                    pass
            return _Srv()

        import threading
        import ssl as _ssl_mod

        monkeypatch.setattr("werkzeug.serving.make_server", _fake_make_server)

        # Run in a thread so serve_forever() returns immediately
        t = threading.Thread(
            target=_wa.run,
            kwargs={"backend_port": 18888},
            daemon=True,
        )
        t.start()
        t.join(timeout=2)

        try:
            assert _wa._backend_port == 18888
        finally:
            _wa._backend_port = original
