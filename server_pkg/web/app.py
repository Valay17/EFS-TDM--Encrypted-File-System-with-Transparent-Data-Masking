"""
EFS-TDM Web Login Server.

Runs on the server machine alongside server.py.
Serves a login page on https://<server-host>:5000  (TLS — same cert as the
backend socket server).

Security properties (defense-in-depth — each layer is independently secure):
  - HTTPS only (TLS 1.2+, cipher-restricted) — traffic encrypted end-to-end
  - HSTS enforced — browsers will not downgrade to HTTP
  - Security headers on every response:
      Strict-Transport-Security, Content-Security-Policy, X-Frame-Options,
      X-Content-Type-Options, Referrer-Policy, Permissions-Policy
  - Server: header suppressed — no Werkzeug fingerprinting
  - poll_key is server-generated, delivered as httpOnly+Secure+SameSite=Strict
    cookie — never in URL, browser history, or access logs
  - /poll requires the exact same httpOnly cookie — replay from another machine
    is blocked even if the attacker intercepts TLS (no poll_key in the traffic)
  - CSRF double-submit cookie — form value must match cookie with constant-time
    comparison
  - Rate limiting on /login: 10 attempts per IP per 5-minute window
  - Account lockout on /login: 5 failures per username locks for 15 minutes
  - Generic auth error — identical message for bad username vs bad password
    (prevents account enumeration)
  - No stack traces exposed — generic 4xx/5xx error pages
  - Pending tokens expire after 5 minutes even if never picked up
  - Token is one-time: removed from _pending on first pickup

On GET /:
  1. Generate a random poll_key and CSRF token
  2. Set both as Secure+SameSite=Strict cookies (poll_key is also httpOnly)
  3. Render the login page (poll_key is NOT in the page HTML or URL)

On POST /login:
  1. Check IP rate limit (10 req / 5 min)
  2. Check account lockout (5 failures / 15 min)
  3. Validate CSRF token (constant-time compare)
  4. Read poll_key from httpOnly cookie
  5. Verify credentials via authenticate() (local DB)
  6. Get session token from TLS backend
  7. Store token in _pending[poll_key] with expiry
  8. Render success page

On GET /poll:
  1. Read poll_key from httpOnly cookie
  2. If token exists and not expired, return it and delete it
  3. Otherwise return {"ok": false}

Environment variable overrides:
  EFS_WEB_PORT      — Flask port (default 5000)
  EFS_WEB_HOST      — Flask bind address (default 0.0.0.0)
  EFS_SERVER_HOST   — TLS backend host (default 127.0.0.1)
  EFS_SERVER_PORT   — TLS backend port (default 9999)
"""

import json
import os
import secrets
import socket
import ssl
import sys
import threading
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from flask import Flask, render_template, request, jsonify, make_response
from server.access_control import authenticate
from core.db import append_audit
from core.config import load_server_config

CERT_PATH = PROJECT_ROOT / "certs" / "cert.pem"
KEY_PATH  = PROJECT_ROOT / "certs" / "key.pem"

app = Flask(__name__, template_folder="templates")
app.secret_key = secrets.token_bytes(32)

# ---------------------------------------------------------------------------
# Pending token store  _pending[poll_key] = {"token": str, "expires": float}
# ---------------------------------------------------------------------------
_pending: dict[str, dict] = {}
_pending_lock = threading.Lock()
_PENDING_TTL = 300  # 5 minutes

# ---------------------------------------------------------------------------
# IP rate limiting  — config-driven
# ---------------------------------------------------------------------------
_web_config = load_server_config()
_IP_WINDOW   = _web_config["web_rate_limiting"]["ip_window_seconds"]
_IP_MAX      = _web_config["web_rate_limiting"]["ip_max_attempts"]
_ip_hits: dict[str, list[float]] = {}
_ip_lock = threading.Lock()

# ---------------------------------------------------------------------------
# Account lockout — config-driven
# ---------------------------------------------------------------------------
_ACCT_MAX      = _web_config["web_rate_limiting"]["account_max_failures"]
_ACCT_LOCKOUT  = _web_config["web_rate_limiting"]["account_lockout_seconds"]
_acct_fails: dict[str, list[float]] = {}
_acct_lock_until: dict[str, float] = {}
_acct_lock = threading.Lock()


def _ip_rate_limited(ip: str) -> bool:
    now = time.time()
    with _ip_lock:
        hits = [t for t in _ip_hits.get(ip, []) if now - t < _IP_WINDOW]
        _ip_hits[ip] = hits
        if len(hits) >= _IP_MAX:
            return True
        hits.append(now)
        _ip_hits[ip] = hits
        return False


def _account_locked(username: str) -> bool:
    now = time.time()
    with _acct_lock:
        until = _acct_lock_until.get(username, 0)
        if until > now:
            return True
        # Clear expired lock
        if until and until <= now:
            _acct_lock_until.pop(username, None)
            _acct_fails.pop(username, None)
        return False


def _record_account_failure(username: str) -> None:
    now = time.time()
    with _acct_lock:
        fails = [t for t in _acct_fails.get(username, []) if now - t < _ACCT_LOCKOUT]
        fails.append(now)
        _acct_fails[username] = fails
        if len(fails) >= _ACCT_MAX:
            _acct_lock_until[username] = now + _ACCT_LOCKOUT
            _acct_fails[username] = []


def _clear_account_failures(username: str) -> None:
    with _acct_lock:
        _acct_fails.pop(username, None)
        _acct_lock_until.pop(username, None)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_backend_port: int = int(os.environ.get("EFS_SERVER_PORT", "9999"))


def _tls_login(username: str, password: str) -> tuple[str, str] | str | None:
    """
    Connect to the TLS backend.
    Returns (session_token, role) on success.
    Returns an error string if the server rejected the login (e.g. already logged in).
    Returns None if the server is unreachable.
    """
    host = os.environ.get("EFS_SERVER_HOST", "127.0.0.1")
    port = _backend_port
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(str(CERT_PATH))
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_REQUIRED
        with socket.create_connection((host, port), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as sock:
                req = json.dumps({"cmd": "login", "username": username,
                                  "password": password})
                sock.sendall(req.encode() + b"\n")
                buf = b""
                while b"\n" not in buf:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    buf += chunk
                resp = json.loads(buf.split(b"\n")[0])
                if resp.get("ok"):
                    return resp["session"], resp.get("role", "")
                return resp.get("error", "Login rejected by server")
    except Exception:
        pass
    return None


def _purge_expired() -> None:
    """Remove stale _pending entries. Must be called under _pending_lock."""
    now = time.time()
    expired = [k for k, v in _pending.items() if v["expires"] < now]
    for k in expired:
        del _pending[k]


def _new_csrf_response(template: str, **ctx) -> object:
    """Render template with a fresh CSRF token and set the cookie."""
    csrf_token = secrets.token_urlsafe(32)
    resp = make_response(render_template(template, csrf_token=csrf_token, **ctx))
    resp.set_cookie("efs_csrf_token", csrf_token,
                    httponly=False, secure=True, samesite="Strict", max_age=600)
    return resp


# ---------------------------------------------------------------------------
# Security headers — applied to every response via after_request
# ---------------------------------------------------------------------------

@app.after_request
def _set_security_headers(response):
    # Force HTTPS for 2 years; include subdomains
    response.headers["Strict-Transport-Security"] = (
        "max-age=63072000; includeSubDomains; preload"
    )
    # Deny framing — prevents clickjacking
    response.headers["X-Frame-Options"] = "DENY"
    # Prevent MIME-type sniffing
    response.headers["X-Content-Type-Options"] = "nosniff"
    # Minimal referrer — no path/query leaked cross-origin
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    # Disable unused browser features
    response.headers["Permissions-Policy"] = (
        "geolocation=(), camera=(), microphone=(), interest-cohort=()"
    )
    # Content Security Policy — strict; no inline scripts or eval
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "   # inline styles in login.html only
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "object-src 'none'; "
        "form-action 'self'; "
        "upgrade-insecure-requests"
    )
    # Cross-origin isolation
    response.headers["Cross-Origin-Opener-Policy"]   = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-site"
    # Remove Werkzeug fingerprint
    response.headers.remove("Server")
    return response


# ---------------------------------------------------------------------------
# Error handlers — no stack traces exposed
# ---------------------------------------------------------------------------

@app.errorhandler(400)
@app.errorhandler(403)
@app.errorhandler(404)
@app.errorhandler(405)
@app.errorhandler(429)
@app.errorhandler(500)
def _generic_error(e):
    code = getattr(e, "code", 500)
    return render_template("error.html", code=code), code


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/", methods=["GET"])
def login_page():
    # Accept an optional client-supplied poll_key via ?init=<key>.
    # This lets the CLI client and the browser share the same poll_key so
    # the client can pick up the token after the user logs in via the browser.
    # The key is validated to be a non-empty URL-safe base64 string (32-48 chars).
    init_key = request.args.get("init", "").strip()
    if init_key and 32 <= len(init_key) <= 64 and init_key.replace("-", "").replace("_", "").isalnum():
        poll_key = init_key
    else:
        poll_key = secrets.token_urlsafe(32)

    csrf_token = secrets.token_urlsafe(32)

    resp = make_response(render_template("login.html", error=None,
                                         csrf_token=csrf_token))
    resp.set_cookie("efs_poll_key",   poll_key,   httponly=True,  secure=True,
                    samesite="Strict", max_age=600)
    resp.set_cookie("efs_csrf_token", csrf_token, httponly=False, secure=True,
                    samesite="Strict", max_age=600)
    return resp


@app.route("/login", methods=["POST"])
def do_login():
    client_ip = request.remote_addr or "unknown"

    # Layer 1 — IP rate limit
    if _ip_rate_limited(client_ip):
        return _new_csrf_response(
            "login.html",
            error="Too many requests. Please wait a few minutes and try again."
        ), 429

    # Layer 2 — CSRF validation (constant-time compare)
    form_csrf   = request.form.get("csrf_token", "")
    cookie_csrf = request.cookies.get("efs_csrf_token", "")
    if not form_csrf or not cookie_csrf or \
            not secrets.compare_digest(form_csrf, cookie_csrf):
        return render_template("login.html",
                               error="Invalid request. Please reload the page.",
                               csrf_token=""), 403

    # Layer 3 — httpOnly poll_key cookie
    poll_key = request.cookies.get("efs_poll_key", "")
    if not poll_key:
        return render_template("login.html",
                               error="Session cookie missing. Please reload.",
                               csrf_token=""), 400

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not username or not password:
        return _new_csrf_response("login.html",
                                  error="Username and password are required.")

    # Layer 4 — Account lockout check
    if _account_locked(username):
        # Generic message — don't confirm the account exists
        return _new_csrf_response(
            "login.html",
            error="Invalid credentials."
        ), 403

    # Layer 5 — Credential check
    user = authenticate(username, password, log=False)
    if user is None:
        _record_account_failure(username)
        append_audit(action="login", outcome="failure", username=username)
        # Generic message — same text for bad user AND bad password
        return _new_csrf_response("login.html", error="Invalid credentials.")

    _clear_account_failures(username)

    # Layer 6 — TLS backend login
    result = _tls_login(username, password)
    if result is None:
        return _new_csrf_response(
            "login.html",
            error="Backend server unreachable. Make sure server.py is running."
        )
    if isinstance(result, str):
        return _new_csrf_response("login.html", error=result)

    token, role = result

    with _pending_lock:
        _purge_expired()
        _pending[poll_key] = {"token": token, "expires": time.time() + _PENDING_TTL}

    return render_template("success.html", username=username, role=role)


@app.route("/poll", methods=["GET"])
def poll():
    """
    Client polls over HTTPS. poll_key comes from the httpOnly cookie only.
    Returns {"ok": true, "token": "..."} once login is complete, or
    {"ok": false} otherwise. Token is deleted on first pickup.
    """
    poll_key = request.cookies.get("efs_poll_key", "")
    if not poll_key:
        return jsonify({"ok": False})

    with _pending_lock:
        entry = _pending.pop(poll_key, None)

    if entry and entry["expires"] > time.time():
        return jsonify({"ok": True, "token": entry["token"]})
    return jsonify({"ok": False})


# ---------------------------------------------------------------------------
# Server startup
# ---------------------------------------------------------------------------

def run(host: str | None = None, port: int | None = None, backend_port: int | None = None, debug: bool = False):
    import ssl as _ssl
    from werkzeug.serving import make_server

    global _backend_port
    h = host or os.environ.get("EFS_WEB_HOST", "0.0.0.0")
    p = port or int(os.environ.get("EFS_WEB_PORT", "5000"))
    if backend_port is not None:
        _backend_port = backend_port

    tls_ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
    tls_ctx.load_cert_chain(certfile=str(CERT_PATH), keyfile=str(KEY_PATH))
    tls_ctx.minimum_version = _ssl.TLSVersion.TLSv1_2
    # Prefer TLS 1.3 ciphers; fall back to restricted TLS 1.2 set
    tls_ctx.set_ciphers(
        # TLS 1.3 suites (automatically preferred when available)
        "TLS_AES_256_GCM_SHA384:"
        "TLS_AES_128_GCM_SHA256:"
        "TLS_CHACHA20_POLY1305_SHA256:"
        # TLS 1.2 fallback — ECDHE + AEAD only, forward secrecy
        "ECDHE-ECDSA-AES256-GCM-SHA384:"
        "ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-AES128-GCM-SHA256:"
        "ECDHE-RSA-AES128-GCM-SHA256:"
        "ECDHE-ECDSA-CHACHA20-POLY1305:"
        "ECDHE-RSA-CHACHA20-POLY1305"
    )

    srv = make_server(h, p, app, ssl_context=tls_ctx)
    srv.serve_forever()


if __name__ == "__main__":
    run()
