"""
EFS-TDM Server.

Listens on a TLS-wrapped local socket (default 127.0.0.1:9999).
Accepts newline-delimited JSON requests from the client, dispatches
to the appropriate module, and returns a JSON response.

Protocol:
  Request:  one JSON object per line, UTF-8, terminated with \\n
  Response: one JSON object per line, UTF-8, terminated with \\n

Every response has at least:
  { "ok": true/false, "error": "<msg>" }   # on failure
  { "ok": true, ... }                       # on success, extra fields vary

Request format:
  { "cmd": "<command>", "session": "<token>", ...args }

Commands (unauthenticated):
  login      { "username": str, "password": str }
  ping       {}

Commands (require valid session token):
  logout     {}
  encrypt    { "filename": str, "data_b64": str }
  decrypt    { "filename": str }
  mask       { "filename": str, "role": str }
  add_user   { "username": str, "password": str, "role": str }
  remove_user { "username": str }
  assign_role { "username": str, "role": str }
  list_users {}
  list_roles {}
  audit_log  { "username": str (opt), "action": str (opt), "limit": int (opt) }

Usage:
  python -m server.server                  # default host/port
  python -m server.server --host 127.0.0.1 --port 9999
"""

import argparse
import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import signal
import socket
import ssl
import sys
import tempfile
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from core.db import (
    init_db, ensure_root, get_db_path, get_conn,
    get_inode, get_inode_by_path_components,
    get_file_meta, create_file_meta, update_file_meta_size,
    create_inode,
    set_acl, revoke_acl, get_acl,
    create_delivery, get_pending_deliveries, update_delivery_status,
    get_role, verify_audit_chain, verify_audit_chain_incremental,
)
from core.encryption import encrypt_file, decrypt_file_with_km
from core.masking import mask_file, load_rules
from core.vfs import (
    resolve_path, resolve_parent, ls as vfs_ls, mkdir as vfs_mkdir,
    rm as vfs_rm, mv as vfs_mv, stat as vfs_stat, tree as vfs_tree,
    inode_path, check_acl,
)
from server.access_control import (
    authenticate,
    add_user,
    assign_role,
    remove_user,
    change_password,
    check_permission,
    list_users,
    list_roles,
    verify_password,
    get_user,
    VALID_ROLES,
)
from server.audit_logger import AuditLogger
from server.key_manager import KeyManager, MK_SIZE_BYTES
from core.config import load_server_config

# Load config once at module level (overridable by EFSServer.__init__)
_server_config = load_server_config()

def _validate_password(password: str, policy: dict | None = None) -> str | None:
    """Return an error string if password fails policy, else None."""
    p = policy or _server_config["password_policy"]
    if len(password) < p["min_length"]:
        return f"Password must be at least {p['min_length']} characters"
    if p.get("require_uppercase", True) and not re.search(r"[A-Z]", password):
        return "Password must contain at least one uppercase letter"
    if p.get("require_lowercase", True) and not re.search(r"[a-z]", password):
        return "Password must contain at least one lowercase letter"
    if p.get("require_digit", True) and not re.search(r"\d", password):
        return "Password must contain at least one number"
    if p.get("require_special", True) and not re.search(r"[^A-Za-z0-9]", password):
        return "Password must contain at least one special character"
    return None


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("efs.server")

# File handler — writes all server logs to server.log next to the DB
_log_file = Path(__file__).parent.parent / "data" / "server.log"
_log_file.parent.mkdir(parents=True, exist_ok=True)
_file_handler = logging.FileHandler(_log_file)
_file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
logging.getLogger().addHandler(_file_handler)

# Derive module-level constants from config (backward compat for tests/imports)
DEFAULT_HOST = _server_config["server"]["host"]
DEFAULT_PORT = _server_config["server"]["port"]
CERT_PATH   = PROJECT_ROOT / _server_config["server"]["cert_path"]
KEY_PATH    = PROJECT_ROOT / _server_config["server"]["key_path"]
MK_PATH     = PROJECT_ROOT / _server_config["server"]["master_key_path"]
DATA_ENC    = PROJECT_ROOT / "data" / "encrypted"

SESSION_TTL        = _server_config["session"]["ttl_seconds"]
MAX_PAYLOAD_BYTES  = _server_config["upload"]["max_bytes"]
MAX_USERNAME_LEN   = 64
MAX_PASSWORD_LEN   = 128
_LOGIN_WINDOW      = _server_config["rate_limiting"]["login_window_seconds"]
_LOGIN_MAX_FAILS   = _server_config["rate_limiting"]["login_max_failures"]

# Per-IP failed login tracker: { ip: [timestamp, ...] }
_login_failures: dict[str, list[float]] = {}
_login_failures_lock = threading.Lock()

# Per-session VFS rate limiter (token bucket).
# Allows legitimate bursts (e.g. listing many files) but blocks automated floods.
# Each session gets a bucket of 20 tokens, refilling at 4 tokens/second.
_VFS_BUCKET_CAPACITY = _server_config["rate_limiting"]["vfs_bucket_capacity"]
_VFS_REFILL_RATE     = _server_config["rate_limiting"]["vfs_refill_rate"]
# { token: {"tokens": float, "last": float} }
_vfs_buckets: dict[str, dict] = {}
_vfs_buckets_lock = threading.Lock()


def _vfs_rate_check(session_token: str) -> bool:
    """Token-bucket rate check for VFS ops. Returns True if allowed."""
    now = time.time()
    with _vfs_buckets_lock:
        bucket = _vfs_buckets.get(session_token)
        if bucket is None:
            _vfs_buckets[session_token] = {"tokens": _VFS_BUCKET_CAPACITY - 1, "last": now}
            return True
        elapsed = now - bucket["last"]
        bucket["tokens"] = min(_VFS_BUCKET_CAPACITY, bucket["tokens"] + elapsed * _VFS_REFILL_RATE)
        bucket["last"] = now
        if bucket["tokens"] >= 1:
            bucket["tokens"] -= 1
            return True
        return False


def _vfs_bucket_clear(session_token: str) -> None:
    with _vfs_buckets_lock:
        _vfs_buckets.pop(session_token, None)


def _check_rate_limit(ip: str) -> bool:
    """Return True if the IP is allowed to attempt login, False if rate-limited."""
    now = time.time()
    with _login_failures_lock:
        times = _login_failures.get(ip, [])
        times = [t for t in times if now - t < _LOGIN_WINDOW]
        _login_failures[ip] = times
        return len(times) < _LOGIN_MAX_FAILS


def _record_login_failure(ip: str) -> None:
    now = time.time()
    with _login_failures_lock:
        _login_failures.setdefault(ip, []).append(now)


def _clear_login_failures(ip: str) -> None:
    with _login_failures_lock:
        _login_failures.pop(ip, None)


# ---------------------------------------------------------------------------
# Audit tamper alert state (module-level, shared across all sessions)
# ---------------------------------------------------------------------------

# Non-empty dict means a tamper event was detected and not yet cleared.
# Shape: { "detected_at": str, "message": str, "mode": str }
_audit_tamper_alert: dict = {}
_audit_tamper_lock = threading.Lock()


class _AuditIntegrityMonitor:
    """
    Background daemon that periodically verifies the audit log HMAC chain.

    Two verification modes:
      Incremental (every poll): checks only rows added since the last poll.
                                Fast; detects tampering within one interval.
      Full scan (every N polls): re-verifies the entire chain from row 1.
                                  Catches retroactive hash replacement that
                                  the incremental scan would miss.

    On detecting tampering:
      - Logs CRITICAL to the server log file.
      - Sets the module-level _audit_tamper_alert dict.
      - The alert is injected into every response for Admin and Auditor
        sessions until rotate_audit is called (which clears it via reset()).

    Skips verification while log rotation is in progress (the live chain is
    transiently incomplete during the backup/truncate sequence).
    """

    def __init__(
        self,
        db_path: str | None,
        interval_seconds: int,
        full_scan_every_n_polls: int,
        audit_rotating_event: threading.Event,
    ) -> None:
        self._db_path = db_path
        self._interval = max(0.05, interval_seconds)
        self._full_every = max(1, full_scan_every_n_polls)
        self._rotating = audit_rotating_event

        self._poll_count = 0
        self._last_id = 0
        self._last_hash = ""
        self._stop = threading.Event()

        t = threading.Thread(
            target=self._run, daemon=True, name="AuditIntegrityMonitor"
        )
        t.start()

    def _run(self) -> None:
        while not self._stop.wait(self._interval):
            if self._rotating.is_set():
                continue
            try:
                self._poll_count += 1
                if self._poll_count % self._full_every == 0:
                    self._full_scan()
                else:
                    self._incremental_scan()
            except Exception:
                logger.exception("AuditIntegrityMonitor: unexpected error during scan")

    def _incremental_scan(self) -> None:
        ok, new_id, new_hash = verify_audit_chain_incremental(
            db_path=self._db_path,
            last_id=self._last_id,
            last_hash=self._last_hash,
        )
        if ok:
            self._last_id = new_id
            self._last_hash = new_hash
        else:
            self._raise_alert("incremental")

    def _full_scan(self) -> None:
        ok = verify_audit_chain(db_path=self._db_path)
        if ok:
            self._resync_tip()
        else:
            self._raise_alert("full")

    def _resync_tip(self) -> None:
        """Sync _last_id and _last_hash to the current chain tip after a confirmed clean full scan."""
        path = self._db_path or get_db_path()
        with get_conn(path) as conn:
            row = conn.execute(
                "SELECT id, chain_hash FROM audit_log ORDER BY id DESC LIMIT 1"
            ).fetchone()
        if row:
            self._last_id = row["id"]
            self._last_hash = row["chain_hash"]
        else:
            self._last_id = 0
            self._last_hash = ""

    def _raise_alert(self, mode: str) -> None:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        msg = (
            f"AUDIT CHAIN INTEGRITY VIOLATION DETECTED "
            f"({mode} scan) at {ts}"
        )
        logger.critical("*** SECURITY ALERT *** %s", msg)
        with _audit_tamper_lock:
            _audit_tamper_alert["detected_at"] = ts
            _audit_tamper_alert["message"] = msg
            _audit_tamper_alert["mode"] = mode

    def reset(self) -> None:
        """
        Called after successful audit log rotation.
        Clears the tamper alert and resets incremental tracking —
        the live log was truncated; the new chain starts from the bootstrap entry.
        """
        with _audit_tamper_lock:
            _audit_tamper_alert.clear()
        self._last_id = 0
        self._last_hash = ""
        self._poll_count = 0

    def stop(self) -> None:
        self._stop.set()


def _safe_filename(filename: str, data_enc: Path = None) -> str | None:
    """
    Validate that filename is a plain filename with no path traversal.
    Returns the sanitized name or None if it is invalid.
    """
    if not filename:
        return None
    p = Path(filename)
    # Must be a single component with no directory separators
    if p.name != filename or filename.startswith(".") or "/" in filename or "\\" in filename:
        return None
    # Resolve what the final path would be and confirm it stays inside the data dir
    base = data_enc if data_enc is not None else DATA_ENC
    resolved = (base / filename).resolve()
    try:
        resolved.relative_to(base.resolve())
    except ValueError:
        return None
    return filename


class EFSServer:
    """
    TLS-wrapped socket server.

    One thread per connected client. All state (KeyManager, AuditLogger,
    session map) is shared across threads and protected by a lock where needed.
    """

    def __init__(
        self,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        cert: str | Path = CERT_PATH,
        key:  str | Path = KEY_PATH,
        db_path: str | None = None,
        master_key: bytes | None = None,
        data_enc: Path | None = None,
    ):
        self.host = host
        self.port = port
        self.cert = str(cert)
        self.key  = str(key)
        self.db_path = db_path
        self.data_enc = data_enc or DATA_ENC

        init_db(db_path)
        ensure_root(db_path)
        self.km  = KeyManager(master_key=master_key)
        self.km.start()
        self._audit_logger = AuditLogger(db_path=db_path,
                                          audit_config=_server_config.get("audit", {}))
        self.masking_rules = load_rules()

        # { session_token: { "username": str, "user_id": int, "role": str } }
        self._sessions: dict[str, dict] = {}
        self._sessions_lock = threading.Lock()

        # Audit write lock: held exclusively during log rotation.
        # All threads that write audit entries acquire it as a shared (read) lock.
        # Rotation acquires it exclusively, queuing all concurrent writes.
        self._audit_lock = threading.Lock()
        self._audit_rotating = threading.Event()  # set while rotation is in progress

        self._server_sock: socket.socket | None = None
        self._running = False

        # Start audit integrity monitor as background daemon
        audit_cfg = _server_config.get("audit", {})
        self._monitor = _AuditIntegrityMonitor(
            db_path=db_path,
            interval_seconds=audit_cfg.get("integrity_check_interval_seconds", 60),
            full_scan_every_n_polls=audit_cfg.get("integrity_full_scan_every_n_polls", 10),
            audit_rotating_event=self._audit_rotating,
        )

    # ------------------------------------------------------------------
    # Audit write guard + proxied logger
    # ------------------------------------------------------------------

    def _audit_guard(self) -> None:
        """
        Block briefly if audit log rotation is in progress.
        Rotation holds _audit_lock exclusively; writers acquire + immediately
        release it so they queue behind rotation without holding it themselves.
        """
        if self._audit_rotating.is_set():
            self._audit_lock.acquire()
            self._audit_lock.release()

    @property
    def log(self) -> AuditLogger:
        """
        Proxy to _audit_logger that inserts the rotation guard before returning.
        All server code uses self.log.xxx() -- the guard fires automatically.
        """
        self._audit_guard()
        return self._audit_logger

    # ------------------------------------------------------------------
    # Session helpers
    # ------------------------------------------------------------------

    def _has_active_session(self, username: str) -> bool:
        """Return True if the user already has a non-expired session."""
        now = time.time()
        with self._sessions_lock:
            for record in self._sessions.values():
                if record["username"] == username and record["expires"] > now:
                    return True
        return False

    def _create_session(self, user: dict) -> str:
        token = secrets.token_urlsafe(32)
        with self._sessions_lock:
            self._sessions[token] = {
                "username": user["username"],
                "user_id":  user["id"],
                "role":     user["role"],
                "expires":  time.time() + SESSION_TTL,
            }
        return token

    def _get_session(self, token: str) -> dict | None:
        with self._sessions_lock:
            record = self._sessions.get(token)
            if record is None:
                return None
            if time.time() > record["expires"]:
                self._sessions.pop(token, None)
                return None
            return record

    def _delete_session(self, token: str) -> None:
        with self._sessions_lock:
            self._sessions.pop(token, None)

    def _revoke_user_sessions(self, username: str) -> None:
        """Revoke all active sessions for a given user (e.g. after password change)."""
        with self._sessions_lock:
            stale = [t for t, r in self._sessions.items() if r["username"] == username]
            for t in stale:
                del self._sessions[t]

    # ------------------------------------------------------------------
    # Root admin helper
    # ------------------------------------------------------------------

    def _is_root_admin(self, username: str) -> bool:
        """Return True if username is the root admin (first user created, id=1)."""
        user = get_user(username, self.db_path)
        return user is not None and user["id"] == 1

    def _get_root_admin_username(self) -> str | None:
        """Return the username of the root admin (id=1), or None if not found."""
        with get_conn(self.db_path) as conn:
            row = conn.execute("SELECT username FROM users WHERE id = 1").fetchone()
        return row["username"] if row else None

    # ------------------------------------------------------------------
    # Command handlers
    # ------------------------------------------------------------------

    def _handle_ping(self, req: dict, session: dict | None) -> dict:
        return {"ok": True, "message": "pong"}

    def _handle_login(self, req: dict, session: dict | None,
                      client_ip: str = "unknown") -> dict:
        if not _check_rate_limit(client_ip):
            return {"ok": False, "error": "Too many login attempts. Try again later."}

        username = req.get("username", "")
        password = req.get("password", "")

        if len(username) > MAX_USERNAME_LEN or len(password) > MAX_PASSWORD_LEN:
            return {"ok": False, "error": "Invalid credentials"}

        user = authenticate(username, password, self.db_path, log=False)
        if user is None:
            _record_login_failure(client_ip)
            existing = get_user(username, self.db_path)
            self.log.login(username, success=False,
                           role=existing["role"] if existing else None)
            return {"ok": False, "error": "Invalid credentials"}

        _clear_login_failures(client_ip)

        now = time.time()
        with self._sessions_lock:
            stale = [t for t, r in self._sessions.items()
                     if r["username"] == username and r["expires"] > now]
            for t in stale:
                del self._sessions[t]
                _vfs_bucket_clear(t)
            token = secrets.token_urlsafe(32)
            self._sessions[token] = {
                "username": user["username"],
                "user_id":  user["id"],
                "role":     user["role"],
                "expires":  now + SESSION_TTL,
            }

        self.log.login(username, user_id=user["id"], success=True, role=user["role"])
        return {"ok": True, "session": token, "role": user["role"]}

    def _handle_logout(self, req: dict, session: dict) -> dict:
        token = req.get("session", "")
        self._delete_session(token)
        _vfs_bucket_clear(token)
        self.log.logout(session["username"], user_id=session["user_id"],
                        role=session["role"])
        return {"ok": True}

    def _handle_encrypt(self, req: dict, session: dict) -> dict:
        username = session["username"]
        if not check_permission(username, "encrypt", self.db_path):
            self.log.permission_denied(username, "encrypt", role=session["role"])
            return {"ok": False, "error": "Permission denied"}

        filename = _safe_filename(req.get("filename", ""), self.data_enc)
        data_b64 = req.get("data_b64", "")
        if not filename or not data_b64:
            return {"ok": False, "error": "filename and data_b64 required"}

        if len(data_b64) > MAX_PAYLOAD_BYTES * 4 // 3 + 4:
            return {"ok": False, "error": "Payload too large"}

        try:
            plaintext = base64.b64decode(data_b64)
        except Exception:
            return {"ok": False, "error": "Invalid base64 data"}

        self.data_enc.mkdir(parents=True, exist_ok=True)
        dst = self.data_enc / (filename + ".enc")

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(plaintext)
            tmp_path = tmp.name

        try:
            dek = self.km.derive_dek(filename)
            enc_path = encrypt_file(tmp_path, dek, dst)
            del dek
        finally:
            os.unlink(tmp_path)

        session_id = self.km.issue_key(username, filename)
        self.km.revoke_key(session_id)
        self.log.encrypt(username, user_id=session["user_id"], file_id=filename,
                         role=session["role"])
        return {"ok": True, "stored_as": enc_path.name}

    def _handle_decrypt(self, req: dict, session: dict) -> dict:
        username = session["username"]
        if not check_permission(username, "decrypt", self.db_path):
            self.log.permission_denied(username, "decrypt", role=session["role"])
            return {"ok": False, "error": "Permission denied"}

        filename = _safe_filename(req.get("filename", ""), self.data_enc)
        if not filename:
            return {"ok": False, "error": "filename required"}

        enc_path = self.data_enc / filename
        if not enc_path.exists():
            return {"ok": False, "error": "File not found"}

        try:
            plaintext = decrypt_file_with_km(enc_path, self.km)
        except Exception:
            self.log.decrypt(username, user_id=session["user_id"],
                             file_id=filename, success=False, role=session["role"])
            return {"ok": False, "error": "Decryption failed"}

        self.log.decrypt(username, user_id=session["user_id"], file_id=filename,
                         role=session["role"])
        return {"ok": True, "data_b64": base64.b64encode(plaintext).decode()}

    def _handle_mask(self, req: dict, session: dict) -> dict:
        username = session["username"]
        if not check_permission(username, "mask", self.db_path):
            self.log.permission_denied(username, "mask", role=session["role"])
            return {"ok": False, "error": "Permission denied"}

        filename = _safe_filename(req.get("filename", ""))
        role = req.get("role") or session["role"]
        if role not in VALID_ROLES:
            return {"ok": False, "error": "Invalid role"}
        if not filename:
            return {"ok": False, "error": "filename required"}

        enc_path = self.data_enc / filename
        if not enc_path.exists():
            return {"ok": False, "error": "File not found"}

        try:
            plaintext = decrypt_file_with_km(enc_path, self.km)
        except Exception:
            self.log.mask(username, user_id=session["user_id"],
                          file_id=filename, success=False, role=session["role"])
            return {"ok": False, "error": "Decryption failed"}

        # Determine original extension for masking
        original_name = enc_path.stem  # e.g. employees.csv
        ext = Path(original_name).suffix.lower()

        with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as tmp:
            tmp.write(plaintext)
            tmp_path = tmp.name

        try:
            masked = mask_file(tmp_path, role=role, rules_config=self.masking_rules)
        except Exception:
            self.log.mask(username, user_id=session["user_id"],
                          file_id=filename, success=False, role=session["role"])
            return {"ok": False, "error": "Masking failed"}
        finally:
            os.unlink(tmp_path)

        self.log.mask(username, user_id=session["user_id"], file_id=filename,
                      role=session["role"])
        if isinstance(masked, str):
            return {"ok": True, "masked": masked, "role": role}
        return {"ok": True, "masked": masked.decode("utf-8", errors="replace"), "role": role}

    def _handle_add_user(self, req: dict, session: dict) -> dict:
        username = session["username"]
        if not check_permission(username, "manage_users", self.db_path):
            self.log.permission_denied(username, "manage_users", role=session["role"])
            return {"ok": False, "error": "Permission denied"}

        target = req.get("username", "")
        password = req.get("password", "")
        role = req.get("role", _server_config["defaults"]["new_user_role"])
        if not target or not password:
            return {"ok": False, "error": "username and password required"}

        err = _validate_password(password)
        if err:
            return {"ok": False, "error": err}

        try:
            result = add_user(target, password, role, self.db_path)
        except ValueError as e:
            return {"ok": False, "error": str(e)}
        except Exception:
            logger.exception("add_user failed for target=%s", target)
            return {"ok": False, "error": "Failed to create user"}

        self.log.add_user(username, target, role, caller_role=session["role"])
        return {"ok": True, "username": result["username"], "role": result["role"]}

    def _handle_remove_user(self, req: dict, session: dict) -> dict:
        username = session["username"]
        if not check_permission(username, "manage_users", self.db_path):
            self.log.permission_denied(username, "manage_users", role=session["role"])
            return {"ok": False, "error": "Permission denied"}

        target = req.get("username", "")
        if not target:
            return {"ok": False, "error": "username required"}

        if target == username:
            return {"ok": False, "error": "Cannot delete your own account"}

        target_user = get_user(target, self.db_path)
        if not target_user:
            return {"ok": False, "error": f"User '{target}' not found"}

        # Only root admin (id=1) can delete other admin accounts
        if target_user["role"] == "Admin" and not self._is_root_admin(username):
            return {"ok": False, "error": "Only the root admin can delete admin accounts"}

        # Root admin (id=1) cannot be deleted by anyone
        if target_user["id"] == 1:
            return {"ok": False, "error": "The root admin account cannot be deleted"}

        deleted = remove_user(target, self.db_path)
        if not deleted:
            return {"ok": False, "error": f"User '{target}' not found"}

        self.log.remove_user(username, target, caller_role=session["role"])
        return {"ok": True}

    def _handle_assign_role(self, req: dict, session: dict) -> dict:
        username = session["username"]
        if not check_permission(username, "manage_users", self.db_path):
            self.log.permission_denied(username, "manage_users", role=session["role"])
            return {"ok": False, "error": "Permission denied"}

        target = req.get("username", "")
        role = req.get("role", "")
        if not target or not role:
            return {"ok": False, "error": "username and role required"}

        if role == "Admin" and session["role"] != "Admin":
            return {"ok": False, "error": "Only admins can assign the Admin role"}

        # Root admin (id=1) role cannot be changed by anyone
        target_user = get_user(target, self.db_path)
        if target_user and target_user["id"] == 1:
            return {"ok": False, "error": "The root admin role cannot be changed"}

        try:
            updated = assign_role(target, role, self.db_path)
        except ValueError as e:
            return {"ok": False, "error": str(e)}

        if not updated:
            return {"ok": False, "error": f"User '{target}' not found"}

        self._revoke_user_sessions(target)
        self.log.assign_role(username, target, role, caller_role=session["role"])
        return {"ok": True}

    def _handle_list_users(self, req: dict, session: dict) -> dict:
        username = session["username"]
        if not check_permission(username, "manage_users", self.db_path):
            self.log.permission_denied(username, "manage_users", role=session["role"])
            return {"ok": False, "error": "Permission denied"}
        return {"ok": True, "users": list_users(self.db_path)}

    def _handle_list_roles(self, req: dict, session: dict) -> dict:
        username = session["username"]
        if not check_permission(username, "manage_users", self.db_path):
            self.log.permission_denied(username, "list_roles", role=session["role"])
            return {"ok": False, "error": "Permission denied"}
        return {"ok": True, "roles": list_roles(self.db_path)}

    def _handle_audit_log(self, req: dict, session: dict) -> dict:
        username = session["username"]
        if not check_permission(username, "view_audit", self.db_path):
            self.log.permission_denied(username, "view_audit", role=session["role"])
            return {"ok": False, "error": "Permission denied"}

        if req.get("verify"):
            ok = verify_audit_chain(self.db_path)
            self.log.log("audit_verify", "success" if ok else "failure",
                         username=username, user_id=session["user_id"],
                         role=session["role"])
            return {"ok": True, "chain_valid": ok}

        archive = req.get("archive")
        if archive:
            # Archive queries: anyone with view_audit (Admin + Auditor)
            if not check_permission(username, "view_audit", self.db_path):
                self.log.permission_denied(username, "view_audit_archive",
                                           role=session["role"])
                return {"ok": False, "error": "Permission denied"}
            if not archive or "/" in archive or "\\" in archive or archive.startswith("."):
                return {"ok": False, "error": "Invalid archive name"}
            data_dir = Path(self.db_path or get_db_path()).parent.resolve()
            archive_path = (data_dir / archive).resolve()
            if not str(archive_path).startswith(str(data_dir)):
                return {"ok": False, "error": "Invalid archive name"}
            if not archive_path.exists():
                return {"ok": False, "error": f"Archive not found: {archive}"}
            db_path_to_query = str(archive_path)
        else:
            db_path_to_query = None  # use live log

        default_ql = _server_config["audit"]["default_query_limit"]
        limit = req.get("limit", default_ql)
        if not isinstance(limit, int) or limit < 0:
            return {"ok": False, "error": "limit must be a non-negative integer (0 = no limit)"}

        entries = self.log.query(
            username=req.get("username"),
            action=req.get("action"),
            limit=limit,
            from_ts=req.get("from_ts"),
            to_ts=req.get("to_ts"),
            db_path=db_path_to_query,
        )
        return {"ok": True, "entries": entries}

    def _handle_rotate_audit(self, req: dict, session: dict) -> dict:
        username = session["username"]
        if not check_permission(username, "manage_users", self.db_path):
            self.log.permission_denied(username, "rotate_audit", role=session["role"])
            return {"ok": False, "error": "Permission denied"}

        # Signal rotation in progress -- _audit_guard() in each request thread
        # will spin-wait before writing any new audit entry.
        self._audit_rotating.set()
        with self._audit_lock:
            try:
                # Use _audit_logger directly -- self.log goes through _audit_guard()
                # which would deadlock trying to re-acquire _audit_lock on this thread.
                retention = _server_config["audit"]["retention_max_archives"]
                archive_name = self._audit_logger.rotate(
                    username=username,
                    retention_max_archives=retention,
                )
            except Exception as e:
                logger.exception("Audit log rotation failed")
                return {"ok": False, "error": f"Rotation failed: {e}"}
            finally:
                self._audit_rotating.clear()

        # Reset monitor: new chain starts from bootstrap entry; clear any prior alert
        self._monitor.reset()
        return {"ok": True, "archive": archive_name}

    def _handle_whoami(self, req: dict, session: dict) -> dict:
        return {
            "ok": True,
            "username": session["username"],
            "role":     session["role"],
        }

    def _handle_get_my_permissions(self, req: dict, session: dict) -> dict:
        role = get_role(session["role"], self.db_path)
        if role is None:
            return {"ok": False, "error": "Role not found"}
        return {
            "ok": True,
            "role": session["role"],
            "permissions": role["permissions"],
            "password_policy": _server_config["password_policy"],
        }

    def _handle_active_users(self, req: dict, session: dict) -> dict:
        if not check_permission(session["username"], "manage_users", self.db_path):
            return {"ok": False, "error": "Permission denied"}
        now = time.time()
        with self._sessions_lock:
            active = [
                {
                    "username":   r["username"],
                    "role":       r["role"],
                    "expires_in": max(0, int(r["expires"] - now)),
                }
                for r in self._sessions.values()
                if r["expires"] > now
            ]
        return {"ok": True, "users": active}

    def _handle_change_password(self, req: dict, session: dict) -> dict:
        username    = session["username"]
        old_pw      = req.get("old_password", "")
        verify_only = req.get("verify_only", False)

        if not old_pw:
            return {"ok": False, "error": "old_password required"}

        user = get_user(username, self.db_path)
        if not user or not verify_password(old_pw, user["password_hash"]):
            return {"ok": False, "error": "Current password is incorrect"}

        if verify_only:
            return {"ok": True}

        new_pw = req.get("new_password", "")
        if not new_pw:
            return {"ok": False, "error": "new_password required"}

        err = _validate_password(new_pw)
        if err:
            return {"ok": False, "error": err}

        change_password(username, new_pw, self.db_path, log=False)
        self._revoke_user_sessions(username)
        self.log.log("change_password", "success", username=username,
                     user_id=session["user_id"], role=session["role"])
        return {"ok": True}

    def _handle_reset_password(self, req: dict, session: dict) -> dict:
        username = session["username"]
        if not check_permission(username, "manage_users", self.db_path):
            self.log.permission_denied(username, "manage_users", role=session["role"])
            return {"ok": False, "error": "Permission denied"}

        target = req.get("username", "")
        new_pw  = req.get("new_password", "")

        if not target or not new_pw:
            return {"ok": False, "error": "username and new_password required"}

        if target == username:
            return {"ok": False, "error": "Use change_password to change your own password"}

        target_user = get_user(target, self.db_path)
        if target_user and target_user["role"] == "Admin" and not self._is_root_admin(username):
            return {"ok": False, "error": "Only the root admin can reset another admin's password"}

        err = _validate_password(new_pw)
        if err:
            return {"ok": False, "error": err}

        updated = change_password(target, new_pw, self.db_path, log=False)
        if not updated:
            return {"ok": False, "error": f"User '{target}' not found"}

        self._revoke_user_sessions(target)
        self.log.log("password_reset", "success", username=username,
                     file_id=f"user:{target}", role=session["role"])
        return {"ok": True}

    def _handle_delete_account(self, req: dict, session: dict) -> dict:
        username = session["username"]
        password = req.get("password", "")

        if not password:
            return {"ok": False, "error": "password required to confirm deletion"}

        user = get_user(username, self.db_path)
        if not user or not verify_password(password, user["password_hash"]):
            return {"ok": False, "error": "Incorrect password"}

        if user["role"] == "Admin":
            return {"ok": False, "error": "Admin accounts cannot be self-deleted. Use another admin to remove this account."}

        remove_user(username, self.db_path)
        token = req.get("session", "")
        self._delete_session(token)
        self.log.log("delete_account", "success", username=username,
                     user_id=session["user_id"], role=session["role"])
        return {"ok": True}

    # ------------------------------------------------------------------
    # VFS handlers
    # ------------------------------------------------------------------

    def _vfs_ls(self, req: dict, session: dict) -> dict:
        username = session["username"]
        role = session["role"]
        if not check_permission(username, "list", self.db_path):
            self.log.permission_denied(username, "list", role=role)
            return {"ok": False, "error": "Permission denied"}
        path = req.get("path", "/")
        cwd  = req.get("cwd", "/")
        acl_mode = _server_config["acl"]["default_mode"]
        # Check ACL read on the directory being listed (deny_wins: parent deny overrides child grant)
        dir_node = resolve_path(path, cwd, self.db_path)
        if dir_node is not None and not check_acl(dir_node["id"], role, "read", self.db_path,
                                                   default_mode=acl_mode, deny_wins=True):
            self.log.permission_denied(username, "ls_acl", role=role)
            return {"ok": False, "error": "Permission denied"}
        try:
            entries = vfs_ls(path, cwd, self.db_path)
        except (FileNotFoundError, NotADirectoryError) as e:
            return {"ok": False, "error": str(e)}
        result = []
        for e in entries:
            if not check_acl(e["id"], role, "read", self.db_path,
                              default_mode=acl_mode, deny_wins=True):
                continue
            result.append({
                "id":            e["id"],
                "name":          e["name"],
                "type":          "dir" if e["is_dir"] else "file",
                "owner":         e["owner"],
                "created_at":    e["created_at"],
                "size_bytes":    e.get("size_bytes"),
                "original_name": e.get("original_name"),
                "uploaded_at":   e.get("uploaded_at"),
            })
        return {"ok": True, "entries": result}

    def _vfs_mkdir(self, req: dict, session: dict) -> dict:
        username = session["username"]
        role     = session["role"]
        if not check_permission(username, "write", self.db_path):
            self.log.permission_denied(username, "mkdir", role=role)
            return {"ok": False, "error": "Permission denied"}
        path = req.get("path", "")
        cwd  = req.get("cwd", "/")
        if not path:
            return {"ok": False, "error": "path required"}
        parent_node, _ = resolve_parent(path, cwd, self.db_path)
        if parent_node is not None and get_acl(parent_node["id"], self.db_path):
            if not check_acl(parent_node["id"], role, "write", self.db_path):
                self.log.permission_denied(username, "mkdir_acl", role=role)
                return {"ok": False, "error": "Permission denied"}
        try:
            inode_id = vfs_mkdir(path, cwd, owner=username, db_path=self.db_path)
        except (FileExistsError, NotADirectoryError) as e:
            return {"ok": False, "error": str(e)}
        self.log.log("mkdir", "success", username=username, user_id=session["user_id"],
                     file_id=path, role=role)
        return {"ok": True, "inode_id": inode_id}

    def _vfs_stat(self, req: dict, session: dict) -> dict:
        username = session["username"]
        if not check_permission(username, "list", self.db_path):
            self.log.permission_denied(username, "stat", role=session["role"])
            return {"ok": False, "error": "Permission denied"}
        path = req.get("path", "")
        cwd  = req.get("cwd", "/")
        if not path:
            return {"ok": False, "error": "path required"}
        node = resolve_path(path, cwd, self.db_path)
        if node is None:
            return {"ok": False, "error": "No such file or directory"}
        try:
            info = vfs_stat(node["id"], self.db_path)
        except FileNotFoundError as e:
            return {"ok": False, "error": str(e)}
        if session["role"] != "Admin":
            info.pop("acl", None)
        return {"ok": True, "stat": info}

    def _vfs_tree(self, req: dict, session: dict) -> dict:
        username = session["username"]
        role = session["role"]
        if not check_permission(username, "list", self.db_path):
            self.log.permission_denied(username, "tree", role=role)
            return {"ok": False, "error": "Permission denied"}
        path = req.get("path", "/")
        cwd  = req.get("cwd", "/")
        node = resolve_path(path, cwd, self.db_path)
        if node is None:
            return {"ok": False, "error": "No such file or directory"}
        acl_mode = _server_config["acl"]["default_mode"]
        if not check_acl(node["id"], role, "read", self.db_path,
                          default_mode=acl_mode, deny_wins=True):
            self.log.permission_denied(username, "tree_acl", role=role)
            return {"ok": False, "error": "Permission denied"}
        lines = vfs_tree(node["id"], self.db_path, role=role, acl_mode=acl_mode)
        return {"ok": True, "tree": lines}

    def _vfs_rm(self, req: dict, session: dict) -> dict:
        username = session["username"]
        role = session["role"]
        path = req.get("path", "")
        cwd  = req.get("cwd", "/")
        if not path:
            return {"ok": False, "error": "path required"}
        node = resolve_path(path, cwd, self.db_path)
        if node is None:
            return {"ok": False, "error": "No such file or directory"}

        is_own = (node["owner"] == username)
        # ACL priority: explicit deny > explicit grant > global role permission.
        # check_acl(default_mode="open")   → False only on explicit deny
        # check_acl(default_mode="closed") → True only on explicit grant
        acl_not_denied_own  = check_acl(node["id"], role, "delete_own", self.db_path, default_mode="open")
        acl_granted_own     = check_acl(node["id"], role, "delete_own", self.db_path, default_mode="closed")
        acl_not_denied_any  = check_acl(node["id"], role, "delete_any", self.db_path, default_mode="closed")
        acl_granted_any     = check_acl(node["id"], role, "delete_any", self.db_path, default_mode="closed")
        if role == "Admin":
            pass
        elif is_own and not acl_not_denied_own:
            # Explicit ACL deny on delete_own for own file is absolute — delete_any cannot override it
            self.log.permission_denied(username, "rm", role=role)
            return {"ok": False, "error": "Permission denied"}
        elif is_own and (acl_granted_own or (acl_not_denied_own and check_permission(username, "delete_own", self.db_path))):
            pass
        elif acl_granted_any or (acl_not_denied_any and check_permission(username, "delete_any", self.db_path)):
            pass
        else:
            self.log.permission_denied(username, "rm", role=role)
            return {"ok": False, "error": "Permission denied"}

        if not check_acl(node["id"], role, "read", self.db_path,
                         default_mode=_server_config["acl"]["default_mode"]):
            self.log.permission_denied(username, "rm_acl", role=role)
            return {"ok": False, "error": "Permission denied"}

        if not node["is_dir"]:
            meta = get_file_meta(node["id"], self.db_path)
            if meta:
                blob = self.data_enc / meta["blob_name"]
                try:
                    blob.unlink(missing_ok=True)
                except Exception:
                    pass

        vfs_path = inode_path(node["id"], self.db_path)
        vfs_rm(node["id"], self.db_path)
        self.log.log("rm", "success", username=username, user_id=session["user_id"],
                     file_id=vfs_path, role=role)
        return {"ok": True}

    def _vfs_mv(self, req: dict, session: dict) -> dict:
        username = session["username"]
        role = session["role"]
        if not check_permission(username, "write", self.db_path):
            self.log.permission_denied(username, "mv", role=role)
            return {"ok": False, "error": "Permission denied"}
        src  = req.get("src", "")
        dst  = req.get("dst", "")
        cwd  = req.get("cwd", "/")
        if not src or not dst:
            return {"ok": False, "error": "src and dst required"}

        src_node = resolve_path(src, cwd, self.db_path)
        if src_node is None:
            return {"ok": False, "error": "Source not found"}

        # Only owner or admin can move a file
        if role != "Admin" and src_node["owner"] != username:
            self.log.permission_denied(username, "mv", role=role)
            return {"ok": False, "error": "Permission denied: you do not own this file"}

        dst_node = resolve_path(dst, cwd, self.db_path)
        if dst_node is not None and dst_node["is_dir"]:
            dst_parent = dst_node
            dst_name = src_node["name"]
        else:
            dst_parent, dst_name = resolve_parent(dst, cwd, self.db_path)
            if dst_parent is None:
                return {"ok": False, "error": "Destination parent directory not found"}

        if get_acl(dst_parent["id"], self.db_path) and not check_acl(dst_parent["id"], role, "write", self.db_path):
            self.log.permission_denied(username, "mv_acl", role=role)
            return {"ok": False, "error": "Permission denied"}

        if get_inode_by_path_components(dst_parent["id"], dst_name, self.db_path) is not None:
            return {"ok": False, "error": f"Move failed: '{dst_name}' already exists in destination"}

        try:
            vfs_mv(src_node["id"], dst_parent["id"], dst_name, self.db_path)
        except Exception:
            logger.exception("vfs_mv failed: src=%s dst=%s", src, dst)
            return {"ok": False, "error": "Move failed"}
        self.log.log("mv", "success", username=username, user_id=session["user_id"],
                     file_id=f"{src} -> {dst}", role=role)
        return {"ok": True}

    def _vfs_chmod(self, req: dict, session: dict) -> dict:
        username = session["username"]
        if not check_permission(username, "manage_permissions", self.db_path):
            self.log.permission_denied(username, "chmod", role=session["role"])
            return {"ok": False, "error": "Permission denied"}
        path   = req.get("path", "")
        cwd    = req.get("cwd", "/")
        role   = req.get("role", "")
        perm   = req.get("perm", "")
        action = req.get("action", "grant")
        if not path or not role or not perm:
            return {"ok": False, "error": "path, role, and perm required"}
        _VALID_PERMS = {"read", "write", "delete_own", "delete_any"}
        if perm not in _VALID_PERMS:
            return {"ok": False, "error": f"Invalid perm '{perm}'. Must be one of: {', '.join(sorted(_VALID_PERMS))}"}
        node = resolve_path(path, cwd, self.db_path)
        if node is None:
            return {"ok": False, "error": "No such file or directory"}
        if action == "grant":
            set_acl(node["id"], role, perm, self.db_path)
        elif action == "revoke":
            revoke_acl(node["id"], role, perm, self.db_path)
        else:
            return {"ok": False, "error": "action must be 'grant' or 'revoke'"}
        self.log.log("chmod", "success", username=username, user_id=session["user_id"],
                     file_id=f"{inode_path(node['id'], self.db_path)} [{action} {perm} -> {role}]",
                     role=session["role"])
        return {"ok": True}

    def _vfs_send(self, req: dict, session: dict) -> dict:
        """
        Upload a file into the VFS.
        Request: { cmd, session, path, cwd, data_b64, size }
        The file content is base64-encoded in the JSON field data_b64.
        Server encrypts, stores blob, and registers in inodes + file_meta.
        """
        username = session["username"]
        role     = session["role"]
        if not check_permission(username, "write", self.db_path):
            self.log.permission_denied(username, "write", role=role)
            return {"ok": False, "error": "Permission denied"}

        path    = req.get("path", "")
        cwd     = req.get("cwd", "/")
        data_b64 = req.get("data_b64")
        if not path or data_b64 is None:
            return {"ok": False, "error": "path and data_b64 required"}

        if len(data_b64) > MAX_PAYLOAD_BYTES * 4 // 3 + 4:
            return {"ok": False, "error": "Payload too large"}

        try:
            plaintext = base64.b64decode(data_b64)
        except Exception:
            return {"ok": False, "error": "Invalid base64 data"}

        parent_node, filename = resolve_parent(path, cwd, self.db_path)
        if parent_node is None:
            return {"ok": False, "error": "Parent directory not found"}
        if not filename:
            return {"ok": False, "error": "Invalid path"}

        if get_acl(parent_node["id"], self.db_path) and not check_acl(parent_node["id"], role, "write", self.db_path):
            self.log.permission_denied(username, "send_acl", role=role)
            return {"ok": False, "error": "Permission denied"}

        overwrite = bool(req.get("overwrite", False))
        existing = resolve_path(path, cwd, self.db_path)
        if existing is not None and existing["is_dir"]:
            return {"ok": False, "error": "Path is a directory"}
        if existing is not None and overwrite:
            if get_acl(existing["id"], self.db_path) and not check_acl(existing["id"], role, "write", self.db_path):
                self.log.permission_denied(username, "send_overwrite_acl", role=role)
                return {"ok": False, "error": "Permission denied"}
        if existing is not None and not overwrite:
            meta = get_file_meta(existing["id"], self.db_path)
            return {
                "ok": False,
                "error": "already_exists",
                "stat": {
                    "size_bytes":   meta["size_bytes"] if meta else None,
                    "uploaded_at":  existing.get("created_at"),
                    "content_hash": meta["content_hash"] if meta else None,
                },
            }

        self.data_enc.mkdir(parents=True, exist_ok=True)
        blob_name = str(uuid.uuid4()) + ".enc"
        dst = self.data_enc / blob_name

        content_hash = hashlib.sha256(plaintext).hexdigest()

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(plaintext)
            tmp_path = tmp.name

        try:
            dek = self.km.derive_dek(blob_name)
            encrypt_file(tmp_path, dek, dst)
            del dek
        finally:
            os.unlink(tmp_path)

        if existing is not None:
            meta = get_file_meta(existing["id"], self.db_path)
            if meta:
                old_blob = self.data_enc / meta["blob_name"]
                try:
                    old_blob.unlink(missing_ok=True)
                except Exception:
                    pass
            update_file_meta_size(existing["id"], len(plaintext), self.db_path,
                                  content_hash=content_hash)
            with get_conn(self.db_path) as conn:
                conn.execute(
                    "UPDATE file_meta SET blob_name = ?, original_name = ? WHERE inode_id = ?",
                    (blob_name, filename, existing["id"]),
                )
                conn.execute(
                    "UPDATE inodes SET owner = ? WHERE id = ?",
                    (username, existing["id"]),
                )
            inode_id = existing["id"]
        else:
            inode_id = create_inode(filename, parent_node["id"],
                                    is_dir=False, owner=username,
                                    db_path=self.db_path)
            create_file_meta(inode_id, blob_name, len(plaintext),
                              filename, self.db_path, content_hash=content_hash)

        full_path = inode_path(inode_id, self.db_path)
        self.log.log("send", "success", username=username, user_id=session["user_id"],
                     file_id=full_path, role=session["role"])
        self.log.encrypt(username, user_id=session["user_id"], file_id=full_path,
                         role=session["role"])
        return {"ok": True, "inode_id": inode_id, "path": full_path, "blob": blob_name}

    def _vfs_fetch(self, req: dict, session: dict) -> dict:
        """
        Download (decrypt + optional mask) a file from the VFS.
        Request: { cmd, session, path, cwd, raw (bool) }
        raw=True requires export_raw permission (admin only).
        raw=False requires read permission; content is masked.
        """
        username = session["username"]
        role     = session["role"]
        path = req.get("path", "")
        cwd  = req.get("cwd", "/")
        raw  = bool(req.get("raw", False))

        if not path:
            return {"ok": False, "error": "path required"}

        node = resolve_path(path, cwd, self.db_path)
        if node is None:
            return {"ok": False, "error": "No such file or directory"}
        if node["is_dir"]:
            return {"ok": False, "error": "Path is a directory"}

        if raw:
            if not check_permission(username, "export_raw", self.db_path):
                self.log.permission_denied(username, "export_raw", role=role)
                return {"ok": False, "error": "Permission denied: --raw requires export_raw permission (admin only)"}
            if get_acl(node["id"], self.db_path) and not check_acl(node["id"], role, "read", self.db_path):
                self.log.permission_denied(username, "fetch_acl", role=role)
                return {"ok": False, "error": "Permission denied"}
        else:
            if not check_permission(username, "read", self.db_path):
                self.log.permission_denied(username, "read", role=role)
                return {"ok": False, "error": "Permission denied"}
            if get_acl(node["id"], self.db_path) and not check_acl(node["id"], role, "read", self.db_path):
                self.log.permission_denied(username, "fetch_acl", role=role)
                return {"ok": False, "error": "Permission denied"}

        meta = get_file_meta(node["id"], self.db_path)
        if not meta:
            return {"ok": False, "error": "File metadata missing"}

        enc_path = self.data_enc / meta["blob_name"]
        if not enc_path.exists():
            return {"ok": False, "error": "Encrypted blob not found"}

        vfs_path = inode_path(node["id"], self.db_path)

        try:
            plaintext = decrypt_file_with_km(enc_path, self.km,
                                              key_id=meta["blob_name"])
        except Exception:
            self.log.decrypt(username, user_id=session["user_id"],
                             file_id=vfs_path, success=False, role=role)
            return {"ok": False, "error": "Decryption failed"}

        if raw:
            self.log.decrypt(username, user_id=session["user_id"],
                             file_id=vfs_path, role=role)
            return {
                "ok": True,
                "data_b64": base64.b64encode(plaintext).decode(),
                "filename": meta["original_name"],
            }

        ext = Path(meta["original_name"]).suffix.lower()
        binary_formats = {".pdf", ".xlsx", ".xls", ".docx", ".odt", ".ods", ".odp", ".pptx"}
        out_ext = ".xlsx" if ext == ".xls" else ext

        with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as tmp:
            tmp.write(plaintext)
            tmp_path = tmp.name

        tmp_out_path = None
        try:
            if ext in binary_formats:
                with tempfile.NamedTemporaryFile(suffix=out_ext, delete=False) as tmp_out:
                    tmp_out_path = tmp_out.name
                mask_file(tmp_path, role=role, output_path=tmp_out_path,
                          rules_config=self.masking_rules)
                with open(tmp_out_path, "rb") as f:
                    masked_bytes = f.read()
            else:
                masked_str = mask_file(tmp_path, role=role, rules_config=self.masking_rules)
                masked_bytes = masked_str.encode("utf-8")
        except Exception:
            self.log.mask(username, user_id=session["user_id"],
                          file_id=vfs_path, success=False, role=role)
            return {"ok": False, "error": "Masking failed"}
        finally:
            os.unlink(tmp_path)
            if tmp_out_path and os.path.exists(tmp_out_path):
                os.unlink(tmp_out_path)

        self.log.mask(username, user_id=session["user_id"], file_id=vfs_path, role=role)
        return {
            "ok": True,
            "masked_b64": base64.b64encode(masked_bytes).decode(),
            "role": role,
            "filename": meta["original_name"],
        }

    # ------------------------------------------------------------------
    # Deliveries
    # ------------------------------------------------------------------

    _DELIVERY_ELIGIBLE_ROLES = {"Analyst", "Contributor", "Viewer"}

    def _handle_send_to_user(self, req: dict, session: dict) -> dict:
        sender = session["username"]
        role   = session["role"]
        if not check_permission(sender, "manage_users", self.db_path):
            self.log.permission_denied(sender, "send_to_user", role=role)
            return {"ok": False, "error": "Permission denied"}

        recipient = req.get("recipient", "").strip()
        path      = req.get("path", "")
        cwd       = req.get("cwd", "/")
        send_unmasked = bool(req.get("unmasked", False)) and role == "Admin"

        if not recipient or not path:
            return {"ok": False, "error": "recipient and path required"}
        if recipient == sender:
            return {"ok": False, "error": "Cannot send to yourself"}

        target = get_user(recipient, self.db_path)
        if target is None:
            return {"ok": False, "error": f"User '{recipient}' not found"}
        if target["role"] not in self._DELIVERY_ELIGIBLE_ROLES:
            return {"ok": False, "error": f"Deliveries not supported for role '{target['role']}'"}

        node = resolve_path(path, cwd, self.db_path)
        if node is None:
            return {"ok": False, "error": "File not found"}
        if node["is_dir"]:
            return {"ok": False, "error": "Cannot send a directory, only files"}

        create_delivery(sender, recipient, path, node["id"], self.db_path,
                        unmasked=send_unmasked)

        now = time.time()
        recipient_active = any(
            r["username"] == recipient and r["expires"] > now
            for r in self._sessions.values()
        )

        self.log.delivery_sent(sender, recipient, path,
                               user_id=session["user_id"], role=role)
        return {"ok": True, "recipient_active": recipient_active}

    def _collect_pending_deliveries(self, session: dict) -> list[dict]:
        """
        Fetch and process all pending deliveries for the session user.
        Returns a list of delivery dicts ready to embed in the response.
        Marks each delivery as delivered/skipped/failed in the DB.
        Never raises — errors are caught per-delivery.
        """
        username = session["username"]
        user_id  = session["user_id"]
        role     = session["role"]

        pending = get_pending_deliveries(username, self.db_path)
        if not pending:
            return []

        results = []
        for d in pending:
            vfs_path = d["vfs_path"]
            inode_id = d["inode_id"]
            try:
                node = get_inode(inode_id, self.db_path) if inode_id else None
                if node is None:
                    update_delivery_status(d["id"], "skipped", "file deleted", self.db_path)
                    self.log.delivery_skipped(username, vfs_path,
                                              user_id=user_id, role=role)
                    continue

                fm = get_file_meta(inode_id, self.db_path)
                if fm is None:
                    update_delivery_status(d["id"], "failed", "no file metadata", self.db_path)
                    self.log.delivery_failed(username, vfs_path, "no file metadata",
                                             user_id=user_id, role=role)
                    continue

                enc_path = self.data_enc / fm["blob_name"]
                plaintext = decrypt_file_with_km(str(enc_path), self.km,
                                                 key_id=fm["blob_name"])

                original_name = fm.get("original_name") or node["name"]
                ext = Path(original_name).suffix.lower()
                binary_formats = {".pdf", ".xlsx", ".xls", ".docx",
                                   ".odt", ".ods", ".odp", ".pptx"}
                out_ext = ".xlsx" if ext == ".xls" else ext

                delivery_unmasked = bool(d.get("unmasked", 0))
                tmp_path = tmp_out_path = None
                try:
                    if delivery_unmasked:
                        payload = plaintext
                    else:
                        with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as tmp:
                            tmp.write(plaintext)
                            tmp_path = tmp.name

                        if ext in binary_formats:
                            with tempfile.NamedTemporaryFile(suffix=out_ext, delete=False) as tmp_out:
                                tmp_out_path = tmp_out.name
                            mask_file(tmp_path, role=role, output_path=tmp_out_path,
                                      rules_config=self.masking_rules)
                            with open(tmp_out_path, "rb") as f:
                                payload = f.read()
                        else:
                            masked_str = mask_file(tmp_path, role=role,
                                                   rules_config=self.masking_rules)
                            payload = masked_str.encode("utf-8")
                except Exception:
                    payload = plaintext
                finally:
                    if tmp_path and os.path.exists(tmp_path):
                        os.unlink(tmp_path)
                    if tmp_out_path and os.path.exists(tmp_out_path):
                        os.unlink(tmp_out_path)

                update_delivery_status(d["id"], "delivered", db_path=self.db_path)
                self.log.delivery_received(username, vfs_path, d["sender"],
                                           user_id=user_id, role=role)

                delivery_filename = ("UNMASKED_" + original_name) if delivery_unmasked else original_name
                results.append({
                    "delivery_id": d["id"],
                    "vfs_path":    vfs_path,
                    "filename":    delivery_filename,
                    "sender":      d["sender"],
                    "sent_at":     d["sent_at"],
                    "data_b64":    base64.b64encode(payload).decode(),
                })
            except Exception as e:
                update_delivery_status(d["id"], "failed", str(e), self.db_path)
                self.log.delivery_failed(username, vfs_path, str(e),
                                         user_id=user_id, role=role)
        return results

    # ------------------------------------------------------------------
    # Request dispatcher
    # ------------------------------------------------------------------

    UNAUTHED_CMDS = {"login", "ping"}

    def _dispatch(self, req: dict, client_ip: str = "unknown") -> dict:
        cmd = req.get("cmd", "")
        token = req.get("session", "")
        session = self._get_session(token) if token else None

        if cmd not in self.UNAUTHED_CMDS:
            if session is None:
                return {"ok": False, "error": "Not authenticated"}

        handlers = {
            "ping":            self._handle_ping,
            "logout":          self._handle_logout,
            "encrypt":         self._handle_encrypt,
            "decrypt":         self._handle_decrypt,
            "mask":            self._handle_mask,
            "add_user":        self._handle_add_user,
            "remove_user":     self._handle_remove_user,
            "assign_role":     self._handle_assign_role,
            "list_users":      self._handle_list_users,
            "list_roles":      self._handle_list_roles,
            "audit_log":       self._handle_audit_log,
            "rotate_audit":    self._handle_rotate_audit,
            "whoami":          self._handle_whoami,
            "get_my_permissions": self._handle_get_my_permissions,
            "change_password": self._handle_change_password,
            "reset_password":  self._handle_reset_password,
            "delete_account":  self._handle_delete_account,
            "vfs_ls":          self._vfs_ls,
            "vfs_mkdir":       self._vfs_mkdir,
            "vfs_stat":        self._vfs_stat,
            "vfs_tree":        self._vfs_tree,
            "vfs_rm":          self._vfs_rm,
            "vfs_mv":          self._vfs_mv,
            "vfs_send":        self._vfs_send,
            "vfs_fetch":       self._vfs_fetch,
            "vfs_chmod":       self._vfs_chmod,
            "send_to_user":    self._handle_send_to_user,
            "active_users":    self._handle_active_users,
        }

        if cmd == "login":
            try:
                return self._handle_login(req, session, client_ip=client_ip)
            except Exception:
                logger.exception("Unhandled error in login")
                return {"ok": False, "error": "Internal server error"}

        handler = handlers.get(cmd)
        if handler is None:
            return {"ok": False, "error": "Unknown command"}

        # VFS rate limiting: token bucket per session — allows bursts but blocks floods.
        _VFS_CMDS = {"vfs_ls", "vfs_mkdir", "vfs_stat", "vfs_tree",
                     "vfs_rm", "vfs_mv", "vfs_send", "vfs_fetch", "vfs_chmod"}
        if cmd in _VFS_CMDS and session:
            if not _vfs_rate_check(req.get("session", "")):
                return {"ok": False, "error": "Too many requests. Slow down."}

        try:
            resp = handler(req, session)
            user = session["username"] if session else "unauthenticated"
            outcome = "ok" if resp.get("ok") else f"err:{resp.get('error', '?')}"
            logger.info("cmd=%s user=%s ip=%s result=%s", cmd, user, client_ip, outcome)

            # Piggyback pending deliveries on any successful authenticated response.
            # Skipped for login (no session yet) and send_to_user (creates deliveries
            # for others, not the sender).
            if session and resp.get("ok") and cmd not in ("login", "send_to_user"):
                try:
                    deliveries = self._collect_pending_deliveries(session)
                    if deliveries:
                        resp["deliveries"] = deliveries
                except Exception:
                    logger.exception("Error collecting pending deliveries for %s", user)

            # Inject audit tamper alert for Admin and Auditor sessions if active.
            # Alert persists until rotate_audit is called (which calls monitor.reset()).
            if session and session.get("role") in ("Admin", "Auditor"):
                with _audit_tamper_lock:
                    if _audit_tamper_alert:
                        resp["audit_tamper_alert"] = dict(_audit_tamper_alert)

            return resp
        except Exception:
            logger.exception("Unhandled error in command '%s'", cmd)
            return {"ok": False, "error": "Internal server error"}

    # ------------------------------------------------------------------
    # Connection handler (runs in its own thread)
    # ------------------------------------------------------------------

    def _handle_conn(self, conn: ssl.SSLSocket, addr: tuple) -> None:
        logger.info("Connection from %s:%s", addr[0], addr[1])
        buf = b""
        try:
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                buf += chunk
                if len(buf) > MAX_PAYLOAD_BYTES + 65536:
                    logger.warning("Connection from %s exceeded max buffer, dropping", addr[0])
                    break
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        req = json.loads(line)
                    except json.JSONDecodeError:
                        resp = {"ok": False, "error": "Invalid JSON"}
                        conn.sendall(json.dumps(resp).encode() + b"\n")
                        continue

                    resp = self._dispatch(req, client_ip=addr[0])
                    conn.sendall(json.dumps(resp).encode() + b"\n")
        except (ssl.SSLError, OSError) as e:
            logger.debug("Connection closed: %s", e)
        finally:
            try:
                conn.close()
            except Exception:
                pass
        logger.info("Connection closed: %s:%s", addr[0], addr[1])

    # ------------------------------------------------------------------
    # Server lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=self.cert, keyfile=self.key)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.set_ciphers(
            # TLS 1.3 suites (preferred when client supports it)
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
        ctx.options |= ssl.OP_NO_COMPRESSION
        ctx.options |= ssl.OP_SINGLE_DH_USE
        ctx.options |= ssl.OP_SINGLE_ECDH_USE

        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        raw.bind((self.host, self.port))
        raw.listen(16)
        self._server_sock = ctx.wrap_socket(raw, server_side=True)
        self._running = True

        logger.info("EFS-TDM server listening on %s:%s (TLS)", self.host, self.port)

        while self._running:
            try:
                conn, addr = self._server_sock.accept()
            except OSError:
                break
            t = threading.Thread(target=self._handle_conn, args=(conn, addr),
                                 daemon=True)
            t.start()

    def stop(self) -> None:
        self._running = False
        self.km.stop()
        if self._server_sock:
            try:
                self._server_sock.close()
            except Exception:
                pass
        logger.info("Server stopped")


def _load_or_create_master_key(path: str | Path = MK_PATH) -> bytes:
    """
    Load the 32-byte Master Key from *path*, or generate and persist one on
    first run.  An ``EFS_MASTER_KEY`` environment variable (hex-encoded)
    takes precedence over the file -- useful for containerised deployments
    where secrets are injected at runtime.

    The key file is created with mode 0600 so only the owner can read it.
    """
    env_hex = os.environ.get("EFS_MASTER_KEY")
    if env_hex:
        mk = bytes.fromhex(env_hex)
        if len(mk) != MK_SIZE_BYTES:
            raise ValueError(
                f"EFS_MASTER_KEY must be exactly {MK_SIZE_BYTES} bytes "
                f"({MK_SIZE_BYTES * 2} hex chars), got {len(mk)}"
            )
        logger.info("Master Key loaded from EFS_MASTER_KEY environment variable")
        return mk

    path = Path(path)
    if path.exists():
        mk = path.read_bytes()
        if len(mk) != MK_SIZE_BYTES:
            raise ValueError(
                f"Master key file {path} is corrupt "
                f"(expected {MK_SIZE_BYTES} bytes, got {len(mk)})"
            )
        logger.info("Master Key loaded from %s", path)
        return mk

    mk = os.urandom(MK_SIZE_BYTES)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(mk)
    os.chmod(path, 0o600)
    logger.info("New Master Key generated and saved to %s", path)
    return mk


def main() -> None:
    parser = argparse.ArgumentParser(description="EFS-TDM Server")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--cert", default=str(CERT_PATH))
    parser.add_argument("--key",  default=str(KEY_PATH))
    parser.add_argument("--db",   default=None, help="Override DB path")
    args = parser.parse_args()

    master_key = _load_or_create_master_key()

    server = EFSServer(
        host=args.host,
        port=args.port,
        cert=args.cert,
        key=args.key,
        db_path=args.db,
        master_key=master_key,
    )

    # Start the Flask web login UI in a background thread
    try:
        from web.app import run as flask_run
        web_thread = threading.Thread(
            target=flask_run,
            kwargs={"backend_port": args.port},
            daemon=True,
        )
        web_thread.start()
        logger.info(
            "Web login UI started on https://%s:%s",
            os.environ.get("EFS_WEB_HOST", "0.0.0.0"),
            os.environ.get("EFS_WEB_PORT", "5000"),
        )
    except ImportError:
        logger.warning("Flask not installed — web login UI unavailable")

    def _shutdown(sig, frame):
        logger.info("Shutting down...")
        server.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    server.start()


if __name__ == "__main__":
    main()
