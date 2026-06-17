"""
EFS-TDM CLI Client.

Communicates with the EFS-TDM server over a TLS-wrapped local socket.
Session token is stored in ~/.efs_session for persistence across commands.

Usage:
  python -m client.client web-login
  python -m client.client login <username>
# python -m client.client encrypt <filepath>
# python -m client.client decrypt <filename> [--out <path>]
# python -m client.client mask <filename> [--role <role>]
  python -m client.client add-user <username> --role <role>
  python -m client.client assign-role <username> --role <role>
  python -m client.client remove-user <username>
  python -m client.client list-users
  python -m client.client list-roles
  python -m client.client audit-log [--user <u>] [--action <a>] [--limit <n>] [--from <ts>] [--to <ts>] [--archive <file>] [--out <path>] [--verify]
  python -m client.client rotate-audit
  python -m client.client logout
  python -m client.client shell
"""
import argparse
import base64
import getpass
import hashlib
import json
import os
import re
import shlex
import socket
import ssl
import sys
import threading
import time
import webbrowser
from pathlib import Path

try:
    import readline  # noqa: F401 — side-effect: up-arrow history, tab completion (Unix)
except ImportError:
    try:
        import pyreadline3 as readline  # type: ignore[no-redef]  # Windows fallback
    except ImportError:
        readline = None  # type: ignore[assignment]

# Force cryptography C extensions to load eagerly so Nuitka bundles them correctly
import cryptography
import cryptography.hazmat.bindings._rust

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

def read_file_b64(filepath: str | Path) -> tuple[str, str]:
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {filepath}")
    if path.is_dir():
        raise IsADirectoryError(f"Path is a directory: {filepath}")
    data = path.read_bytes()
    return path.name, base64.b64encode(data).decode("utf-8")


def decode_b64_to_bytes(data_b64: str) -> bytes:
    return base64.b64decode(data_b64)


def write_output(content: str | bytes, output_path: str | Path | None = None) -> None:
    if output_path is None:
        if isinstance(content, bytes):
            sys.stdout.buffer.write(content)
            sys.stdout.buffer.flush()
        else:
            sys.stdout.write(content)
            sys.stdout.flush()
        return
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")

DEFAULT_HOST  = "127.0.0.1"
DEFAULT_PORT  = 9999

# Resolve paths for the deployment layout:
#   portable_client/
#     EFS              <- launcher
#     certs/           <- TOFU cert (user-facing, next to launcher)
#     downloads/       <- fetched files (user-facing, next to launcher)
#     libs/
#       EFS_bin        <- this binary
#       config.json    <- binary config (next to binary)
#
# When running as libs/EFS_bin, _BIN_DIR = libs/, _DEPLOY_ROOT = portable_client/
# When running from source, both point to PROJECT_ROOT.
_proc_exe = Path("/proc/self/exe")
if _proc_exe.exists() and "python" not in _proc_exe.resolve().name.lower():
    # Linux compiled binary: use /proc/self/exe for reliable path
    _BIN_DIR = _proc_exe.resolve().parent
    _DEPLOY_ROOT = _BIN_DIR.parent if _BIN_DIR.name == "libs" else _BIN_DIR
elif sys.argv and Path(sys.argv[0]).suffix.lower() == ".exe" and "python" not in Path(sys.argv[0]).name.lower():
    # Windows compiled binary: sys.argv[0] correctly points to EFS_bin.exe
    # (sys.executable points to a python shim in Nuitka standalone, not the binary)
    _BIN_DIR = Path(sys.argv[0]).resolve().parent
    _DEPLOY_ROOT = _BIN_DIR.parent if _BIN_DIR.name.lower() == "libs" else _BIN_DIR
else:
    _BIN_DIR = PROJECT_ROOT
    _DEPLOY_ROOT = PROJECT_ROOT

# In the deployed binary, cert lives at <deploy_root>/certs/cert.pem (TOFU-fetched).
# When running from source, fall back to server_pkg/certs/cert.pem (one level up from client_pkg/).
_deploy_cert  = _DEPLOY_ROOT / "certs" / "cert.pem"
_source_cert  = PROJECT_ROOT.parent / "server_pkg" / "certs" / "cert.pem"
CERT_PATH     = _deploy_cert if _deploy_cert.exists() else _source_cert
SESSION_FILE  = Path.home() / ".efs_session"
CONFIG_FILE   = _BIN_DIR / "config.json"


# ---------------------------------------------------------------------------
# Config file (host / port / cert persistence)
# ---------------------------------------------------------------------------

def _load_config() -> dict:
    """Load config.json next to the binary. Returns defaults if missing or invalid."""
    defaults = {"host": DEFAULT_HOST, "port": DEFAULT_PORT, "cert": None,
                "downloads_dir": None}
    if CONFIG_FILE.exists():
        try:
            data = json.loads(CONFIG_FILE.read_text())
            defaults.update({k: v for k, v in data.items() if k in defaults})
        except Exception:
            pass
    return defaults


def _save_config(host: str, port: int, cert: str | None) -> None:
    CONFIG_FILE.write_text(json.dumps({"host": host, "port": port, "cert": cert}, indent=4))
    _ok(f"Config saved to {CONFIG_FILE}")

# ANSI color helpers — disabled automatically when the terminal does not support VT sequences
def _ansi_supported() -> bool:
    if not sys.stdout.isatty():
        return False
    if sys.platform == "win32":
        try:
            import ctypes
            import ctypes.wintypes
            ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
            mode = ctypes.wintypes.DWORD()
            if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                return False
            if mode.value & ENABLE_VIRTUAL_TERMINAL_PROCESSING:
                return True
            return bool(kernel32.SetConsoleMode(handle, mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING))
        except Exception:
            return False
    return True

_ANSI = _ansi_supported()
_GREEN  = "\033[92m" if _ANSI else ""
_RED    = "\033[91m" if _ANSI else ""
_CYAN   = "\033[96m" if _ANSI else ""
_BOLD   = "\033[1m"  if _ANSI else ""
_RESET  = "\033[0m"  if _ANSI else ""

def _ok(msg: str)   -> None: print(f"{_GREEN}[ok]{_RESET} {msg}")
def _err(msg: str)  -> None: print(f"{_RED}[error]{_RESET} {msg}", file=sys.stderr)
def _info(msg: str) -> None: print(f"{_CYAN}[info]{_RESET} {msg}")


def _print_tamper_alert(alert: dict) -> None:
    """Print a prominent security alert when audit chain tampering is detected."""
    ts  = alert.get("detected_at", "unknown")
    sep = f"{_RED}{_BOLD}{'!' * 70}{_RESET}"
    print("", file=sys.stderr)
    print(sep, file=sys.stderr)
    print(f"{_RED}{_BOLD}  *** SECURITY ALERT: AUDIT LOG TAMPERING DETECTED ***{_RESET}", file=sys.stderr)
    print(f"{_RED}{_BOLD}  Detected at : {ts}{_RESET}", file=sys.stderr)
    print(f"{_RED}{_BOLD}  The audit chain HMAC verification has failed.{_RESET}", file=sys.stderr)
    print(f"{_RED}{_BOLD}  Audit records may have been altered or deleted.{_RESET}", file=sys.stderr)
    print(f"{_RED}{_BOLD}  Contact your security team immediately.{_RESET}", file=sys.stderr)
    print(sep, file=sys.stderr)
    print("", file=sys.stderr)


def _fmt_size(size_bytes: int) -> str:
    """Format a byte count as a human-readable string using IEC binary prefixes."""
    for unit, threshold in (("TiB", 1 << 40), ("GiB", 1 << 30), ("MiB", 1 << 20), ("KiB", 1 << 10)):
        if size_bytes >= threshold:
            value = size_bytes / threshold
            return f"{value:.1f} {unit} ({size_bytes:,} B)"
    return f"{size_bytes:,} B"


_ROLE_PERMISSIONS: dict[str, frozenset] = {
    "Admin":       frozenset(["list", "read", "write", "delete_own", "delete_any",
                               "mask", "export_raw", "manage_permissions", "manage_users",
                               "view_audit", "encrypt", "decrypt"]),
    "Analyst":     frozenset(["list", "read", "mask"]),
    "Contributor": frozenset(["list", "read", "write", "delete_own"]),
    "Viewer":      frozenset(["list", "read"]),
    "Auditor":     frozenset(["view_audit"]),
    "Guest":       frozenset(["list"]),
}


def _guard(role: str | None, *required_perms: str) -> int | None:
    """Return 1 (with error) if role lacks all required permissions, else None."""
    if role is None:
        return None  # No cached role — server will enforce
    perms = _ROLE_PERMISSIONS.get(role, frozenset())
    if any(p in perms for p in required_perms):
        return None
    _err(f"Permission denied: your role ({role}) cannot run this command")
    return 1


# Password policy: cached from server via get_my_permissions, falls back to defaults.
_POLICY_FILE = _BIN_DIR / ".password_policy.json"

_DEFAULT_PASSWORD_POLICY = {
    "min_length": 8,
    "require_uppercase": True,
    "require_lowercase": True,
    "require_digit": True,
    "require_special": True,
}


def _save_password_policy(policy: dict) -> None:
    try:
        _POLICY_FILE.write_text(json.dumps(policy))
    except Exception:
        pass


def _load_password_policy() -> dict:
    if _POLICY_FILE.exists():
        try:
            return json.loads(_POLICY_FILE.read_text())
        except Exception:
            pass
    return dict(_DEFAULT_PASSWORD_POLICY)


def _check_password_policy(pw: str) -> str | None:
    """Return an error string if password fails policy, else None."""
    p = _load_password_policy()
    if len(pw) < p.get("min_length", 8):
        return f"Password must be at least {p['min_length']} characters"
    if p.get("require_uppercase", True) and not re.search(r"[A-Z]", pw):
        return "Password must contain at least one uppercase letter"
    if p.get("require_lowercase", True) and not re.search(r"[a-z]", pw):
        return "Password must contain at least one lowercase letter"
    if p.get("require_digit", True) and not re.search(r"\d", pw):
        return "Password must contain at least one number"
    if p.get("require_special", True) and not re.search(r"[^A-Za-z0-9]", pw):
        return "Password must contain at least one special character"
    return None


# ---------------------------------------------------------------------------
# First-run setup
# ---------------------------------------------------------------------------

def _ensure_dirs() -> None:
    """Create required local directories if they do not exist."""
    (CERT_PATH.parent).mkdir(parents=True, exist_ok=True)
    (_DEPLOY_ROOT / "downloads").mkdir(parents=True, exist_ok=True)


def _ensure_cert(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> None:
    """
    If cert.pem is missing, fetch it from the server using an unverified
    TLS connection (trust-on-first-use) and save it for all future connections.
    """
    if CERT_PATH.exists():
        return

    _info("cert.pem not found — fetching from server (trust-on-first-use)...")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        raw = socket.create_connection((host, port), timeout=10)
        conn = ctx.wrap_socket(raw, server_hostname=host)
        der = conn.getpeercert(binary_form=True)
        conn.close()
    except Exception as e:
        _err(f"Could not fetch cert from server: {e}")
        _err("Place cert.pem in the certs/ folder next to the binary and retry.")
        sys.exit(1)

    pem = (
        b"-----BEGIN CERTIFICATE-----\n"
        + b"\n".join(
            base64.encodebytes(der).strip().split(b"\n")
        )
        + b"\n-----END CERTIFICATE-----\n"
    )
    CERT_PATH.write_bytes(pem)
    _ok(f"Certificate saved to {CERT_PATH}")


# ---------------------------------------------------------------------------
# Transport
# ---------------------------------------------------------------------------

class SessionExpired(Exception):
    """Raised when the server reports the session is no longer valid."""


class ServerConn:
    """Single TLS connection to the server. Used as a context manager."""

    def __init__(self, host: str, port: int, cert: str | Path):
        self.host = host
        self.port = port
        self.cert = str(cert)
        self._sock: ssl.SSLSocket | None = None
        self.last_deliveries: list = []

    def __enter__(self) -> "ServerConn":
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(self.cert)
        ctx.check_hostname = False   # self-signed: no hostname in cert CN
        ctx.verify_mode = ssl.CERT_REQUIRED
        raw = socket.create_connection((self.host, self.port), timeout=10)
        self._sock = ctx.wrap_socket(raw, server_hostname=self.host)
        return self

    def __exit__(self, *_) -> None:
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass

    def send(self, req: dict) -> dict:
        """Send a request dict and return the response dict."""
        payload = json.dumps(req).encode() + b"\n"
        self._sock.sendall(payload)
        # Read until newline
        buf = b""
        while b"\n" not in buf:
            chunk = self._sock.recv(65536)
            if not chunk:
                raise ConnectionError("Server closed connection")
            buf += chunk
        line = buf.split(b"\n")[0]
        resp = json.loads(line)
        if not resp.get("ok") and resp.get("error") == "Not authenticated":
            raise SessionExpired()
        alert = resp.pop("audit_tamper_alert", None)
        if alert:
            _print_tamper_alert(alert)
        self.last_deliveries = resp.pop("deliveries", [])
        _process_deliveries(self.last_deliveries)
        return resp


# ---------------------------------------------------------------------------
# Session token persistence
# ---------------------------------------------------------------------------

def _load_session() -> str | None:
    if not SESSION_FILE.exists():
        return None
    raw = SESSION_FILE.read_text().strip()
    if not raw:
        return None
    try:
        return json.loads(raw).get("token") or None
    except (json.JSONDecodeError, AttributeError):
        return raw  # backward-compatible: plain token string


def _load_session_role() -> str | None:
    if not SESSION_FILE.exists():
        return None
    raw = SESSION_FILE.read_text().strip()
    if not raw:
        return None
    try:
        return json.loads(raw).get("role") or None
    except (json.JSONDecodeError, AttributeError):
        return None


def _save_session(token: str, role: str | None = None) -> None:
    data = json.dumps({"token": token, "role": role}) if role else token
    SESSION_FILE.write_text(data)
    SESSION_FILE.chmod(0o600)


def _clear_session() -> None:
    if SESSION_FILE.exists():
        SESSION_FILE.unlink()


# ---------------------------------------------------------------------------
# Command implementations
# ---------------------------------------------------------------------------

def cmd_login(args, conn: ServerConn) -> int:
    password = getpass.getpass(f"Password for {args.username}: ")
    resp = conn.send({"cmd": "login", "username": args.username, "password": password})
    if not resp.get("ok"):
        _err(resp.get("error", "Login failed"))
        return 1
    _save_session(resp["session"], resp["role"])
    _ok(f"Logged in as {args.username} (role: {resp['role']})")
    return 0


def cmd_logout(args, conn: ServerConn) -> int:
    token = _load_session()
    if not token:
        _err("No active session")
        return 1
    resp = conn.send({"cmd": "logout", "session": token})
    _clear_session()
    if resp.get("ok"):
        _ok("Logged out, session revoked")
    else:
        _info("Session cleared locally (server said: " + resp.get("error", "?") + ")")
    return 0


# def cmd_encrypt(args, conn: ServerConn) -> int:
#     token = _load_session()
#     if not token:
#         _err("Not logged in")
#         return 1
#     if (rc := _guard(_load_session_role(), "encrypt")) is not None:
#         return rc
#     try:
#         filename, data_b64 = read_file_b64(args.filepath)
#     except (FileNotFoundError, IsADirectoryError) as e:
#         _err(str(e))
#         return 1
#     _info(f"Uploading {filename} for encryption...")
#     resp = conn.send({
#         "cmd": "encrypt", "session": token,
#         "filename": filename, "data_b64": data_b64,
#     })
#     if not resp.get("ok"):
#         _err(resp.get("error", "Encryption failed"))
#         return 1
#     _ok(f"Encrypted and stored as: {resp['stored_as']}")
#     return 0


def _resolve_downloads_dir() -> Path:
    cfg = _load_config()
    override = cfg.get("downloads_dir")
    if override:
        return Path(override)
    return _DEPLOY_ROOT / "downloads"

DOWNLOADS_DIR = _resolve_downloads_dir()


def _process_deliveries(deliveries: list) -> None:
    """
    Save any piggybacked file deliveries from the server response to DOWNLOADS_DIR.
    Called transparently from ServerConn.send() — never raises.
    """
    if not deliveries:
        return
    try:
        DOWNLOADS_DIR.mkdir(parents=True, exist_ok=True)
        for d in deliveries:
            filename = d.get("filename", "file")
            stem     = Path(filename).stem
            suffix   = Path(filename).suffix
            dest     = DOWNLOADS_DIR / f"admin_delivery_{filename}"
            counter  = 1
            while dest.exists():
                dest = DOWNLOADS_DIR / f"admin_delivery_{stem}_{counter}{suffix}"
                counter += 1
            dest.write_bytes(base64.b64decode(d["data_b64"]))
            _info(f"[delivery] {d['vfs_path']} (from {d['sender']}) -> {dest.name}")
    except Exception as e:
        _err(f"[delivery] Failed to save delivery: {e}")


# def cmd_decrypt(args, conn: ServerConn) -> int:
#     token = _load_session()
#     if not token:
#         _err("Not logged in")
#         return 1
#     if (rc := _guard(_load_session_role(), "decrypt")) is not None:
#         return rc
#     resp = conn.send({"cmd": "decrypt", "session": token, "filename": args.filename})
#     if not resp.get("ok"):
#         _err(resp.get("error", "Decryption failed"))
#         return 1
#     plaintext = decode_b64_to_bytes(resp["data_b64"])
#     out = args.out
#     if out is None:
#         bare = Path(args.filename).name
#         if bare.endswith(".enc"):
#             bare = bare[:-4]
#         DOWNLOADS_DIR.mkdir(parents=True, exist_ok=True)
#         out = str(DOWNLOADS_DIR / bare)
#     write_output(plaintext, out)
#     _ok(f"Decrypted content written to {out}")
#     return 0


# def cmd_mask(args, conn: ServerConn) -> int:
#     token = _load_session()
#     if not token:
#         _err("Not logged in")
#         return 1
#     if (rc := _guard(_load_session_role(), "mask")) is not None:
#         return rc
#     req = {"cmd": "mask", "session": token, "filename": args.filename}
#     if args.role:
#         req["role"] = args.role
#     resp = conn.send(req)
#     if not resp.get("ok"):
#         _err(resp.get("error", "Mask failed"))
#         return 1
#     print(f"\n{_BOLD}Masked content (role: {resp['role']}){_RESET}")
#     print("=" * 60)
#     print(resp["masked"])
#     print("=" * 60)
#     return 0


def cmd_add_user(args, conn: ServerConn) -> int:
    token = _load_session()
    if not token:
        _err("Not logged in")
        return 1
    if (rc := _guard(_load_session_role(), "manage_users")) is not None:
        return rc
    # Check username not already taken before prompting
    users_resp = conn.send({"cmd": "list_users", "session": token})
    if not users_resp.get("ok"):
        _err(users_resp.get("error", "Failed to list users"))
        return 1
    existing = {u["username"] for u in users_resp.get("users", [])}
    if args.username in existing:
        _err(f"User '{args.username}' already exists")
        return 1
    print(f"Add user '{args.username}' with role '{args.role}'?")
    if input("Confirm [Y/n]: ").strip() != "Y":
        print("Aborted.")
        return 0
    password = getpass.getpass(f"Set password for {args.username}: ")
    policy_err = _check_password_policy(password)
    if policy_err:
        _err(policy_err)
        return 1
    resp = conn.send({
        "cmd": "add_user", "session": token,
        "username": args.username, "password": password, "role": args.role,
    })
    if not resp.get("ok"):
        _err(resp.get("error", "Failed"))
        return 1
    _ok(f"User created")
    print(f"  Username : {resp['username']}")
    print(f"  Role     : {resp['role']}")
    print(f"  Password : {password}")
    return 0


def cmd_remove_user(args, conn: ServerConn) -> int:
    token = _load_session()
    if not token:
        _err("Not logged in")
        return 1
    if (rc := _guard(_load_session_role(), "manage_users")) is not None:
        return rc
    # Resolve caller before any prompting
    whoami_resp = conn.send({"cmd": "whoami", "session": token})
    if not whoami_resp.get("ok"):
        _err("Could not verify session.")
        return 1
    if args.username == whoami_resp.get("username"):
        _err("Cannot delete your own account.")
        return 1
    # Check target exists and role before prompting
    users_resp = conn.send({"cmd": "list_users", "session": token})
    if not users_resp.get("ok"):
        _err(users_resp.get("error", "Failed to list users"))
        return 1
    known = {u["username"]: u for u in users_resp.get("users", [])}
    if args.username not in known:
        _err(f"User '{args.username}' not found")
        return 1
    target_role = known[args.username]["role"]
    if target_role == "Admin" and whoami_resp.get("role") != "Admin":
        _err("Only the root admin can delete admin accounts.")
        return 1
    print(f"Remove user '{args.username}'?")
    if input("Confirm [Y/n]: ").strip() != "Y":
        print("Aborted.")
        return 0
    resp = conn.send({"cmd": "remove_user", "session": token, "username": args.username})
    if not resp.get("ok"):
        _err(resp.get("error", "Failed"))
        return 1
    _ok(f"User removed")
    print(f"  Username : {args.username}")
    return 0


def cmd_assign_role(args, conn: ServerConn) -> int:
    token = _load_session()
    if not token:
        _err("Not logged in")
        return 1
    if (rc := _guard(_load_session_role(), "manage_users")) is not None:
        return rc
    # Check user exists before prompting
    users_resp = conn.send({"cmd": "list_users", "session": token})
    if not users_resp.get("ok"):
        _err(users_resp.get("error", "Failed to list users"))
        return 1
    known = {u["username"] for u in users_resp.get("users", [])}
    if args.username not in known:
        _err(f"User '{args.username}' not found")
        return 1
    print(f"Assign role '{args.role}' to '{args.username}'?")
    if input("Confirm [Y/n]: ").strip() != "Y":
        print("Aborted.")
        return 0
    resp = conn.send({
        "cmd": "assign_role", "session": token,
        "username": args.username, "role": args.role,
    })
    if not resp.get("ok"):
        _err(resp.get("error", "Failed"))
        return 1
    _ok(f"Role assigned")
    print(f"  Username : {args.username}")
    print(f"  Role     : {args.role}")
    return 0


def cmd_list_users(args, conn: ServerConn) -> int:
    token = _load_session()
    if not token:
        _err("Not logged in")
        return 1
    if (rc := _guard(_load_session_role(), "manage_users")) is not None:
        return rc
    resp = conn.send({"cmd": "list_users", "session": token})
    if not resp.get("ok"):
        _err(resp.get("error", "Failed"))
        return 1
    users = resp["users"]
    print(f"\n{_BOLD}{'Username':<20} {'Role':<12} {'Created'}{_RESET}")
    print("-" * 55)
    for u in users:
        print(f"{u['username']:<20} {u['role']:<12} {u['created_at']}")
    print(f"\n{len(users)} user(s)")
    return 0


def cmd_list_roles(args, conn: ServerConn) -> int:
    token = _load_session()
    if not token:
        _err("Not logged in")
        return 1
    if (rc := _guard(_load_session_role(), "manage_users")) is not None:
        return rc
    resp = conn.send({"cmd": "list_roles", "session": token})
    if not resp.get("ok"):
        _err(resp.get("error", "Failed"))
        return 1
    for r in resp["roles"]:
        print(f"\n{_BOLD}{r['name'].upper()}{_RESET}")
        print(f"  Permissions: {', '.join(r['permissions'])}")
    return 0


def cmd_whoami(args, conn: ServerConn) -> int:
    token = _load_session()
    if not token:
        _err("Not logged in")
        return 1
    resp = conn.send({"cmd": "whoami", "session": token})
    if not resp.get("ok"):
        _err(resp.get("error", "Failed"))
        return 1
    _ok(f"Logged in as {resp['username']} (role: {resp['role']})")
    return 0


def cmd_change_password(args, conn: ServerConn) -> int:
    token = _load_session()
    if not token:
        _err("Not logged in")
        return 1
    old_pw = getpass.getpass("Current password: ")
    # Verify current password before prompting for new one
    verify_resp = conn.send({
        "cmd": "change_password", "session": token,
        "old_password": old_pw, "verify_only": True,
    })
    if not verify_resp.get("ok"):
        _err(verify_resp.get("error", "Failed"))
        return 1
    new_pw = getpass.getpass("New password: ")
    policy_err = _check_password_policy(new_pw)
    if policy_err:
        _err(policy_err)
        return 1
    new_pw2 = getpass.getpass("Confirm new password: ")
    if new_pw != new_pw2:
        _err("Passwords do not match")
        return 1
    resp = conn.send({
        "cmd": "change_password", "session": token,
        "old_password": old_pw, "new_password": new_pw,
    })
    if not resp.get("ok"):
        _err(resp.get("error", "Failed"))
        return 1
    _ok("Password changed. You have been logged out.")
    _clear_session()
    return 2  # sentinel: shell loop should exit immediately


def cmd_reset_password(args, conn: ServerConn) -> int:
    token = _load_session()
    if not token:
        _err("Not logged in")
        return 1
    if (rc := _guard(_load_session_role(), "manage_users")) is not None:
        return rc
    # Check if resetting own password before prompting
    whoami_resp = conn.send({"cmd": "whoami", "session": token})
    if not whoami_resp.get("ok"):
        _err("Could not verify session.")
        return 1
    if whoami_resp.get("username") == args.username:
        _err("Use 'change-password' to change your own password.")
        return 1
    # Check target user exists before prompting
    users_resp = conn.send({"cmd": "list_users", "session": token})
    if not users_resp.get("ok"):
        _err(users_resp.get("error", "Failed to list users"))
        return 1
    known = {u["username"] for u in users_resp.get("users", [])}
    if args.username not in known:
        _err(f"User '{args.username}' not found")
        return 1
    new_pw = getpass.getpass(f"New password for {args.username}: ")
    policy_err = _check_password_policy(new_pw)
    if policy_err:
        _err(policy_err)
        return 1
    new_pw2 = getpass.getpass("Confirm new password: ")
    if new_pw != new_pw2:
        _err("Passwords do not match")
        return 1
    resp = conn.send({
        "cmd": "reset_password", "session": token,
        "username": args.username, "new_password": new_pw,
    })
    if not resp.get("ok"):
        _err(resp.get("error", "Failed"))
        return 1
    _ok(f"Password for '{args.username}' reset successfully")
    return 0



def _human_size(n: int) -> str:
    for unit in ("B", "K", "M", "G", "T"):
        if n < 1024:
            return f"{n}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}P"


def cmd_vfs_ls(args, conn: ServerConn, cwd: str = "/") -> int:
    token = _load_session()
    if not token:
        _err("Not logged in")
        return 1
    path = getattr(args, "path", None) or cwd
    resp = conn.send({"cmd": "vfs_ls", "session": token, "path": path, "cwd": cwd})
    if not resp.get("ok"):
        _err(resp.get("error", "Failed"))
        return 1

    dir_itself = getattr(args, "dir_itself", False)
    if dir_itself:
        sr = conn.send({"cmd": "vfs_stat", "session": token, "path": path, "cwd": cwd})
        if not sr.get("ok"):
            _err(sr.get("error", "Failed"))
            return 1
        s = sr["stat"]
        show_inode = getattr(args, "inode", False)
        human      = getattr(args, "human", False)
        inode_pfx  = f"{s['id']}  " if show_inode else ""
        typ = "d" if s.get("is_dir") else "-"
        sz = s.get("size_bytes")
        size_str = (_human_size(sz) if human else str(sz)) if sz is not None else "-"
        label = s["name"] + ("/" if s.get("is_dir") else "")
        print(f"{inode_pfx}{typ}rw-  {s['owner']:<15}  {size_str:>10}  {s['created_at']}  {label}")
        return 0

    show_all   = getattr(args, "all", False) or getattr(args, "unsorted", False)
    unsorted   = getattr(args, "unsorted", False)
    long_fmt   = getattr(args, "long", False) or getattr(args, "no_owner", False)
    no_owner   = getattr(args, "no_owner", False)
    human      = getattr(args, "human", False)
    show_inode = getattr(args, "inode", False)
    reverse    = getattr(args, "reverse", False)
    show_blocks= getattr(args, "blocks", False)
    by_time    = getattr(args, "by_time", False)
    by_upload  = getattr(args, "by_upload", False)
    across     = getattr(args, "across", False)
    one_line   = getattr(args, "one_per_line", False)

    entries = resp["entries"]

    if not show_all:
        entries = [e for e in entries if not e["name"].startswith(".")]

    if not unsorted:
        if by_time:
            entries.sort(key=lambda e: e["created_at"], reverse=True)
        elif by_upload:
            entries.sort(key=lambda e: e.get("uploaded_at") or e["created_at"], reverse=True)
        else:
            entries.sort(key=lambda e: e["name"].lower())

    if reverse:
        entries.reverse()

    if not entries:
        return 0

    def _size(e):
        b = e.get("size_bytes")
        if b is None:
            return "-"
        if human:
            return _human_size(b)
        return str(b)

    def _blocks(e):
        b = e.get("size_bytes")
        return str((b + 511) // 512) if b is not None else "-"

    def _label(e):
        return e["name"] + ("/" if e["type"] == "dir" else "")

    def _time(e):
        if by_upload:
            return e.get("uploaded_at") or e["created_at"]
        return e["created_at"]

    if long_fmt:
        for e in entries:
            parts = []
            if show_inode:
                parts.append(f"{e['id']:<6}")
            if show_blocks:
                parts.append(f"{_blocks(e):>6}")
            typ = "d" if e["type"] == "dir" else "-"
            parts.append(f"{typ}rw-")
            if not no_owner:
                parts.append(f"{e['owner']:<15}")
            parts.append(f"{_size(e):>10}")
            parts.append(f"{_time(e)}")
            parts.append(_label(e))
            print("  ".join(parts))
    elif across:
        labels = []
        for e in entries:
            prefix = f"{e['id']} " if show_inode else ""
            prefix += f"{_blocks(e)} " if show_blocks else ""
            labels.append(prefix + _label(e))
        col_w = max(len(l) for l in labels) + 2
        cols = max(1, 80 // col_w)
        for i, label in enumerate(labels):
            end = "\n" if (i + 1) % cols == 0 or i == len(labels) - 1 else ""
            print(f"{label:<{col_w}}", end=end)
    elif one_line:
        for e in entries:
            parts = []
            if show_inode:
                parts.append(str(e["id"]))
            if show_blocks:
                parts.append(_blocks(e))
            parts.append(_label(e))
            print("  ".join(parts))
    else:
        labels = []
        for e in entries:
            prefix = f"{e['id']} " if show_inode else ""
            prefix += f"{_blocks(e)} " if show_blocks else ""
            labels.append(prefix + _label(e))
        col_w = max(len(l) for l in labels) + 2
        cols = max(1, 80 // col_w)
        rows = (len(labels) + cols - 1) // cols
        for r in range(rows):
            line = ""
            for c in range(cols):
                idx = r + c * rows
                if idx < len(labels):
                    line += f"{labels[idx]:<{col_w}}"
            print(line)

    print(f"\n{len(entries)} item(s)")
    return 0


def cmd_vfs_mkdir(args, conn: ServerConn, cwd: str = "/") -> int:
    token = _load_session()
    if not token:
        _err("Not logged in")
        return 1
    if (rc := _guard(_load_session_role(), "write")) is not None:
        return rc
    resp = conn.send({"cmd": "vfs_mkdir", "session": token, "path": args.path, "cwd": cwd})
    if not resp.get("ok"):
        _err(resp.get("error", "Failed"))
        return 1
    _ok(f"Directory created: {args.path}")
    return 0


def cmd_vfs_stat(args, conn: ServerConn, cwd: str = "/") -> int:
    token = _load_session()
    if not token:
        _err("Not logged in")
        return 1
    resp = conn.send({"cmd": "vfs_stat", "session": token, "path": args.path, "cwd": cwd})
    if not resp.get("ok"):
        _err(resp.get("error", "Failed"))
        return 1
    s = resp["stat"]
    for k, v in s.items():
        if v is None:
            continue
        if k == "acl":
            if isinstance(v, dict) and v:
                print(f"  {'acl':<20}")
                for role, perms in sorted(v.items()):
                    for perm, action in sorted(perms.items()):
                        tag = "" if action == "grant" else " (deny)"
                        print(f"    {role:<18} {perm}{tag}")
            continue
        if k == "size_bytes" and isinstance(v, int):
            v = _fmt_size(v)
        print(f"  {k:<20} {v}")
    return 0


def cmd_vfs_tree(args, conn: ServerConn, cwd: str = "/") -> int:
    token = _load_session()
    if not token:
        _err("Not logged in")
        return 1
    path = getattr(args, "path", None) or cwd
    resp = conn.send({"cmd": "vfs_tree", "session": token, "path": path, "cwd": cwd})
    if not resp.get("ok"):
        _err(resp.get("error", "Failed"))
        return 1
    for line in resp["tree"]:
        print(line)
    return 0


def cmd_vfs_rm(args, conn: ServerConn, cwd: str = "/") -> int:
    token = _load_session()
    if not token:
        _err("Not logged in")
        return 1
    if (rc := _guard(_load_session_role(), "delete_own", "delete_any")) is not None:
        return rc
    resp = conn.send({"cmd": "vfs_rm", "session": token, "path": args.path, "cwd": cwd})
    if not resp.get("ok"):
        _err(resp.get("error", "Failed"))
        return 1
    _ok("Removed")
    return 0


def cmd_vfs_mv(args, conn: ServerConn, cwd: str = "/") -> int:
    token = _load_session()
    if not token:
        _err("Not logged in")
        return 1
    if (rc := _guard(_load_session_role(), "write")) is not None:
        return rc
    resp = conn.send({"cmd": "vfs_mv", "session": token,
                      "src": args.src, "dst": args.dst, "cwd": cwd})
    if not resp.get("ok"):
        _err(resp.get("error", "Failed"))
        return 1
    _ok("Moved")
    return 0


def cmd_vfs_chmod(args, conn: ServerConn, cwd: str = "/") -> int:
    token = _load_session()
    if not token:
        _err("Not logged in")
        return 1
    if (rc := _guard(_load_session_role(), "manage_permissions")) is not None:
        return rc
    resp = conn.send({
        "cmd": "vfs_chmod", "session": token,
        "path": args.path, "cwd": cwd,
        "role": args.role, "perm": args.perm,
        "action": getattr(args, "action", "grant"),
    })
    if not resp.get("ok"):
        _err(resp.get("error", "Failed"))
        return 1
    _ok(f"ACL updated: {args.action} '{args.perm}' on '{args.path}' for role '{args.role}'")
    return 0


def _vfs_send_file(conn, token: str, local_path: Path, vfs_path: str, cwd: str,
                   overwrite: bool = False) -> str | None:
    """Upload a single file. Returns error string on failure, None on success."""
    try:
        data_b64 = base64.b64encode(local_path.read_bytes()).decode()
    except Exception as e:
        return str(e)
    resp = conn.send({"cmd": "vfs_send", "session": token,
                      "path": vfs_path, "cwd": cwd, "data_b64": data_b64,
                      "overwrite": overwrite})
    if not resp.get("ok"):
        return resp.get("error", "Upload failed")
    return None


def cmd_vfs_send(args, conn: ServerConn, cwd: str = "/") -> int:
    token = _load_session()
    if not token:
        _err("Not logged in")
        return 1
    if (rc := _guard(_load_session_role(), "write")) is not None:
        return rc
    src = Path(args.src)
    if not src.exists():
        _err(f"Not found: {src}")
        _err('  Tip: if the path contains spaces, wrap it in quotes: send "My Folder"')
        return 1

    # ------------------------------------------------------------------ #
    # Directory upload                                                     #
    # ------------------------------------------------------------------ #
    if src.is_dir():
        if input(f"  Upload directory '{src}' and all its contents? [Y/n]: ").strip() != "Y":
            _info("Canceled.")
            return 0
        dst = getattr(args, "dst", None) or (cwd.rstrip("/") + "/" + src.name)
        vfs_root = dst.rstrip("/")
        import os as _os
        files: list[tuple[Path, str]] = []
        for dirpath, dirnames, filenames in _os.walk(src):
            rel = Path(dirpath).relative_to(src)
            rel_str = str(rel)
            vfs_dir = vfs_root if rel_str == "." else vfs_root + "/" + rel_str.replace("\\", "/")
            conn.send({"cmd": "vfs_mkdir", "session": token, "path": vfs_dir, "cwd": "/"})
            for filename in sorted(filenames):
                files.append((Path(dirpath) / filename, vfs_dir + "/" + filename))
        if not files:
            _err(f"Directory is empty: {src}")
            return 1

        # ---- attempt upload; server rejects existing files --------------
        _info(f"Uploading {len(files)} file(s) to {vfs_root} ...")
        ok_count, fail_count = 0, 0
        conflict_files: list[tuple[Path, str, dict]] = []  # (local, vfs, remote_stat)
        for local_file, vfs_path in files:
            try:
                data_b64 = base64.b64encode(local_file.read_bytes()).decode()
            except Exception as e:
                _err(f"  {vfs_path}: {e}")
                fail_count += 1
                continue
            resp = conn.send({"cmd": "vfs_send", "session": token,
                              "path": vfs_path, "cwd": "/", "data_b64": data_b64,
                              "overwrite": False})
            if resp.get("ok"):
                ok_count += 1
            elif resp.get("error") == "already_exists":
                conflict_files.append((local_file, vfs_path, resp.get("stat", {})))
            else:
                _err(f"  {vfs_path}: {resp.get('error', 'Upload failed')}")
                fail_count += 1

        # ---- resolve conflicts -------------------------------------------
        to_overwrite: list[tuple[Path, str]] = []
        if conflict_files:
            print(f"\n  {len(conflict_files)} file(s) already exist in VFS:\n")
            print(f"  {'VFS path':<45} {'Remote':>10}  {'Local':>10}  Uploaded")
            print(f"  {'-'*45} {'-'*10}  {'-'*10}  {'-'*16}")
            for local_file, vfs_path, remote in conflict_files:
                r_size = remote.get("size_bytes", "?")
                r_date = remote.get("uploaded_at", "unknown")
                l_size = local_file.stat().st_size
                print(f"  {vfs_path:<45} {r_size!s:>10}  {l_size!s:>10}  {r_date}")
            print()
            print("  [O] Overwrite all    [S] Skip all    [C] Choose for each    [A] Abort")
            choice = input("  Choice: ").strip()
            if choice == "A":
                _info("Aborted.")
                return 1
            elif choice == "O":
                to_overwrite = [(lf, vp) for lf, vp, _ in conflict_files]
            elif choice == "C":
                for local_file, vfs_path, remote in conflict_files:
                    r_size = remote.get("size_bytes", "?")
                    r_date = remote.get("uploaded_at", "unknown")
                    l_size = local_file.stat().st_size
                    l_mtime = time.strftime("%Y-%m-%d %H:%M:%S",
                                            time.localtime(_os.path.getmtime(local_file)))
                    print(f"\n  {vfs_path}")
                    print(f"  Remote : {r_size} bytes, uploaded {r_date}")
                    print(f"  Local  : {l_size} bytes, modified {l_mtime}")
                    ans = input("  Overwrite? [Y/n] ").strip()
                    if ans == "Y":
                        to_overwrite.append((local_file, vfs_path))
                    else:
                        _info("  Skipped.")
            elif choice != "S":
                _info("Canceled.")
                return 0
            # choice == "S": to_overwrite stays empty

            if to_overwrite:
                _info(f"Overwriting {len(to_overwrite)} file(s) ...")
                for local_file, vfs_path in to_overwrite:
                    err = _vfs_send_file(conn, token, local_file, vfs_path, "/",
                                         overwrite=True)
                    if err:
                        _err(f"  {vfs_path}: {err}")
                        fail_count += 1
                    else:
                        ok_count += 1

        skipped = len(conflict_files) - len(to_overwrite)
        if fail_count == 0:
            _ok(f"Done. {ok_count} uploaded, {skipped} skipped.")
        else:
            _info(f"Done. {ok_count} uploaded, {fail_count} failed, {skipped} skipped.")
        return 0 if fail_count == 0 else 1

    # ------------------------------------------------------------------ #
    # Single file upload                                                   #
    # ------------------------------------------------------------------ #
    dst = getattr(args, "dst", None) or ("/" + src.name if cwd == "/" else cwd + "/" + src.name)
    if dst == "/" or dst.endswith("/"):
        dst = dst.rstrip("/") + "/" + src.name

    try:
        local_bytes = src.read_bytes()
    except Exception as e:
        _err(str(e))
        return 1

    data_b64 = base64.b64encode(local_bytes).decode()

    _info(f"Uploading {src.name} to {dst} ...")
    resp = conn.send({"cmd": "vfs_send", "session": token,
                      "path": dst, "cwd": cwd, "data_b64": data_b64,
                      "overwrite": False})

    if resp.get("error") == "already_exists":
        remote = resp.get("stat", {})
        local_hash = hashlib.sha256(local_bytes).hexdigest()
        if remote.get("content_hash") and local_hash == remote["content_hash"]:
            _info(f"{dst} is identical to the stored version "
                  f"(uploaded {remote.get('uploaded_at', 'unknown')}). Skipping.")
            return 0
        remote_size = remote.get("size_bytes", "?")
        remote_uploaded = remote.get("uploaded_at", "unknown")
        local_size = len(local_bytes)
        local_mtime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(os.path.getmtime(src)))
        print(f"  File already exists at {dst}")
        print(f"  Remote : {remote_size} bytes, uploaded {remote_uploaded}")
        print(f"  Local  : {local_size} bytes, modified {local_mtime}")
        answer = input("  Overwrite? [Y/n] ").strip()
        if answer != "Y":
            _info("Upload canceled.")
            return 0
        resp = conn.send({"cmd": "vfs_send", "session": token,
                          "path": dst, "cwd": cwd, "data_b64": data_b64,
                          "overwrite": True})

    if not resp.get("ok"):
        _err(resp.get("error", "Upload failed"))
        return 1
    _ok(f"Stored at {resp['path']} (inode {resp['inode_id']})")
    return 0


def cmd_vfs_fetch(args, conn: ServerConn, cwd: str = "/") -> int:
    token = _load_session()
    if not token:
        _err("Not logged in")
        return 1
    role = _load_session_role()
    if (rc := _guard(role, "read")) is not None:
        return rc
    raw = getattr(args, "raw", False)
    if raw and role != "Admin":
        _err("Permission denied: --raw requires admin role")
        return 1
    resp = conn.send({"cmd": "vfs_fetch", "session": token,
                      "path": args.path, "cwd": cwd, "raw": raw})
    if not resp.get("ok"):
        _err(resp.get("error", "Fetch failed"))
        return 1

    vfs_filename = resp.get("filename") or Path(args.path).name

    def _resolve_out(out: str, filename: str) -> str:
        """If out is a directory (or ends with /), append the filename."""
        p = Path(out)
        if out.endswith("/") or p.is_dir():
            return str(p / filename)
        return out

    if raw:
        plaintext = base64.b64decode(resp["data_b64"])
        out = getattr(args, "out", None)
        if out is None:
            DOWNLOADS_DIR.mkdir(parents=True, exist_ok=True)
            out = str(DOWNLOADS_DIR / vfs_filename)
        else:
            out = _resolve_out(out, vfs_filename)
        Path(out).parent.mkdir(parents=True, exist_ok=True)
        Path(out).write_bytes(plaintext)
        _ok(f"Saved to {out}")
    else:
        masked_bytes = base64.b64decode(resp["masked_b64"])
        out = getattr(args, "out", None)
        if out is None:
            DOWNLOADS_DIR.mkdir(parents=True, exist_ok=True)
            out = str(DOWNLOADS_DIR / vfs_filename)
        else:
            out = _resolve_out(out, vfs_filename)
        Path(out).parent.mkdir(parents=True, exist_ok=True)
        Path(out).write_bytes(masked_bytes)
        _ok(f"Saved to {out}")
    return 0


def cmd_audit_log(args, conn: ServerConn) -> int:
    token = _load_session()
    if not token:
        _err("Not logged in")
        return 1
    if (rc := _guard(_load_session_role(), "view_audit")) is not None:
        return rc
    if getattr(args, "verify", False):
        resp = conn.send({"cmd": "audit_log", "session": token, "verify": True})
        if not resp.get("ok"):
            _err(resp.get("error", "Failed"))
            return 1
        if resp.get("chain_valid"):
            _ok("Audit log chain intact — no tampering detected")
        else:
            _err("Audit log chain BROKEN — log may have been tampered with")
            return 1
        return 0

    req = {"cmd": "audit_log", "session": token}
    if args.user:
        req["username"] = args.user
    if args.action:
        req["action"] = args.action
    if args.limit is not None:
        req["limit"] = args.limit
    if getattr(args, "from_ts", None):
        req["from_ts"] = args.from_ts
    if getattr(args, "to_ts", None):
        req["to_ts"] = args.to_ts
    if getattr(args, "archive", None):
        req["archive"] = args.archive
    resp = conn.send(req)
    if not resp.get("ok"):
        _err(resp.get("error", "Failed"))
        return 1
    entries = resp["entries"]
    source = f" [{args.archive}]" if getattr(args, "archive", None) else ""
    header = f"{'Timestamp (UTC)':<20} {'User':<15} {'Role':<14} {'Action':<20} {'Outcome':<12} {'File'}\n" + "-" * 110
    rows = [
        f"{e['timestamp']:<20} "
        f"{(e['username'] or ''):<15} "
        f"{(e.get('role') or ''):<14} "
        f"{e['action']:<20} "
        f"{e['outcome']:<12} "
        f"{(e['file_id'] or '')}"
        for e in entries
    ]
    summary = f"\n{len(entries)} entry/entries{source}"

    out = getattr(args, "out", None)
    if out:
        Path(out).parent.mkdir(parents=True, exist_ok=True)
        Path(out).write_text("\n".join([header] + rows + [summary]) + "\n", encoding="utf-8")
        _ok(f"Audit log written to {out}")
    else:
        print(f"\n{_BOLD}{header}{_RESET}")
        for row in rows:
            print(row)
        print(summary)
    return 0


def cmd_send_to(args, conn: ServerConn, cwd: str = "/") -> int:
    token = _load_session()
    if not token:
        _err("Not logged in")
        return 1
    if (rc := _guard(_load_session_role(), "manage_users")) is not None:
        return rc
    req = {"cmd": "send_to_user", "session": token,
           "recipient": args.username, "path": args.path, "cwd": cwd}
    if getattr(args, "unmasked", False):
        req["unmasked"] = True
    resp = conn.send(req)
    if not resp.get("ok"):
        _err(resp.get("error", "Delivery failed"))
        return 1
    if resp.get("recipient_active"):
        _ok(f"File queued for {args.username} — they are online and will receive it on their next action.")
    else:
        _ok(f"File queued for {args.username} — they will receive it on next login.")
    return 0


def cmd_active_users(args, conn: ServerConn) -> int:
    token = _load_session()
    if not token:
        _err("Not logged in")
        return 1
    if (rc := _guard(_load_session_role(), "manage_users")) is not None:
        return rc
    resp = conn.send({"cmd": "active_users", "session": token})
    if not resp.get("ok"):
        _err(resp.get("error", "Failed to retrieve active users"))
        return 1
    users = resp.get("users", [])
    if not users:
        _info("No active sessions.")
        return 0
    col_u = max(len("Username"), max(len(u["username"]) for u in users))
    col_r = max(len("Role"),     max(len(u["role"])     for u in users))
    header = f"{'Username':<{col_u}}  {'Role':<{col_r}}  Expires In"
    print(header)
    print("-" * len(header))
    for u in sorted(users, key=lambda x: x["username"]):
        mins, secs = divmod(u["expires_in"], 60)
        expires_str = f"{mins}m {secs:02d}s"
        print(f"{u['username']:<{col_u}}  {u['role']:<{col_r}}  {expires_str}")
    return 0


def cmd_rotate_audit(args, conn: ServerConn) -> int:
    token = _load_session()
    if not token:
        _err("Not logged in")
        return 1
    if (rc := _guard(_load_session_role(), "manage_users")) is not None:
        return rc
    answer = input("Rotate audit log? This will archive the current log and start a new one. [Y/n] ").strip()
    if answer != "Y":
        _info("Cancelled.")
        return 0
    resp = conn.send({"cmd": "rotate_audit", "session": token})
    if not resp.get("ok"):
        _err(resp.get("error", "Rotation failed"))
        return 1
    _ok(f"Audit log rotated. Archive: {resp['archive']}")
    return 0


# ---------------------------------------------------------------------------
# Web login launcher
# ---------------------------------------------------------------------------

def _make_default_args():
    """Return a minimal namespace with host/port/cert from config for shell hand-off."""
    import types
    _cfg = _load_config()
    ns = types.SimpleNamespace()
    ns.host = _cfg["host"]
    ns.port = _cfg["port"]
    ns.cert = _cfg["cert"] or str(CERT_PATH)
    return ns

def _https_get(host: str, port: int, path: str, headers: dict | None = None) -> tuple[int, str]:
    """
    Minimal raw HTTPS GET using only ssl + socket — no urllib, no http.cookiejar,
    no datetime. Returns (status_code, body_text).
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(str(CERT_PATH))
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED

    hdrs = {"Host": host, "Connection": "close"}
    if headers:
        hdrs.update(headers)
    header_str = "".join(f"{k}: {v}\r\n" for k, v in hdrs.items())
    request = f"GET {path} HTTP/1.1\r\n{header_str}\r\n"

    raw = socket.create_connection((host, port), timeout=10)
    conn = ctx.wrap_socket(raw, server_hostname=host)
    try:
        conn.sendall(request.encode())
        buf = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            buf += chunk
    finally:
        conn.close()

    # Split headers and body
    if b"\r\n\r\n" in buf:
        head, body = buf.split(b"\r\n\r\n", 1)
    else:
        head, body = buf, b""

    status_line = head.split(b"\r\n")[0].decode()
    status_code = int(status_line.split()[1])

    # Extract Set-Cookie header value if present
    set_cookie = ""
    for line in head.split(b"\r\n")[1:]:
        if line.lower().startswith(b"set-cookie:"):
            set_cookie = line.split(b":", 1)[1].strip().decode()
            break

    return status_code, body.decode(errors="replace"), set_cookie


def web_login() -> int:
    """
    Open the browser to the server's HTTPS web login page and poll for the
    session token. Uses raw ssl+socket — no urllib, no http.cookiejar.

    Returns 0 on success, 1 on timeout or error.
    """
    import secrets as _secrets
    import subprocess, shutil

    # If a valid session already exists, go straight to shell
    if _load_session():
        _ok("Already logged in. Dropping into shell.")
        return cmd_shell(_make_default_args())

    if SESSION_FILE.exists():
        SESSION_FILE.unlink()

    _cfg = _load_config()
    web_host = os.environ.get("EFS_WEB_HOST", _cfg["host"])
    web_port = int(os.environ.get("EFS_WEB_PORT", "5000"))

    poll_key = _secrets.token_urlsafe(32)
    init_url  = f"https://{web_host}:{web_port}/?init={poll_key}"
    login_url = f"https://{web_host}:{web_port}/"

    # Hit /?init=<poll_key> to register the key server-side
    try:
        _https_get(web_host, web_port, f"/?init={poll_key}")
    except Exception:
        _err("Cannot reach the web login server. Make sure server.py is running.")
        return 1

    _info(f"Opening browser at {login_url}")
    _info(f"Or open this URL manually: {init_url}")
    _info("Complete login in the browser, then return to this terminal.")

    _opened = False
    _browser_private_flags = {
        "firefox":          ["--private-window"],
        "chromium":         ["--incognito"],
        "chromium-browser": ["--incognito"],
        "google-chrome":    ["--incognito"],
    }
    for browser in ("firefox", "chromium", "chromium-browser", "google-chrome", "xdg-open"):
        path = shutil.which(browser)
        if path:
            extra = _browser_private_flags.get(browser, [])
            subprocess.Popen(
                [path] + extra + [init_url],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            _opened = True
            break
    if not _opened:
        webbrowser.open(init_url)

    # Poll /poll sending poll_key as a cookie
    deadline = time.time() + 120
    while time.time() < deadline:
        try:
            _, body, _ = _https_get(
                web_host, web_port, "/poll",
                headers={"Cookie": f"efs_poll_key={poll_key}"},
            )
            data = json.loads(body)
            if data.get("ok"):
                token = data["token"]
                _save_session(token)  # role will be written by cmd_shell after whoami
                _ok("Browser login successful. Dropping into shell.")
                return cmd_shell(_make_default_args())
        except Exception:
            pass
        time.sleep(0.5)

    _err("Timed out waiting for browser login (120 s). Session not established.")
    return 1


# ---------------------------------------------------------------------------
# Interactive shell (REPL)
# ---------------------------------------------------------------------------

_SHELL_HELP = """\
File storage commands:
  ls [folder] [-a] [-d] [-f] [-g] [-h] [-i] [-l] [-r] [-s] [-t] [-u] [-x] [-1]
  cd <folder>
  mkdir <folder>
  stat <file or folder>
  tree [folder]
  rm <file or folder>
  mv <source> <destination>
  send <local-file> [<server-path>]
  fetch <server-path> [<local-path>] [--raw]
  chmod <server-path> --role {Admin,Analyst,Contributor,Viewer,Auditor,Guest} --perm {read,write,delete_own,delete_any} [--action {grant,revoke}]

User management:
  add-user <username> --role <role>
  remove-user <username>
  assign-role <username> --role <role>
  reset-password <username>
  list-users
  list-roles
  send-to <username> <server-path> [--unmasked]
  active-users
  audit-log [--user <u>] [--action <a>] [--limit <n>] [--from <ts>] [--to <ts>] [--archive <file>] [--out <path>] [--verify]
  rotate-audit
  whoami
  change-password
  logout
  help
  clear
  exit / quit
"""

_CMD_HELP = {
    "ls": (
        "usage: ls [path] [-a] [-d] [-f] [-g] [-h] [-i] [-l] [-r] [-s] [-t] [-u] [-x] [-1]\n"
        "  -a  show hidden entries (. prefix)\n"
        "  -d  list directory itself, not contents\n"
        "  -f  do not sort (implies -a)\n"
        "  -g  long format, omit owner\n"
        "  -h  human-readable sizes\n"
        "  -i  print inode id\n"
        "  -l  long listing format\n"
        "  -r  reverse sort order\n"
        "  -s  show size in 512-byte blocks\n"
        "  -t  sort by created time\n"
        "  -u  sort by upload time (files), created time (dirs)\n"
        "  -x  list entries across columns\n"
        "  -1  one entry per line"
    ),
    "rm":     "usage: rm <path>",
    "mv":     "usage: mv <src> <dst>",
    "mkdir":  "usage: mkdir <path>",
    "stat":   "usage: stat <path>",
    "tree":   "usage: tree [path]",
    "send":   "usage: send <local-file> [<server-path>]",
    "fetch":  "usage: fetch <server-path> [<local-path>] [--raw]\n"
              "  --raw  download unmasked file (admin only)",
    # "encrypt":"usage: encrypt <filepath>",
    # "decrypt":"usage: decrypt <filename> [--out <path>]",
    # "mask":   "usage: mask <filename> [--role <role>]",
    "add-user":    "usage: add-user <username> --role <role>",
    "remove-user": "usage: remove-user <username>",
    "assign-role": "usage: assign-role <username> --role <role>",
    "reset-password": "usage: reset-password <username>",
    "audit-log": (
        "usage: audit-log [--user <u>] [--action <a>] [--limit <n>]\n"
        "                 [--from 'YYYY-MM-DD HH:MM:SS'] [--to 'YYYY-MM-DD HH:MM:SS']\n"
        "                 [--archive <filename>] [--out <path>] [--verify]"
    ),
    "send-to":      "usage: send-to <username> <server-path> [--unmasked]\n"
                    "  --unmasked  send raw file without masking (admin only)",
    "active-users": "usage: active-users  (admin only — list all currently logged-in users)",
    "rotate-audit": "usage: rotate-audit  (admin only — archives current log and starts a new one)",
    "chmod": "usage: chmod <path> --role {Admin,...} --perm {read,write,delete_own,delete_any} [--action {grant,revoke}]",
}

# Single-line summaries used in the role-filtered help listing
_CMD_SUMMARY = {
    "ls":             "ls [folder] [flags]        — list files in a folder (use --help for flags)",
    "cd":             "cd <folder>                — open a folder",
    "mkdir":          "mkdir <folder>             — create a new folder",
    "stat":           "stat <file/folder>         — show details about a file or folder",
    "tree":           "tree [folder]              — show folder contents as a tree",
    "rm":             "rm <file/folder>           — delete a file or folder",
    "mv":             "mv <source> <destination>  — move or rename a file",
    "send":           "send <local-file> [dest]   — upload a file to the server",
    "fetch":          "fetch <server-file> [path] — download a file from the server",
    # "encrypt":        "encrypt <file>             — encrypt a file",
    # "decrypt":        "decrypt <file>             — decrypt a file",
    # "mask":           "mask <file> [--role]       — view a file with sensitive data hidden",
    "add-user":       "add-user <name> --role <r> — create a user",
    "remove-user":    "remove-user <name>         — delete a user",
    "assign-role":    "assign-role <name> --role  — change a user's role",
    "reset-password": "reset-password <name>      — reset a user's password",
    "list-users":     "list-users                 — list all users",
    "list-roles":     "list-roles                 — list roles and permissions",
    "send-to":        "send-to <username> <server-path> [--unmasked]  — deliver a file to a user's downloads",
    "active-users":   "active-users               — list all currently logged-in users",
    "audit-log":      "audit-log [--user <u>] [--action <a>] [--limit <n>] [--from <ts>] [--to <ts>] [--archive <file>] [--out <path>] [--verify]  — view/verify audit log",
    "rotate-audit":   "rotate-audit               — archive and reset audit log",
    "chmod":          "chmod <file> --role --perm — set access permissions on a file",
    "whoami":         "whoami                     — show current user and role",
    "change-password":"change-password            — change your password",
    "logout":         "logout                     — end session",
}

_PERM_COMMANDS = {
    "list":               ["ls", "cd", "tree", "stat"],
    "read":               ["fetch"],
    "write":              ["send", "mkdir", "mv"],
    "delete_own":         ["rm"],
    "delete_any":         ["rm"],
    # "mask":               ["mask"],
    # "encrypt":            ["encrypt"],
    # "decrypt":            ["decrypt"],
    "manage_permissions": ["chmod"],
    "manage_users":       ["add-user", "remove-user", "assign-role", "reset-password",
                           "list-users", "list-roles", "rotate-audit", "send-to",
                           "active-users"],
    "view_audit":         ["audit-log"],
}

_ALWAYS_VISIBLE = ["whoami", "change-password", "logout", "help", "clear", "exit"]

def _resolve_cd(cwd: str, path: str) -> str:
    """Resolve a cd path against cwd client-side (mirrors server _normalise)."""
    if path == "/" or not path:
        return "/"
    if not path.startswith("/"):
        path = cwd.rstrip("/") + "/" + path
    parts = []
    for seg in path.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if parts:
                parts.pop()
        else:
            parts.append(seg)
    return "/" + "/".join(parts)


def _safe_completion(s: str) -> str:
    """Quote a completion path that contains spaces using double-quotes (Windows)."""
    if " " in s:
        # Preserve trailing slash outside the quotes so directory cycling works.
        if s.endswith("/"):
            return '"' + s[:-1] + '"/'
        return '"' + s + '"'
    return s


def _safe_completion_readline(s: str) -> str:
    """Escape spaces with backslash for GNU readline completions (Linux/macOS)."""
    return s.replace(" ", r"\ ")


# Persistent command history for _win_readline (module-level so it survives across calls)
_win_history: list[str] = []


def _win_complete(line: str, conn, token: str, cwd: str, allowed_cmds) -> list[str]:
    """
    Stateless Windows tab completer. Returns all completion candidates for the current
    word in `line`. Callers own the cycling state.

    Rules:
    - Empty line or only whitespace: return all allowed commands (sorted).
    - One token, not ending with space: command completion.
    - Command in LOCAL_FIRST_ARG_CMDS on first arg: local filesystem completion.
    - fetch command: VFS completion for first arg, local filesystem for second arg.
    - send-to: skip completion on first arg (username), VFS for second arg.
    - All other VFS commands: VFS path completion.

    Returns a list of strings; each command match has a trailing space,
    each VFS directory match has a trailing /, paths with spaces are quoted.
    """
    import os as _os

    VFS_CMDS = {"ls", "cd", "rm", "mv", "stat", "tree", "fetch", "chmod", "mkdir"}
    LOCAL_FIRST_ARG_CMDS = {"send"}

    # Parse command from the line using a norm copy (backslashes → /) so shlex handles
    # Windows paths correctly.  We only use this for cmd/trailing_space/on_first_arg
    # detection — NOT for extracting cur_text (see below).
    norm = _win_norm(line)
    try:
        parts = shlex.split(norm) if norm.strip() else []
    except ValueError:
        parts = norm.split()

    trailing_space = norm.endswith(" ")
    cmd = parts[0] if parts else ""

    # ---- command completion ------------------------------------------------
    if not parts or (len(parts) == 1 and not trailing_space):
        all_cmds = sorted((allowed_cmds or set()) | {"help", "clear", "exit", "quit"})
        typed = parts[0] if parts else ""
        matches = [c for c in all_cmds if c.startswith(typed)]
        return [m + " " for m in matches]

    # ---- extract cur_text directly from the raw line -----------------------
    # We cannot use parts[-1] because _win_norm already converted backslashes to
    # forward slashes and shlex stripped quotes — so "Test Now"/N would become
    # "Test Now/N" but we'd lose the quoting context needed for correct insertion.
    # Instead, use _shell_word_start on the raw line to get the word as typed,
    # then unescape it (remove quotes / convert \ -space to space) for matching.
    def _shell_word_start_local(s: str) -> int:
        i = 0
        word_start = 0
        in_quote = False
        quote_char = ""
        while i < len(s):
            ch = s[i]
            if in_quote:
                if ch == quote_char:
                    in_quote = False
            else:
                if ch in ('"', "'"):
                    in_quote = True
                    quote_char = ch
                    word_start = i
                elif ch == " ":
                    word_start = i + 1
            i += 1
        return word_start

    def _unescape(word: str) -> str:
        """Strip surrounding quotes or unescape backslash-space, normalize slashes."""
        w = word
        # Remove surrounding double-quotes (possibly with trailing chars after closing quote)
        if w.startswith('"'):
            end_q = w.find('"', 1)
            if end_q != -1:
                w = w[1:end_q] + w[end_q + 1:]
            else:
                w = w[1:]
        # Convert backslash-space to space, then remaining backslashes to /
        w = w.replace("\\ ", "\x00")
        w = w.replace("\\", "/")
        w = w.replace("\x00", " ")
        return w

    if trailing_space:
        cur_text = ""
    else:
        raw_word = line[_shell_word_start_local(line):]
        cur_text = _unescape(raw_word)

    on_first_arg = len(parts) == 1 or (len(parts) == 2 and not trailing_space)

    # ---- local path helpers ------------------------------------------------
    def _local_matches(text: str) -> list[str]:
        # text is already unescaped (real spaces, forward slashes).
        raw = text.replace("\\", "/")
        dir_part = raw.rsplit("/", 1)[0] if "/" in raw else "."
        base = raw.rsplit("/", 1)[1] if "/" in raw else raw
        # On Windows, "C:" means CWD of that drive; "C:/" means the root.
        list_dir = dir_part if dir_part else "/"
        if list_dir and list_dir[-1] == ":":
            list_dir += "/"
        try:
            entries = _os.listdir(list_dir)
        except Exception:
            return []
        result = []
        for e in entries:
            if e.startswith(base):
                if dir_part in (".", ""):
                    full = e
                else:
                    full = list_dir.rstrip("/") + "/" + e
                if _os.path.isdir(full.replace("/", _os.sep)):
                    full += "/"
                result.append(_safe_completion(full))
        return result

    # ---- VFS path helper ---------------------------------------------------
    def _vfs_matches(text: str, vfs_cwd: str) -> list[str]:
        if conn is None or token is None:
            return []
        # text is already unescaped (real spaces, forward slashes).
        raw = text
        if raw.startswith("/"):
            if "/" in raw[1:]:
                parent = raw.rsplit("/", 1)[0] or "/"
                prefix = raw.rsplit("/", 1)[1]
            else:
                parent = "/"
                prefix = raw[1:]
        elif "/" in raw:
            # Relative path with a slash — e.g. "Test Now/N" after completing a dir.
            rel_parent, prefix = raw.rsplit("/", 1)
            parent = vfs_cwd.rstrip("/") + "/" + rel_parent
        else:
            parent = vfs_cwd
            prefix = raw
        try:
            resp = conn.send({"cmd": "vfs_ls", "session": token,
                              "path": parent, "cwd": vfs_cwd})
            if not resp.get("ok"):
                return []
            names = [e["name"] + ("/" if e["type"] == "dir" else "")
                     for e in resp["entries"]]
        except Exception:
            return []
        result = []
        for name in names:
            if name.startswith(prefix):
                full = ("/" + name) if parent == "/" else (parent.rstrip("/") + "/" + name)
                result.append(_safe_completion(full))
        return result

    # ---- send: local path for first arg, VFS for second arg ---------------
    if cmd in LOCAL_FIRST_ARG_CMDS:
        if on_first_arg:
            return _local_matches(cur_text)
        return _vfs_matches(cur_text, cwd)

    # ---- fetch: VFS for first arg, local for second arg -------------------
    if cmd == "fetch":
        if on_first_arg:
            return _vfs_matches(cur_text, cwd)
        return _local_matches(cur_text)

    # ---- send-to: skip username arg, VFS for path arg ---------------------
    if cmd == "send-to":
        positional = [p for p in parts[1:] if not p.startswith("-")]
        on_username = (len(positional) == 0) or (len(positional) == 1 and not trailing_space)
        if on_username:
            return []
        return _vfs_matches(cur_text, "/")

    # ---- all other VFS commands -------------------------------------------
    if cmd in VFS_CMDS:
        return _vfs_matches(cur_text, cwd)

    return []


def _win_readline(prompt: str, complete_fn) -> str:
    """
    Windows-native line input with Tab completion, history, and cursor editing.
    Uses msvcrt.getwch() — no readline dependency.

    complete_fn(line: str) -> list[str]: returns ALL matches for the current word.
    Cycling state is owned here; complete_fn is called fresh on each new Tab cycle.

    Tab behaviour:
    - Any non-Tab key clears the active completion list (_comp_list = []).
    - Tab with empty _comp_list: call complete_fn, build candidate list.
      * 0 matches: bell (no-op).
      * 1 match: insert immediately.
      * >1 matches: extend buffer to common prefix. If buffer already at common
        prefix, cycle to first candidate immediately; else wait for next Tab.
    - Tab with non-empty _comp_list: cycle to next candidate by index.

    Supported keys: Tab, Up/Down, Left/Right, Home/End, Backspace, Delete, Ctrl+C/D.
    """
    import msvcrt

    buf: list[str] = []
    cursor = 0
    hist_idx = len(_win_history)
    saved_input = ""

    # Tab completion state
    _comp_list: list[str] = []   # [] = no active cycle
    _comp_idx = 0                # next index to use when cycling
    _comp_base = ""              # buffer text before the completed word (the prefix part)
    _comp_stem = ""              # the word being completed (before any Tab was pressed)

    _ansi_re = __import__("re").compile(r"\033\[[^A-Za-z]*[A-Za-z]")
    _prompt_visible_len = len(_ansi_re.sub("", prompt))

    def _redraw() -> None:
        text = "".join(buf)
        clear_width = _prompt_visible_len + len(text) + 10
        sys.stdout.write("\r" + " " * clear_width + "\r" + prompt + text)
        back = len(buf) - cursor
        if back > 0:
            # Use spaces to position cursor without relying on ANSI cursor-move sequences.
            # Write the prompt+text then carriage-return + reprint up to cursor position.
            sys.stdout.write("\r" + prompt + "".join(buf[:cursor]))
        sys.stdout.flush()

    def _clear_comp() -> None:
        nonlocal _comp_list, _comp_idx, _comp_base, _comp_stem
        _comp_list = []
        _comp_idx = 0
        _comp_base = ""
        _comp_stem = ""

    def _shell_word_start(line: str) -> int:
        """
        Return the index in `line` where the current shell word begins.
        Handles quoted tokens so that spaces inside quotes are not treated
        as word boundaries. Examples:
            'send foo'           -> 5  (start of 'foo')
            'send "Test Now"'    -> 5  (start of '"Test Now"')
            'send "Test Now'     -> 5  (unclosed quote, same rule)
        """
        i = 0
        word_start = 0
        in_quote = False
        quote_char = ""
        while i < len(line):
            ch = line[i]
            if in_quote:
                if ch == quote_char:
                    in_quote = False
            else:
                if ch in ('"', "'"):
                    in_quote = True
                    quote_char = ch
                    word_start = i
                elif ch == " ":
                    word_start = i + 1
            i += 1
        return word_start

    sys.stdout.write(prompt)
    sys.stdout.flush()

    while True:
        c = msvcrt.getwch()

        if c in ("\r", "\n"):
            result = "".join(buf)
            sys.stdout.write("\r\n")
            sys.stdout.flush()
            if result.strip():
                _win_history.append(result)
            return result

        elif c == "\t":
            line = "".join(buf)

            if not _comp_list:
                # Fresh cycle: compute all candidates.
                candidates = complete_fn(line) if complete_fn is not None else []
                if not candidates:
                    # No matches — do nothing.
                    pass
                elif len(candidates) == 1:
                    # Unique match — insert immediately.
                    word_start = _shell_word_start(line)
                    buf = list(line[:word_start] + candidates[0])
                    cursor = len(buf)
                    _redraw()
                    _clear_comp()
                else:
                    # Multiple matches.
                    import os as _os
                    # Stems: strip the trailing space (for commands) but keep "/" for dirs.
                    stems = [c.rstrip(" ") for c in candidates]
                    common = _os.path.commonprefix(stems)
                    word_start = _shell_word_start(line)
                    cur_word = line[word_start:]
                    if len(common) > len(cur_word):
                        # Can extend to common prefix — do that first.
                        buf = list(line[:word_start] + common)
                        cursor = len(buf)
                        _redraw()
                        # Store cycle state starting at first candidate.
                        _comp_base = line[:word_start]
                        _comp_stem = cur_word
                        _comp_list = candidates
                        _comp_idx = 0
                    else:
                        # Already at common prefix — start cycling immediately.
                        _comp_base = line[:word_start]
                        _comp_stem = cur_word
                        _comp_list = candidates
                        _comp_idx = 0
                        match = _comp_list[_comp_idx]
                        _comp_idx += 1
                        buf = list(_comp_base + match)
                        cursor = len(buf)
                        _redraw()
            else:
                # Continue cycling.
                match = _comp_list[_comp_idx % len(_comp_list)]
                _comp_idx += 1
                buf = list(_comp_base + match)
                cursor = len(buf)
                _redraw()

        elif c in ("\x00", "\xe0"):
            ext = msvcrt.getwch()
            _clear_comp()
            if ext == "H":      # Up arrow
                if hist_idx == len(_win_history):
                    saved_input = "".join(buf)
                if hist_idx > 0:
                    hist_idx -= 1
                    buf = list(_win_history[hist_idx])
                    cursor = len(buf)
                    _redraw()
            elif ext == "P":    # Down arrow
                if hist_idx < len(_win_history):
                    hist_idx += 1
                    buf = list(saved_input if hist_idx == len(_win_history)
                               else _win_history[hist_idx])
                    cursor = len(buf)
                    _redraw()
            elif ext == "K":    # Left arrow
                if cursor > 0:
                    cursor -= 1
                    _redraw()
            elif ext == "M":    # Right arrow
                if cursor < len(buf):
                    cursor += 1
                    _redraw()
            elif ext == "G":    # Home
                cursor = 0
                _redraw()
            elif ext == "O":    # End
                cursor = len(buf)
                _redraw()
            elif ext == "S":    # Delete
                if cursor < len(buf):
                    buf.pop(cursor)
                    _redraw()

        elif c == "\x08":       # Backspace
            _clear_comp()
            if cursor > 0:
                cursor -= 1
                buf.pop(cursor)
                _redraw()

        elif c == "\x03":       # Ctrl+C
            sys.stdout.write("\r\n")
            sys.stdout.flush()
            raise KeyboardInterrupt

        elif c == "\x04":       # Ctrl+D
            sys.stdout.write("\r\n")
            sys.stdout.flush()
            raise EOFError

        elif ord(c) >= 32:      # Printable character
            _clear_comp()
            buf.insert(cursor, c)
            cursor += 1
            _redraw()


def _make_completer(conn_ref: list, token_ref: list, cwd_ref: list, allowed_cmds_ref: list):
    """
    Returns a readline completer function for Linux/macOS (GNU readline).
    conn_ref, token_ref, cwd_ref, allowed_cmds_ref are single-element lists used as
    mutable references so the completer always sees current shell state.
    Not used on Windows — see _win_complete / _win_readline instead.
    """
    import os as _os

    VFS_CMDS = {"ls", "cd", "rm", "mv", "stat", "tree", "fetch", "chmod", "mkdir"}
    LOCAL_FIRST_ARG_CMDS = {"send"}

    _cache = {}  # path -> [names], cleared at start of each new completion cycle

    def _vfs_children(path: str) -> list:
        if path in _cache:
            return _cache[path]
        conn = conn_ref[0]
        token = token_ref[0]
        cwd = cwd_ref[0]
        if conn is None or token is None:
            return []
        try:
            resp = conn.send({"cmd": "vfs_ls", "session": token, "path": path, "cwd": cwd})
            if resp.get("ok"):
                names = [e["name"] + ("/" if e["type"] == "dir" else "")
                         for e in resp["entries"]]
                _cache[path] = names
                return names
        except Exception:
            pass
        return []

    def completer(text, state):
        if state == 0:
            _cache.clear()
        try:
            line = readline.get_line_buffer() if readline is not None else ""
            parts = shlex.split(line) if line.strip() else []
        except ValueError:
            parts = line.split()

        cmd = parts[0] if parts else ""

        # Command completion (no cmd yet or still typing cmd)
        if not parts or (len(parts) == 1 and not line.endswith(" ")):
            all_cmds = sorted((allowed_cmds_ref[0] or set()) | {"help", "clear", "exit", "quit"})
            cmd_matches = [c for c in all_cmds if c.startswith(text)]
            if not cmd_matches:
                return None
            if text in cmd_matches:
                matches = [text + " "] + [c + " " for c in cmd_matches if c != text]
            else:
                matches = [c + " " for c in cmd_matches]
            if state < len(matches):
                return matches[state]
            return None

        # readline passes `text` = everything after the last delimiter (space).
        # For paths with spaces escaped as "\ ", readline still splits at the space,
        # so `text` may only be the tail (e.g. "Now" when buffer is "fetch /Test\ Now/").
        # We reconstruct the full current word from get_line_buffer() so we can find
        # the correct parent directory, then return only the suffix readline expects.
        raw_text = text.replace(r"\ ", " ")

        # Reconstruct full word from line buffer for correct parent detection.
        # readline with " \t\n" delimiters splits at spaces, so `text` starts after
        # the last unescaped space.  The full word includes the "\ "-joined prefix.
        # Strategy: find the last token in `line` that ends with `text` (unescaped).
        line_unesc = line.replace(r"\ ", "\x00")  # protect escaped spaces temporarily
        last_space = line_unesc.rfind(" ")
        full_word_esc = line_unesc[last_space + 1:] if last_space != -1 else line_unesc
        full_word = full_word_esc.replace("\x00", " ")  # restore real spaces

        on_first_arg = len(parts) == 1 or (len(parts) == 2 and not line.endswith(" "))

        def _local_path_matches(word: str) -> list[str]:
            dir_part = _os.path.dirname(word) or "."
            base = _os.path.basename(word)
            try:
                entries = _os.listdir(dir_part)
                result = []
                for e in entries:
                    if e.startswith(base):
                        full = _os.path.join(dir_part, e) if dir_part != "." else e
                        if _os.path.isdir(full):
                            full += "/"
                        result.append(_safe_completion_readline(full))
                return result
            except Exception:
                return []

        def _vfs_path_matches(word: str, vfs_cwd: str) -> list[str]:
            if word.startswith("/"):
                if "/" in word[1:]:
                    parent = word.rsplit("/", 1)[0] or "/"
                    prefix = word.rsplit("/", 1)[1]
                else:
                    parent = "/"
                    prefix = word[1:]
            else:
                parent = vfs_cwd
                prefix = word
            children = _vfs_children(parent)
            result = []
            for name in children:
                if name.startswith(prefix):
                    full = ("/" + name) if parent == "/" else (parent.rstrip("/") + "/" + name)
                    result.append(_safe_completion_readline(full))
            return result

        def _to_readline_match(full_match: str, text: str) -> str:
            """
            readline replaces `text` with whatever the completer returns.
            `full_match` is the complete escaped path (e.g. /Test\\ Now/Now.txt).
            `text` is what readline passed in (e.g. "N" when buffer is "fetch /Test\\ Now/N").
            We need to return only the portion starting from where `text` begins in
            the basename — i.e. strip the already-present prefix from the buffer.

            The already-present prefix in the buffer is `full_word` minus `text`
            (the part readline already has before `text`). We need to return
            `full_match` with that prefix stripped, so readline inserts only the new part.

            Since readline splits on space, `text` = everything after the last space in
            the buffer. The part of `full_match` that readline must insert = everything
            after the already-present prefix (full_word minus the tail that equals text).

            Concretely: prefix_in_buf = full_word[:-len(text)] if text else full_word
            Then return the escaped version of the suffix starting after that prefix.
            """
            # prefix already present before text (unescaped real path prefix)
            prefix_len = len(full_word) - len(text.replace(r"\ ", " "))
            # full_match is escaped; unescape to find split point then re-escape suffix
            full_unesc = full_match.replace(r"\ ", " ")
            suffix_unesc = full_unesc[prefix_len:]
            return _safe_completion_readline(suffix_unesc)

        # Local path completion for 'send' first arg only.
        if cmd in LOCAL_FIRST_ARG_CMDS and on_first_arg:
            matches = [_to_readline_match(m, text) for m in _local_path_matches(full_word)]
            if state < len(matches):
                return matches[state]
            return None

        # fetch: VFS completion for first arg, local path for second arg.
        if cmd == "fetch":
            on_first_arg_fetch = (len(parts) == 1 and line.endswith(" ")) or \
                                  (len(parts) == 2 and not line.endswith(" "))
            if not on_first_arg_fetch:
                matches = [_to_readline_match(m, text) for m in _local_path_matches(full_word)]
                if state < len(matches):
                    return matches[state]
                return None

        # send-to: no completion on first arg (username), VFS completion on second arg.
        if cmd == "send-to":
            positional = [p for p in parts[1:] if not p.startswith("-")]
            on_username_arg = (len(positional) == 0) or \
                              (len(positional) == 1 and not line.endswith(" "))
            if on_username_arg:
                return None

        # VFS path completion
        if cmd in VFS_CMDS or cmd in LOCAL_FIRST_ARG_CMDS or cmd == "send-to":
            cwd = "/" if cmd == "send-to" else cwd_ref[0]
            matches = [_to_readline_match(m, text) for m in _vfs_path_matches(full_word, cwd)]
            if state < len(matches):
                return matches[state]
        return None

    return completer


def _win_norm(line: str) -> str:
    """
    On Windows, shlex.split treats backslash as an escape character, which eats every
    backslash in Windows paths (e.g. C:\\Users\\test → C:Userstest).
    This function converts backslash path separators to forward slashes so shlex parses
    the line correctly, while preserving '\\ ' (backslash-space) which is the space-escape
    sequence inserted by _win_readline's tab completer.
    Called only in the shell loop before shlex.split; no-op on non-Windows platforms.
    """
    if sys.platform != "win32":
        return line
    # Protect backslash-space (space escape from tab completion)
    placeholder = "\x00"
    safe = line.replace("\\ ", placeholder)
    safe = safe.replace("\\", "/")
    return safe.replace(placeholder, "\\ ")


def cmd_shell(outer_args) -> int:
    """
    Start an interactive REPL that keeps a persistent TLS connection open.
    Each command is dispatched through the same handlers used by the one-shot CLI.
    Typing 'exit', 'quit', or pressing Ctrl+C/Ctrl+D exits and revokes the session.
    """
    token = _load_session()
    if not token:
        _err("Not logged in. Run 'web-login' or 'login' first.")
        return 1

    _cfg = _load_config()
    outer_args.host = _cfg["host"]
    outer_args.port = _cfg["port"]
    outer_args.cert = _cfg["cert"] or str(CERT_PATH)

    shell_parser = _build_shell_parser()
    cwd = "/"

    handlers = {
        # "encrypt":          cmd_encrypt,
        # "decrypt":          cmd_decrypt,
        # "mask":             cmd_mask,
        "add-user":         cmd_add_user,
        "remove-user":      cmd_remove_user,
        "assign-role":      cmd_assign_role,
        "reset-password":   cmd_reset_password,
        "list-users":       cmd_list_users,
        "list-roles":       cmd_list_roles,
        "send-to":          lambda a, c: cmd_send_to(a, c, cwd),
        "active-users":     cmd_active_users,
        "audit-log":        cmd_audit_log,
        "rotate-audit":     cmd_rotate_audit,
        "whoami":           cmd_whoami,
        "change-password":  cmd_change_password,
        "logout":           cmd_logout,
        "ls":               lambda a, c: cmd_vfs_ls(a, c, cwd),
        "mkdir":            lambda a, c: cmd_vfs_mkdir(a, c, cwd),
        "stat":             lambda a, c: cmd_vfs_stat(a, c, cwd),
        "tree":             lambda a, c: cmd_vfs_tree(a, c, cwd),
        "rm":               lambda a, c: cmd_vfs_rm(a, c, cwd),
        "mv":               lambda a, c: cmd_vfs_mv(a, c, cwd),
        "send":             lambda a, c: cmd_vfs_send(a, c, cwd),
        "fetch":            lambda a, c: cmd_vfs_fetch(a, c, cwd),
        "chmod":            lambda a, c: cmd_vfs_chmod(a, c, cwd),
    }

    # Fetch current user's role for permission filtering
    _user_role = None
    _user_perms = set()

    _info("EFS-TDM shell. Type 'help' for commands, 'exit' to quit.")

    try:
        with ServerConn(outer_args.host, outer_args.port, outer_args.cert) as conn:
            whoami_resp = conn.send({"cmd": "whoami", "session": token})
            if whoami_resp.get("ok"):
                _user_role = whoami_resp.get("role", "Guest")
                _save_session(token, _user_role)  # cache role for standalone permission checks
                if _user_role == "Admin":
                    shell_parser._subparsers._group_actions[0].choices["fetch"].usage = (
                        "fetch <server-path> [<local-path>] [--raw]"
                    )
                # Fetch live permissions from server (works for all roles).
                # Falls back to local cache if server doesn't support the command.
                _user_perms = set(_ROLE_PERMISSIONS.get(_user_role, frozenset()))
                perms_resp = conn.send({"cmd": "get_my_permissions", "session": token})
                if perms_resp.get("ok"):
                    _user_perms = set(perms_resp["permissions"])
                    _pw_policy = perms_resp.get("password_policy")
                    if _pw_policy:
                        _save_password_policy(_pw_policy)

            # Compute initial allowed commands for tab completion
            all_known_cmds = set(handlers.keys()) | {"cd"}
            if _user_role is not None and _user_role != "Admin":
                _initial_allowed = set(_ALWAYS_VISIBLE) | {"cd"}
                for perm, cmds in _PERM_COMMANDS.items():
                    if perm in _user_perms:
                        _initial_allowed.update(cmds)
            else:
                _initial_allowed = all_known_cmds

            # Set up tab completion and input function
            _conn_ref = [conn]
            _token_ref = [token]
            _cwd_ref = [cwd]
            _allowed_cmds_ref = [_initial_allowed]

            if sys.platform == "win32":
                # Windows: always use msvcrt-based _win_readline with _win_complete.
                # pyreadline3 strips backslashes from input (breaking Windows paths) and
                # parse_and_bind("tab: complete") is unreliable in Nuitka binaries.
                def _read_line(p: str) -> str:
                    return _win_readline(
                        p,
                        lambda l: _win_complete(
                            l, _conn_ref[0], _token_ref[0], _cwd_ref[0], _allowed_cmds_ref[0]
                        ),
                    )
            else:
                # Linux/macOS: use GNU readline (or plain input if readline unavailable).
                _completer_fn = _make_completer(
                    _conn_ref, _token_ref, _cwd_ref, _allowed_cmds_ref
                )
                if readline is not None:
                    readline.set_completer(_completer_fn)
                    # Exclude backslash from delimiters so "Test\ Now" is not split
                    # at the backslash-space; our completer reads get_line_buffer() directly.
                    readline.set_completer_delims(" \t\n")
                    readline.parse_and_bind("tab: complete")

                def _read_line(p: str) -> str:
                    return input(p)

            while True:
                _cwd_ref[0] = cwd
                prompt = f"{_BOLD}EFS:{cwd}>{_RESET} "
                try:
                    line = _read_line(prompt).strip()
                except (EOFError, KeyboardInterrupt):
                    print()
                    _do_shell_logout(conn)
                    return 0

                if not line:
                    continue

                if _load_session() is None:
                    _err("Session terminated remotely. You have been logged out.")
                    return 1

                if line in ("exit", "quit"):
                    _do_shell_logout(conn)
                    return 0

                if line == "help":
                    if _user_role is None or _user_role == "Admin":
                        print(_SHELL_HELP)
                    else:
                        allowed_cmds = set(_ALWAYS_VISIBLE)
                        for perm, cmds in _PERM_COMMANDS.items():
                            if perm in _user_perms:
                                allowed_cmds.update(cmds)
                        print("Available commands:")
                        for cmd in sorted(allowed_cmds):
                            if cmd in ("help", "clear", "exit", "logout"):
                                continue
                            summary = _CMD_SUMMARY.get(cmd, cmd)
                            print(f"  {summary}")
                        print("  help")
                        print("  clear")
                        print("  exit / quit")
                        print()
                    continue

                if line == "clear":
                    if _ANSI:
                        print("\033[2J\033[H", end="", flush=True)
                    else:
                        os.system("cls" if sys.platform == "win32" else "clear")
                    continue

                try:
                    parts = shlex.split(_win_norm(line))
                except ValueError as e:
                    _err(f"Parse error: {e}")
                    continue

                cmd_name = parts[0] if parts else ""

                # Handle cd specially — it changes client-side cwd
                if cmd_name == "cd":
                    target = parts[1] if len(parts) > 1 else "/"
                    resp = conn.send({
                        "cmd": "vfs_stat", "session": token,
                        "path": target, "cwd": cwd,
                    })
                    if not resp.get("ok"):
                        _err(resp.get("error", "No such directory"))
                    elif not resp["stat"].get("is_dir"):
                        _err("Not a directory")
                    else:
                        cwd = _resolve_cd(cwd, target)
                        _cwd_ref[0] = cwd
                    continue

                if "--help" in parts or "-?" in parts:
                    cmd = parts[0] if parts else ""
                    if cmd in _CMD_HELP:
                        print(_CMD_HELP[cmd])
                    else:
                        print(_SHELL_HELP)
                    continue

                # Build the set of commands this user is allowed to run
                all_known_cmds = set(handlers.keys()) | {"cd"}
                if _user_role is not None and _user_role != "Admin":
                    allowed_cmds = set(_ALWAYS_VISIBLE) | {"cd"}
                    for perm, cmds in _PERM_COMMANDS.items():
                        if perm in _user_perms:
                            allowed_cmds.update(cmds)
                else:
                    allowed_cmds = all_known_cmds

                # Unknown command — don't leak the full list
                if cmd_name and cmd_name not in all_known_cmds:
                    _err(f"Unknown command: '{cmd_name}'. Type 'help' for available commands.")
                    continue

                # Permission check — report as unknown so the command list isn't leaked
                if cmd_name and cmd_name not in allowed_cmds:
                    _err(f"Unknown command: '{cmd_name}'")
                    continue

                try:
                    args, unknown = shell_parser.parse_known_args(parts)
                except (SystemExit, argparse.ArgumentError) as e:
                    if isinstance(e, argparse.ArgumentError):
                        _err(f"Invalid argument: {e}")
                    continue
                if unknown:
                    _err(f"Unrecognized arguments: {' '.join(unknown)}")
                    continue

                if args.command not in handlers:
                    _err(f"Unknown command: {args.command}")
                    continue

                if args.command == "fetch" and getattr(args, "raw", False):
                    if _user_role and _user_role != "Admin":
                        _err("Permission denied: --raw requires admin role")
                        continue

                if args.command == "logout":
                    _do_shell_logout(conn)
                    return 0

                try:
                    rc = handlers[args.command](args, conn)
                    print()
                    if rc == 2:
                        return 0
                except SessionExpired:
                    print()
                    _err("Session terminated remotely. You have been logged out.")
                    _clear_session()
                    return 1
                except (ConnectionError, OSError):
                    print()
                    _err("Lost connection to server. The server may be offline.")
                    _clear_session()
                    return 1

    except ConnectionRefusedError:
        _err(f"Server is not reachable at {outer_args.host}:{outer_args.port} — is it running?")
        _clear_session()
        return 1
    except ssl.SSLError as e:
        _err(f"TLS error: {e}")
        return 1


def _do_shell_logout(conn: ServerConn) -> None:
    """Revoke session and clear the session file on shell exit."""
    token = _load_session()
    if not token:
        return
    try:
        conn.send({"cmd": "logout", "session": token})
    except Exception:
        pass
    _clear_session()
    _ok("Session revoked. Goodbye.")


_ALL_ROLES  = ["Admin", "Analyst", "Contributor", "Viewer", "Auditor", "Guest"]
_ALL_PERMS  = ["read", "write", "delete_own", "delete_any"]
_role_type = lambda s: s.strip().capitalize() if s.strip().lower() in [r.lower() for r in _ALL_ROLES] else s.strip()


def _build_shell_parser() -> argparse.ArgumentParser:
    """Minimal parser for commands typed inside the shell REPL."""
    p = argparse.ArgumentParser(prog="", add_help=False, exit_on_error=False,
                                allow_abbrev=False)
    sub = p.add_subparsers(dest="command")

    sub.add_parser("logout",          add_help=False, allow_abbrev=False)
    sub.add_parser("list-users",      add_help=False, allow_abbrev=False)
    sub.add_parser("list-roles",      add_help=False, allow_abbrev=False)
    sub.add_parser("whoami",          add_help=False, allow_abbrev=False)
    sub.add_parser("change-password", add_help=False, allow_abbrev=False)

    rp = sub.add_parser("reset-password", add_help=False, allow_abbrev=False,
                        usage="reset-password <username>")
    rp.add_argument("username")

    # ep = sub.add_parser("encrypt", add_help=False)
    # ep.add_argument("filepath")

    # dp = sub.add_parser("decrypt", add_help=False)
    # dp.add_argument("filename")
    # dp.add_argument("--out", default=None)

    # mp = sub.add_parser("mask", add_help=False)
    # mp.add_argument("filename")
    # mp.add_argument("--role", default=None, type=_role_type, choices=_ALL_ROLES)

    au = sub.add_parser("add-user", add_help=False, allow_abbrev=False,
                        usage="add-user <username> --role <role>")
    au.add_argument("username")
    au.add_argument("--role", required=True, type=_role_type, choices=_ALL_ROLES)

    ru = sub.add_parser("remove-user", add_help=False, allow_abbrev=False,
                        usage="remove-user <username>")
    ru.add_argument("username")

    ar = sub.add_parser("assign-role", add_help=False, allow_abbrev=False,
                        usage="assign-role <username> --role <role>")
    ar.add_argument("username")
    ar.add_argument("--role", required=True, type=_role_type, choices=_ALL_ROLES)

    st_p2 = sub.add_parser("send-to", add_help=False, allow_abbrev=False,
                            usage="send-to <username> <server-path> [--unmasked]")
    st_p2.add_argument("username", metavar="<username>")
    st_p2.add_argument("path",     metavar="<server-path>")
    st_p2.add_argument("--unmasked", action="store_true", default=False,
                       help="send raw file without masking (admin only)")

    sub.add_parser("active-users", add_help=False, allow_abbrev=False,
                   usage="active-users")

    al = sub.add_parser("audit-log", add_help=False, allow_abbrev=False,
                        usage=("audit-log [--user <u>] [--action <a>] [--limit <n>]"
                               " [--from 'YYYY-MM-DD HH:MM:SS'] [--to 'YYYY-MM-DD HH:MM:SS']"
                               " [--archive <filename>] [--out <path>] [--verify]"))
    al.add_argument("--user",    default=None, metavar="<u>")
    al.add_argument("--action",  default=None, metavar="<a>")
    al.add_argument("--limit",   type=int, default=None, metavar="<n>")
    al.add_argument("--from",    dest="from_ts", default=None, metavar="<ts>")
    al.add_argument("--to",      dest="to_ts",   default=None, metavar="<ts>")
    al.add_argument("--archive", default=None, metavar="<filename>")
    al.add_argument("--out",     default=None, metavar="<path>")
    al.add_argument("--verify",  action="store_true")
    sub.add_parser("rotate-audit", add_help=False, allow_abbrev=False)

    # VFS commands
    ls_p = sub.add_parser("ls", add_help=False, allow_abbrev=False,
                          usage="ls [<folder>] [-a] [-d] [-f] [-g] [-h] [-i] [-l] [-r] [-s] [-t] [-u] [-x] [-1]")
    ls_p.add_argument("path", nargs="?", default=None, metavar="<folder>")
    ls_p.add_argument("-a", dest="all",     action="store_true")
    ls_p.add_argument("-d", dest="dir_itself", action="store_true")
    ls_p.add_argument("-f", dest="unsorted", action="store_true")
    ls_p.add_argument("-g", dest="no_owner", action="store_true")
    ls_p.add_argument("-h", dest="human",   action="store_true")
    ls_p.add_argument("-i", dest="inode",   action="store_true")
    ls_p.add_argument("-l", dest="long",    action="store_true")
    ls_p.add_argument("-r", dest="reverse", action="store_true")
    ls_p.add_argument("-s", dest="blocks",  action="store_true")
    ls_p.add_argument("-t", dest="by_time", action="store_true")
    ls_p.add_argument("-u", dest="by_upload", action="store_true")
    ls_p.add_argument("-x", dest="across",  action="store_true")
    ls_p.add_argument("-1", dest="one_per_line", action="store_true")

    mk_p = sub.add_parser("mkdir", add_help=False, allow_abbrev=False,
                          usage="mkdir <folder>")
    mk_p.add_argument("path", metavar="<folder>")

    st_p = sub.add_parser("stat", add_help=False, allow_abbrev=False,
                          usage="stat <file or folder>")
    st_p.add_argument("path", metavar="<file or folder>")

    tr_p = sub.add_parser("tree", add_help=False, allow_abbrev=False,
                          usage="tree [<folder>]")
    tr_p.add_argument("path", nargs="?", default=None, metavar="<folder>")

    rm_p = sub.add_parser("rm", add_help=False, allow_abbrev=False,
                          usage="rm <file or folder>")
    rm_p.add_argument("path", metavar="<file or folder>")

    mv_p = sub.add_parser("mv", add_help=False, allow_abbrev=False,
                          usage="mv <source> <destination>")
    mv_p.add_argument("src", metavar="<source>")
    mv_p.add_argument("dst", metavar="<destination>")

    sn_p = sub.add_parser("send", add_help=False, allow_abbrev=False,
                          usage="send <local-file> [<server-path>]")
    sn_p.add_argument("src", metavar="<local-file>")
    sn_p.add_argument("dst", nargs="?", default=None, metavar="<server-path>")

    ft_p = sub.add_parser("fetch", add_help=False, allow_abbrev=False,
                          usage="fetch <server-path> [<local-path>]")
    ft_p.add_argument("path", metavar="<server-path>")
    ft_p.add_argument("out",  nargs="?", default=None, metavar="<local-path>")
    ft_p.add_argument("--raw", action="store_true", default=False, help=argparse.SUPPRESS)

    ch_p = sub.add_parser(
        "chmod", add_help=False, allow_abbrev=False,
        usage=(
            "chmod path"
            " --role {" + ",".join(_ALL_ROLES) + "}"
            " --perm {" + ",".join(_ALL_PERMS) + "}"
            " [--action {grant,revoke}]"
        ),
    )
    ch_p.add_argument("path")
    ch_p.add_argument("--role", required=True, type=_role_type, choices=_ALL_ROLES)
    ch_p.add_argument("--perm", required=True, choices=_ALL_PERMS)
    ch_p.add_argument("--action", default="grant", choices=["grant", "revoke"])

    return p


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    _cfg = _load_config()
    parser = argparse.ArgumentParser(
        prog="EFS",
        description="EFS-TDM CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    sub = parser.add_subparsers(dest="command")

    sub.add_parser("web-login", help="Log in via browser")
    sub.add_parser("shell", help="Resume an existing session in the interactive shell")

    cfg_p = sub.add_parser("configure", help="Set server address and connection options")
    cfg_p.add_argument("--host", dest="cfg_host", default=None, help="Server hostname or IP")
    cfg_p.add_argument("--port", dest="cfg_port", type=int, default=None, help="Server port")
    cfg_p.add_argument("--cert", dest="cfg_cert", default=None,
                       help="Path to server certificate (leave unset to use automatic TOFU)")

    return parser


def _revoke_session_on_exit(host: str, port: int, cert: str) -> None:
    """
    Attempt to revoke the current session on the server and clear the local
    session file. Called on SIGINT/SIGTERM so Ctrl+C logs out automatically.
    Failures are silenced — the local file is always cleared regardless.
    """
    token = _load_session()
    if not token:
        return
    try:
        with ServerConn(host, port, cert) as conn:
            conn.send({"cmd": "logout", "session": token})
    except Exception:
        pass
    finally:
        _clear_session()
        _info("Session revoked. Goodbye.")


def cmd_configure(args) -> int:
    """Save host/port/cert to config.json next to the binary."""
    _cfg = _load_config()
    host = args.cfg_host or _cfg["host"]
    port = args.cfg_port or _cfg["port"]
    cert = args.cfg_cert if args.cfg_cert is not None else _cfg["cert"]
    _save_config(host, port, cert)
    _info(f"  host : {host}")
    _info(f"  port : {port}")
    _info(f"  cert : {cert or '(TOFU — auto-fetched on first connect)'}")
    return 0


def main() -> int:
    _ensure_dirs()

    parser = build_parser()
    args = parser.parse_args()

    cfg = _load_config()

    # Default action with no subcommand: run web-login directly
    if not args.command:
        _ensure_cert(cfg["host"], cfg["port"])
        return web_login()

    if args.command == "configure":
        return cmd_configure(args)

    if args.command == "shell":
        _ensure_cert(cfg["host"], cfg["port"])
        return cmd_shell(args)

    # web-login
    _ensure_cert(cfg["host"], cfg["port"])
    return web_login()


if __name__ == "__main__":
    sys.exit(main())
