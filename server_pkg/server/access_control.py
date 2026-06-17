"""
RBAC enforcement and user management.

Roles and their permissions are defined in config/roles.json (server-side)
and seeded into the roles table by core.db.init_db on startup.

Password hashing uses hashlib.scrypt (never bcrypt, never plaintext).
The scrypt parameters follow OWASP 2024 recommendations for interactive
logins. A 32-byte random salt is stored with each hash.

Hash format stored in the DB:
  scrypt:<N>:<r>:<p>:<hex_salt>:<hex_dk>
"""

import hashlib
import hmac
import logging
import os
import sqlite3

_log = logging.getLogger(__name__)

from core.db import (
    init_db,
    create_user,
    get_user,
    get_role,
    update_user_role,
    update_user_password,
    list_users as db_list_users,
    list_roles as db_list_roles,
    delete_user,
    append_audit,
    get_db_path,
)

SCRYPT_N = 2 ** 14   # CPU/memory cost
SCRYPT_R = 8         # block size
SCRYPT_P = 1         # parallelisation
SCRYPT_DKLEN = 32    # derived key length in bytes

def _get_valid_roles(db_path: str | None = None) -> set:
    """Derive valid role names from the database."""
    return {r["name"] for r in db_list_roles(db_path)}


# Backward-compat: module-level constant for imports that use it directly.
# Populated lazily on first call to add_user / assign_role.
VALID_ROLES = {"Admin", "Analyst", "Contributor", "Viewer", "Auditor", "Guest"}

MAX_USERNAME_LEN = 64
MAX_PASSWORD_LEN = 128


# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------

def hash_password(password: str) -> str:
    """
    Derive a scrypt hash of the password.

    Returns a string in the format:
      scrypt:<N>:<r>:<p>:<hex_salt>:<hex_dk>
    """
    salt = os.urandom(32)
    dk = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=SCRYPT_DKLEN,
    )
    return f"scrypt:{SCRYPT_N}:{SCRYPT_R}:{SCRYPT_P}:{salt.hex()}:{dk.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """
    Verify a plaintext password against a stored scrypt hash string.
    Returns True if the password matches, False otherwise.
    """
    try:
        parts = stored_hash.split(":")
        if len(parts) != 6 or parts[0] != "scrypt":
            return False
        _, n, r, p, salt_hex, dk_hex = parts
        salt = bytes.fromhex(salt_hex)
        expected_dk = bytes.fromhex(dk_hex)
        candidate_dk = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=len(expected_dk),
        )
        return hmac.compare_digest(candidate_dk, expected_dk)
    except Exception as e:
        _log.error("verify_password unexpected error (possible corrupted hash): %s", e)
        return False


# ---------------------------------------------------------------------------
# Permission checking
# ---------------------------------------------------------------------------

def check_permission(username: str, action: str, db_path: str | None = None) -> bool:
    """
    Return True if the user's role grants the requested action.

    Args:
        username: The authenticated user.
        action:   Action string, e.g. "encrypt", "decrypt", "mask".
        db_path:  Override DB path (for tests).
    """
    user = get_user(username, db_path)
    if user is None:
        return False
    role = get_role(user["role"], db_path)
    if role is None:
        return False
    return action in role["permissions"]


# ---------------------------------------------------------------------------
# User management (admin-only operations — caller must enforce this)
# ---------------------------------------------------------------------------

def add_user(
    username: str,
    password: str,
    role: str = "Guest",
    db_path: str | None = None,
) -> dict:
    """
    Create a new user with a scrypt-hashed password.

    Raises:
        ValueError:                 If role is not valid.
        sqlite3.IntegrityError:     If username already exists.

    Returns:
        Dict with username and role.
    """
    valid = _get_valid_roles(db_path)
    if role not in valid:
        raise ValueError(f"Invalid role '{role}'. Must be one of: {sorted(valid)}")

    if len(username) > MAX_USERNAME_LEN:
        raise ValueError("Username too long")
    if len(password) > MAX_PASSWORD_LEN:
        raise ValueError("Password too long")

    pw_hash = hash_password(password)
    create_user(username, pw_hash, role, db_path)
    _log.info("add_user: username=%s role=%s", username, role)
    return {"username": username, "role": role}


def assign_role(
    username: str,
    new_role: str,
    db_path: str | None = None,
) -> bool:
    """
    Change a user's role.

    Raises:
        ValueError: If new_role is not valid.

    Returns:
        True if updated, False if user not found.
    """
    valid = _get_valid_roles(db_path)
    if new_role not in valid:
        raise ValueError(f"Invalid role '{new_role}'. Must be one of: {sorted(valid)}")

    updated = update_user_role(username, new_role, db_path)
    if updated:
        _log.info("assign_role: username=%s new_role=%s", username, new_role)
    return updated


def remove_user(username: str, db_path: str | None = None) -> bool:
    """
    Delete a user. Returns True if deleted, False if not found.
    """
    deleted = delete_user(username, db_path)
    if deleted:
        _log.info("remove_user: username=%s", username)
    return deleted


def change_password(
    username: str,
    new_password: str,
    db_path: str | None = None,
    log: bool = True,
) -> bool:
    """
    Set a new password for an existing user (no old-password check — caller
    must enforce any policy, e.g. admin reset vs. self-change).

    Pass log=False when the caller handles audit logging itself (e.g. admin reset).
    Returns True if updated, False if user not found.
    """
    new_hash = hash_password(new_password)
    updated = update_user_password(username, new_hash, db_path)
    if updated and log:
        append_audit(
            action="change_password",
            outcome="success",
            username=username,
            file_id=None,
            db_path=db_path,
        )
    return updated


def authenticate(username: str, password: str, db_path: str | None = None,
                 log: bool = True) -> dict | None:
    """
    Verify credentials. Returns the user dict (without password_hash) on
    success, or None on failure.

    Pass log=False when the caller handles audit logging itself (e.g. _handle_login).
    """
    user = get_user(username, db_path)
    if user is None:
        if log:
            append_audit(action="login", outcome="failure", username=username, db_path=db_path)
        return None

    if not verify_password(password, user["password_hash"]):
        if log:
            append_audit(action="login", outcome="failure", username=username, db_path=db_path)
        return None

    if log:
        append_audit(action="login", outcome="success", username=username,
                     user_id=user["id"], db_path=db_path)
    return {k: v for k, v in user.items() if k != "password_hash"}


def list_users(db_path: str | None = None) -> list[dict]:
    return db_list_users(db_path)


def list_roles(db_path: str | None = None) -> list[dict]:
    return db_list_roles(db_path)
