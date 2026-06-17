"""
Shared HMAC token store for the web login handoff.

Tokens are structured as:  <uuid>.<hmac_hex>

The HMAC-SHA256 is computed over the uuid using a per-process secret
generated once at import time. The secret never leaves memory and is
never written to disk.

Token records stored in _STORE:
  {
    "username":      str,
    "role":          str,
    "expires":       float,   # absolute expiry — time.time() + TOKEN_TTL
    "last_activity": float,   # updated on each validate() call
  }

Two independent expiry mechanisms (defense-in-depth):
  - Absolute TTL (TOKEN_TTL): token always expires after 30 minutes regardless
    of activity — prevents indefinitely extended sessions
  - Idle timeout (IDLE_TTL): token expires if not used for 15 minutes —
    limits exposure from abandoned sessions

Only the opaque token string is written to ~/.efs_session.
The server validates by:
  1. Splitting on '.'
  2. Recomputing HMAC over the uuid with the same secret
  3. Comparing with hmac.compare_digest (timing-safe)
  4. Checking absolute expiry
  5. Checking idle timeout
  6. Updating last_activity on success
"""

import hmac
import hashlib
import os
import threading
import time
import uuid as _uuid_mod

# Per-process secret — never persisted
_SECRET: bytes = os.urandom(32)

# In-memory store:  token_id -> record dict
_STORE: dict[str, dict] = {}
_LOCK = threading.Lock()

TOKEN_TTL = 1800   # 30 minutes absolute
IDLE_TTL  = 900    # 15 minutes idle


def _sign(token_id: str) -> str:
    return hmac.new(_SECRET, token_id.encode(), hashlib.sha256).hexdigest()


def issue(username: str, role: str) -> str:
    """
    Create a new signed token for the given user.
    Returns the opaque token string  '<uuid>.<hmac_hex>'.
    """
    token_id = str(_uuid_mod.uuid4())
    sig = _sign(token_id)
    now = time.time()
    record = {
        "username":      username,
        "role":          role,
        "expires":       now + TOKEN_TTL,
        "last_activity": now,
    }
    with _LOCK:
        _STORE[token_id] = record
    return f"{token_id}.{sig}"


def validate(token: str) -> dict | None:
    """
    Validate a token string. Updates last_activity on success.
    Returns the record dict on success, None on any failure.
    """
    try:
        token_id, sig = token.split(".", 1)
    except ValueError:
        return None

    expected = _sign(token_id)
    if not hmac.compare_digest(sig, expected):
        return None

    now = time.time()
    with _LOCK:
        record = _STORE.get(token_id)
        if record is None:
            return None

        # Absolute expiry
        if now > record["expires"]:
            _STORE.pop(token_id, None)
            return None

        # Idle timeout
        if now - record["last_activity"] > IDLE_TTL:
            _STORE.pop(token_id, None)
            return None

        # Update activity timestamp
        record["last_activity"] = now

    return record


def revoke(token: str) -> bool:
    """Remove a token from the store. Returns True if it existed."""
    try:
        token_id, _ = token.split(".", 1)
    except ValueError:
        return False
    with _LOCK:
        return _STORE.pop(token_id, None) is not None
