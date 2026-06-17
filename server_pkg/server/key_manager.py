"""
Ephemeral Key Manager.

Responsibilities:
  - Hold the Master Key (MK) in memory.
  - Derive per-file Data Encryption Keys (DEKs) from the MK using HKDF-SHA256.
  - Issue Ephemeral Session Keys (ESKs): short-lived keys tied to a
    (user_id, file_id) pair with a configurable TTL (default 5 minutes).
  - Validate and revoke ESKs on demand.
  - Run a background sweep thread that purges expired ESKs every 60 seconds.

MK persistence is the caller's responsibility.  The server loads or
creates the MK via _load_or_create_master_key() in server.py and
passes it here.  This class never reads from or writes to disk.

Usage:
    km = KeyManager()               # MK auto-generated (dev/test only)
    km = KeyManager(master_key=b'...')  # supply persisted 32-byte key
    km.start()                      # start background sweep thread

    session_id = km.issue_key("alice", "employees.csv")
    key = km.validate_key(session_id)   # returns bytes or None if expired
    km.revoke_key(session_id)
    km.stop()                       # stop sweep thread cleanly
"""

import os
import uuid
import threading
import time
import logging
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

logger = logging.getLogger(__name__)

DEFAULT_TTL_SECONDS = 300       # 5 minutes
SWEEP_INTERVAL_SECONDS = 60     # background sweep every 60 seconds
MK_SIZE_BYTES = 32              # 256-bit master key
ESK_SIZE_BYTES = 32             # 256-bit ephemeral session key


class KeyManager:
    """
    In-memory ephemeral key manager.

    Thread-safe: all mutations to _store are protected by _lock.
    The MK is held as a plain bytes object; it never touches disk.
    """

    def __init__(self, master_key: bytes | None = None, ttl: int = DEFAULT_TTL_SECONDS):
        """
        Args:
            master_key: 32-byte master key.  If None, a random key is generated
                        (suitable for tests only -- in production the server
                        loads a persisted key and passes it here).
            ttl:        ESK lifetime in seconds (default 300 / 5 minutes).
        """
        if master_key is not None:
            if len(master_key) != MK_SIZE_BYTES:
                raise ValueError(f"master_key must be exactly {MK_SIZE_BYTES} bytes")
            self._mk = master_key
        else:
            self._mk = os.urandom(MK_SIZE_BYTES)

        self._ttl = ttl
        # { session_id: { "key": bytes, "expiry": datetime, "user_id": str, "file_id": str } }
        self._store: dict[str, dict] = {}
        self._lock = threading.Lock()
        self._sweep_thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    # ------------------------------------------------------------------
    # Key derivation
    # ------------------------------------------------------------------

    def derive_dek(self, file_id: str) -> bytes:
        """
        Derive a Data Encryption Key (DEK) for the given file_id using
        HKDF-SHA256 keyed from the master key.

        The DEK is deterministic for a given (MK, file_id) pair so the
        same key can be re-derived on demand without storing it anywhere.

        Args:
            file_id: Unique identifier for the file (e.g. filename or UUID).

        Returns:
            32-byte DEK as bytes.
        """
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=file_id.encode("utf-8"),
        )
        return hkdf.derive(self._mk)

    # ------------------------------------------------------------------
    # ESK lifecycle
    # ------------------------------------------------------------------

    def issue_key(self, user_id: str, file_id: str) -> str:
        """
        Issue a new Ephemeral Session Key for (user_id, file_id).

        Generates a random 32-byte ESK, stores it with an expiry timestamp,
        and returns a UUID session_id the caller uses to retrieve it later.

        Args:
            user_id: Username or user identifier requesting access.
            file_id: File the ESK grants access to.

        Returns:
            session_id string (UUID4).
        """
        session_id = str(uuid.uuid4())
        esk = os.urandom(ESK_SIZE_BYTES)
        expiry = datetime.now(tz=timezone.utc) + timedelta(seconds=self._ttl)

        with self._lock:
            self._store[session_id] = {
                "key": esk,
                "expiry": expiry,
                "user_id": user_id,
                "file_id": file_id,
            }

        logger.debug("ESK issued: session=%s user=%s file=%s expiry=%s",
                     session_id, user_id, file_id, expiry.isoformat())
        return session_id

    def validate_key(self, session_id: str) -> bytes | None:
        """
        Validate a session and return its ESK if still valid.

        Does NOT consume or revoke the key — the caller is responsible for
        revoking after use via revoke_key().

        Args:
            session_id: UUID returned by issue_key().

        Returns:
            ESK bytes if the session exists and has not expired, else None.
        """
        with self._lock:
            entry = self._store.get(session_id)

        if entry is None:
            logger.debug("validate_key: session %s not found", session_id)
            return None

        if datetime.now(tz=timezone.utc) >= entry["expiry"]:
            logger.debug("validate_key: session %s expired", session_id)
            with self._lock:
                self._store.pop(session_id, None)
            return None

        return entry["key"]

    def revoke_key(self, session_id: str) -> bool:
        """
        Revoke a session key immediately, regardless of expiry.

        Args:
            session_id: UUID to revoke.

        Returns:
            True if the session existed and was removed, False if not found.
        """
        with self._lock:
            existed = session_id in self._store
            self._store.pop(session_id, None)

        if existed:
            logger.debug("ESK revoked: session=%s", session_id)
        return existed

    def get_session_info(self, session_id: str) -> dict | None:
        """
        Return metadata for a session (without the key bytes).
        Useful for audit/logging purposes.

        Returns:
            Dict with user_id, file_id, expiry — or None if not found.
        """
        with self._lock:
            entry = self._store.get(session_id)
        if entry is None:
            return None
        return {
            "user_id": entry["user_id"],
            "file_id": entry["file_id"],
            "expiry": entry["expiry"],
        }

    def active_session_count(self) -> int:
        """Return the number of currently stored (not yet swept) sessions."""
        with self._lock:
            return len(self._store)

    # ------------------------------------------------------------------
    # Background sweep
    # ------------------------------------------------------------------

    def _sweep_expired(self):
        """Remove all expired sessions from the store."""
        now = datetime.now(tz=timezone.utc)
        with self._lock:
            expired = [sid for sid, e in self._store.items() if now >= e["expiry"]]
            for sid in expired:
                del self._store[sid]
        if expired:
            logger.debug("Sweep removed %d expired session(s)", len(expired))

    def _sweep_loop(self):
        while not self._stop_event.wait(timeout=SWEEP_INTERVAL_SECONDS):
            self._sweep_expired()
        # Final sweep on shutdown
        self._sweep_expired()

    def start(self):
        """Start the background expiry sweep thread."""
        if self._sweep_thread and self._sweep_thread.is_alive():
            return
        self._stop_event.clear()
        self._sweep_thread = threading.Thread(
            target=self._sweep_loop, daemon=True, name="key-manager-sweep"
        )
        self._sweep_thread.start()
        logger.info("KeyManager sweep thread started (interval=%ds)", SWEEP_INTERVAL_SECONDS)

    def stop(self):
        """Stop the background sweep thread and clear all keys from memory."""
        self._stop_event.set()
        if self._sweep_thread:
            self._sweep_thread.join(timeout=5)
        with self._lock:
            self._store.clear()
        logger.info("KeyManager stopped, all ESKs cleared from memory")
