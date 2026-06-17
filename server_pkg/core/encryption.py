"""
AES-256-GCM Encryption/Decryption Engine.

File format for .enc files:
  [nonce (12 bytes)] | [tag (16 bytes)] | [ciphertext (variable)]

The DEK is never stored — it is derived on demand from the KeyManager
using HKDF and discarded after use.

Public API:
  encrypt_bytes(plaintext, dek)              -> (nonce, tag, ciphertext)
  decrypt_bytes(ciphertext, nonce, tag, dek) -> plaintext
  encrypt_file(src_path, dek, dst_path=None) -> Path
  decrypt_file(enc_path, dek)                -> bytes
  encrypt_file_with_km(src_path, km)         -> Path
  decrypt_file_with_km(enc_path, km)         -> bytes
"""

import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_SIZE = 12   # 96-bit nonce (GCM standard)
TAG_SIZE   = 16   # 128-bit authentication tag (GCM default)
KEY_SIZE   = 32   # 256-bit key


# ---------------------------------------------------------------------------
# Core primitives
# ---------------------------------------------------------------------------

def encrypt_bytes(plaintext: bytes, dek: bytes) -> tuple[bytes, bytes, bytes]:
    """
    Encrypt plaintext with AES-256-GCM.

    Returns:
        (nonce, tag, ciphertext) — nonce 12 B, tag 16 B, ciphertext variable.

    Raises:
        ValueError: dek is not 32 bytes.
    """
    if len(dek) != KEY_SIZE:
        raise ValueError(f"DEK must be {KEY_SIZE} bytes, got {len(dek)}")

    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(dek)
    # cryptography appends tag at end: ciphertext || tag
    ct_with_tag = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    ciphertext  = ct_with_tag[:-TAG_SIZE]
    tag         = ct_with_tag[-TAG_SIZE:]
    return nonce, tag, ciphertext


def decrypt_bytes(ciphertext: bytes, nonce: bytes, tag: bytes, dek: bytes) -> bytes:
    """
    Decrypt and authenticate AES-256-GCM ciphertext.

    Raises:
        ValueError:                         dek length wrong.
        cryptography.exceptions.InvalidTag: tag check failed (tamper or wrong key).
    """
    if len(dek) != KEY_SIZE:
        raise ValueError(f"DEK must be {KEY_SIZE} bytes, got {len(dek)}")

    aesgcm = AESGCM(dek)
    return aesgcm.decrypt(nonce, ciphertext + tag, associated_data=None)


# ---------------------------------------------------------------------------
# File-level operations
# ---------------------------------------------------------------------------

def encrypt_file(
    src_path: str | Path,
    dek: bytes,
    dst_path: str | Path | None = None,
) -> Path:
    """
    Encrypt a file and write a .enc file with layout [nonce|tag|ciphertext].

    dst_path defaults to data/encrypted/<filename>.enc in the project root.

    Raises:
        FileNotFoundError: src_path does not exist.
    """
    src_path = Path(src_path)
    if not src_path.exists():
        raise FileNotFoundError(f"Source file not found: {src_path}")

    if dst_path is None:
        project_root = Path(__file__).parent.parent
        dst_path = project_root / "data" / "encrypted" / (src_path.name + ".enc")

    dst_path = Path(dst_path)
    dst_path.parent.mkdir(parents=True, exist_ok=True)

    nonce, tag, ciphertext = encrypt_bytes(src_path.read_bytes(), dek)

    with dst_path.open("wb") as f:
        f.write(nonce)
        f.write(tag)
        f.write(ciphertext)

    return dst_path


def decrypt_file(enc_path: str | Path, dek: bytes) -> bytes:
    """
    Read a .enc file, verify the GCM tag, and return plaintext bytes.

    Raises:
        FileNotFoundError:                  enc_path does not exist.
        ValueError:                         file too short to be valid.
        cryptography.exceptions.InvalidTag: authentication failed.
    """
    enc_path = Path(enc_path)
    if not enc_path.exists():
        raise FileNotFoundError(f"Encrypted file not found: {enc_path}")

    data = enc_path.read_bytes()
    min_size = NONCE_SIZE + TAG_SIZE
    if len(data) < min_size:
        raise ValueError(f"File too short: {len(data)} bytes (minimum {min_size})")

    nonce      = data[:NONCE_SIZE]
    tag        = data[NONCE_SIZE:NONCE_SIZE + TAG_SIZE]
    ciphertext = data[NONCE_SIZE + TAG_SIZE:]

    return decrypt_bytes(ciphertext, nonce, tag, dek)


# ---------------------------------------------------------------------------
# KeyManager-integrated wrappers
# ---------------------------------------------------------------------------

def encrypt_file_with_km(
    src_path: str | Path,
    km,
    dst_path: str | Path | None = None,
) -> Path:
    """
    Encrypt a file, deriving the DEK from km.derive_dek(filename).
    DEK is deleted from local scope immediately after use.
    """
    src_path = Path(src_path)
    dek = km.derive_dek(src_path.name)
    try:
        return encrypt_file(src_path, dek, dst_path)
    finally:
        del dek


def decrypt_file_with_km(enc_path: str | Path, km,
                          key_id: str | None = None) -> bytes:
    """
    Decrypt a .enc file using a DEK derived by the KeyManager.

    key_id: explicit identifier for DEK derivation. If omitted, the
    original filename is inferred by stripping the .enc suffix (legacy
    behavior for the flat-file encrypt/decrypt commands).
    DEK is deleted from local scope immediately after use.
    """
    enc_path = Path(enc_path)
    if key_id is None:
        key_id = enc_path.stem if enc_path.suffix == ".enc" else enc_path.name
    dek = km.derive_dek(key_id)
    try:
        return decrypt_file(enc_path, dek)
    finally:
        del dek
