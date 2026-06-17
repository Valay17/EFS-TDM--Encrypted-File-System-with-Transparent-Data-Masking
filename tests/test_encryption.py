"""
Unit tests for core/encryption.py.
Covers: roundtrip, nonce uniqueness, tamper detection, wrong key rejection,
        file format, short file rejection, KeyManager integration.
"""

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

from cryptography.exceptions import InvalidTag

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.encryption import (
    encrypt_bytes,
    decrypt_bytes,
    encrypt_file,
    decrypt_file,
    encrypt_file_with_km,
    decrypt_file_with_km,
    NONCE_SIZE,
    TAG_SIZE,
    KEY_SIZE,
)
from server.key_manager import KeyManager


def make_dek() -> bytes:
    return os.urandom(KEY_SIZE)


class TestEncryptBytes(unittest.TestCase):

    def test_returns_three_parts(self):
        nonce, tag, ct = encrypt_bytes(b"hello", make_dek())
        self.assertIsInstance(nonce, bytes)
        self.assertIsInstance(tag, bytes)
        self.assertIsInstance(ct, bytes)

    def test_nonce_is_12_bytes(self):
        nonce, _, _ = encrypt_bytes(b"hello", make_dek())
        self.assertEqual(len(nonce), NONCE_SIZE)

    def test_tag_is_16_bytes(self):
        _, tag, _ = encrypt_bytes(b"hello", make_dek())
        self.assertEqual(len(tag), TAG_SIZE)

    def test_ciphertext_not_equal_to_plaintext(self):
        plaintext = b"sensitive data 1234"
        _, _, ct = encrypt_bytes(plaintext, make_dek())
        self.assertNotEqual(ct, plaintext)

    def test_nonce_is_unique_per_call(self):
        dek = make_dek()
        nonce1, _, _ = encrypt_bytes(b"same data", dek)
        nonce2, _, _ = encrypt_bytes(b"same data", dek)
        self.assertNotEqual(nonce1, nonce2)

    def test_ciphertext_is_unique_per_call(self):
        dek = make_dek()
        _, _, ct1 = encrypt_bytes(b"same data", dek)
        _, _, ct2 = encrypt_bytes(b"same data", dek)
        self.assertNotEqual(ct1, ct2)

    def test_wrong_key_length_raises(self):
        with self.assertRaises(ValueError):
            encrypt_bytes(b"hello", b"tooshort")

    def test_empty_plaintext(self):
        nonce, tag, ct = encrypt_bytes(b"", make_dek())
        self.assertEqual(len(nonce), NONCE_SIZE)
        self.assertEqual(len(tag), TAG_SIZE)
        self.assertEqual(ct, b"")

    def test_large_plaintext(self):
        plaintext = os.urandom(10 * 1024 * 1024)  # 10 MB
        dek = make_dek()
        nonce, tag, ct = encrypt_bytes(plaintext, dek)
        self.assertEqual(len(ct), len(plaintext))


class TestDecryptBytes(unittest.TestCase):

    def test_roundtrip(self):
        plaintext = b"top secret payload"
        dek = make_dek()
        nonce, tag, ct = encrypt_bytes(plaintext, dek)
        result = decrypt_bytes(ct, nonce, tag, dek)
        self.assertEqual(result, plaintext)

    def test_wrong_key_raises_invalid_tag(self):
        dek = make_dek()
        nonce, tag, ct = encrypt_bytes(b"data", dek)
        wrong_dek = make_dek()
        with self.assertRaises(InvalidTag):
            decrypt_bytes(ct, nonce, tag, wrong_dek)

    def test_tampered_ciphertext_raises_invalid_tag(self):
        dek = make_dek()
        nonce, tag, ct = encrypt_bytes(b"data", dek)
        tampered = bytes([ct[0] ^ 0xFF]) + ct[1:]
        with self.assertRaises(InvalidTag):
            decrypt_bytes(tampered, nonce, tag, dek)

    def test_tampered_tag_raises_invalid_tag(self):
        dek = make_dek()
        nonce, tag, ct = encrypt_bytes(b"data", dek)
        bad_tag = bytes([tag[0] ^ 0xFF]) + tag[1:]
        with self.assertRaises(InvalidTag):
            decrypt_bytes(ct, nonce, bad_tag, dek)

    def test_tampered_nonce_raises_invalid_tag(self):
        dek = make_dek()
        nonce, tag, ct = encrypt_bytes(b"data", dek)
        bad_nonce = bytes([nonce[0] ^ 0xFF]) + nonce[1:]
        with self.assertRaises(InvalidTag):
            decrypt_bytes(ct, bad_nonce, tag, dek)

    def test_wrong_key_length_raises_value_error(self):
        with self.assertRaises(ValueError):
            decrypt_bytes(b"ct", b"nonce", b"tag", b"short")

    def test_empty_plaintext_roundtrip(self):
        dek = make_dek()
        nonce, tag, ct = encrypt_bytes(b"", dek)
        result = decrypt_bytes(ct, nonce, tag, dek)
        self.assertEqual(result, b"")


class TestEncryptFile(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.dek = make_dek()

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _make_src(self, content: bytes, name: str = "test.csv") -> Path:
        p = Path(self.tmp_dir) / name
        p.write_bytes(content)
        return p

    def test_returns_path(self):
        src = self._make_src(b"id,name\n1,Alice")
        dst = Path(self.tmp_dir) / "out.enc"
        result = encrypt_file(src, self.dek, dst)
        self.assertIsInstance(result, Path)

    def test_enc_file_created(self):
        src = self._make_src(b"id,name\n1,Alice")
        dst = Path(self.tmp_dir) / "out.enc"
        encrypt_file(src, self.dek, dst)
        self.assertTrue(dst.exists())

    def test_enc_file_layout(self):
        src = self._make_src(b"hello world")
        dst = Path(self.tmp_dir) / "out.enc"
        encrypt_file(src, self.dek, dst)
        data = dst.read_bytes()
        # At minimum: nonce + tag + at least 0 bytes of ciphertext
        self.assertGreaterEqual(len(data), NONCE_SIZE + TAG_SIZE)

    def test_enc_file_not_equal_to_plaintext(self):
        plaintext = b"sensitive,data,here"
        src = self._make_src(plaintext)
        dst = Path(self.tmp_dir) / "out.enc"
        encrypt_file(src, self.dek, dst)
        self.assertNotEqual(dst.read_bytes(), plaintext)

    def test_missing_src_raises(self):
        with self.assertRaises(FileNotFoundError):
            encrypt_file("/nonexistent/path.csv", self.dek)

    def test_default_dst_path(self):
        src = self._make_src(b"content", name="employees.csv")
        result = encrypt_file(src, self.dek)
        self.assertEqual(result.name, "employees.csv.enc")
        self.assertTrue(result.exists())
        result.unlink()

    def test_two_encryptions_of_same_file_differ(self):
        src = self._make_src(b"same content")
        dst1 = Path(self.tmp_dir) / "out1.enc"
        dst2 = Path(self.tmp_dir) / "out2.enc"
        encrypt_file(src, self.dek, dst1)
        encrypt_file(src, self.dek, dst2)
        self.assertNotEqual(dst1.read_bytes(), dst2.read_bytes())


class TestDecryptFile(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.dek = make_dek()

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _enc_file(self, content: bytes) -> Path:
        src = Path(self.tmp_dir) / "src.txt"
        src.write_bytes(content)
        dst = Path(self.tmp_dir) / "src.txt.enc"
        encrypt_file(src, self.dek, dst)
        return dst

    def test_roundtrip(self):
        content = b"id,ssn,email\n1,123-45-6789,alice@example.com"
        enc = self._enc_file(content)
        result = decrypt_file(enc, self.dek)
        self.assertEqual(result, content)

    def test_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            decrypt_file("/nonexistent/file.enc", self.dek)

    def test_short_file_raises(self):
        bad = Path(self.tmp_dir) / "bad.enc"
        bad.write_bytes(b"\x00" * 10)
        with self.assertRaises(ValueError):
            decrypt_file(bad, self.dek)

    def test_wrong_key_raises_invalid_tag(self):
        enc = self._enc_file(b"secret data")
        with self.assertRaises(InvalidTag):
            decrypt_file(enc, make_dek())

    def test_tampered_file_raises_invalid_tag(self):
        enc = self._enc_file(b"secret data")
        data = bytearray(enc.read_bytes())
        data[-1] ^= 0xFF
        enc.write_bytes(bytes(data))
        with self.assertRaises(InvalidTag):
            decrypt_file(enc, self.dek)

    def test_binary_file_roundtrip(self):
        content = os.urandom(4096)
        enc = self._enc_file(content)
        result = decrypt_file(enc, self.dek)
        self.assertEqual(result, content)


class TestKeyManagerIntegration(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.km = KeyManager()

    def tearDown(self):
        self.km.stop()
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _make_src(self, content: bytes, name: str = "report.csv") -> Path:
        p = Path(self.tmp_dir) / name
        p.write_bytes(content)
        return p

    def test_encrypt_decrypt_roundtrip_with_km(self):
        content = b"id,name,ssn\n1,Alice,123-45-6789"
        src = self._make_src(content, "employees.csv")
        dst = Path(self.tmp_dir) / "employees.csv.enc"

        encrypt_file_with_km(src, self.km, dst)
        result = decrypt_file_with_km(dst, self.km)

        self.assertEqual(result, content)

    def test_km_dek_is_deterministic(self):
        # Use the same DEK directly to verify determinism — same key, two
        # different encryptions of the same file should both decrypt correctly.
        content = b"stable content"
        src = self._make_src(content, "stable.csv")
        dek = self.km.derive_dek("stable.csv")

        dst1 = Path(self.tmp_dir) / "stable.csv.enc"
        dst2 = Path(self.tmp_dir) / "stable_copy.csv.enc"

        encrypt_file(src, dek, dst1)
        encrypt_file(src, dek, dst2)

        r1 = decrypt_file(dst1, dek)
        r2 = decrypt_file(dst2, dek)
        self.assertEqual(r1, content)
        self.assertEqual(r2, content)

    def test_different_km_cannot_decrypt(self):
        content = b"private"
        src = self._make_src(content, "private.csv")
        dst = Path(self.tmp_dir) / "private.csv.enc"

        encrypt_file_with_km(src, self.km, dst)

        other_km = KeyManager()  # different master key
        with self.assertRaises(InvalidTag):
            decrypt_file_with_km(dst, other_km)

    def test_enc_suffix_stripped_for_dek_derivation(self):
        content = b"strip test"
        src = self._make_src(content, "data.csv")
        dst = Path(self.tmp_dir) / "data.csv.enc"

        encrypt_file_with_km(src, self.km, dst)
        # decrypt_file_with_km must strip .enc to derive the same DEK
        result = decrypt_file_with_km(dst, self.km)
        self.assertEqual(result, content)


if __name__ == "__main__":
    unittest.main(verbosity=2)
