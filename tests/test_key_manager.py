"""
Unit tests for server/key_manager.py.
Covers: key issuance, expiry, revocation, replay prevention,
        DEK derivation determinism, thread safety, sweep.
"""

import os
import sys
import time
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from server.key_manager import KeyManager, MK_SIZE_BYTES, ESK_SIZE_BYTES


class TestKeyManagerInit(unittest.TestCase):

    def test_auto_generates_master_key(self):
        km = KeyManager()
        self.assertIsNotNone(km._mk)
        self.assertEqual(len(km._mk), MK_SIZE_BYTES)

    def test_accepts_explicit_master_key(self):
        mk = os.urandom(32)
        km = KeyManager(master_key=mk)
        self.assertEqual(km._mk, mk)

    def test_rejects_wrong_length_master_key(self):
        with self.assertRaises(ValueError):
            KeyManager(master_key=b"tooshort")

    def test_starts_with_empty_store(self):
        km = KeyManager()
        self.assertEqual(km.active_session_count(), 0)


class TestDEKDerivation(unittest.TestCase):

    def setUp(self):
        self.mk = os.urandom(32)
        self.km = KeyManager(master_key=self.mk)

    def test_dek_is_32_bytes(self):
        dek = self.km.derive_dek("employees.csv")
        self.assertEqual(len(dek), 32)

    def test_dek_is_deterministic(self):
        dek1 = self.km.derive_dek("employees.csv")
        dek2 = self.km.derive_dek("employees.csv")
        self.assertEqual(dek1, dek2)

    def test_different_files_produce_different_deks(self):
        dek1 = self.km.derive_dek("file_a.csv")
        dek2 = self.km.derive_dek("file_b.csv")
        self.assertNotEqual(dek1, dek2)

    def test_different_master_keys_produce_different_deks(self):
        km2 = KeyManager(master_key=os.urandom(32))
        dek1 = self.km.derive_dek("employees.csv")
        dek2 = km2.derive_dek("employees.csv")
        self.assertNotEqual(dek1, dek2)


class TestIssueKey(unittest.TestCase):

    def setUp(self):
        self.km = KeyManager()

    def test_returns_string_session_id(self):
        sid = self.km.issue_key("alice", "file.csv")
        self.assertIsInstance(sid, str)
        self.assertTrue(len(sid) > 0)

    def test_each_call_returns_unique_session_id(self):
        sid1 = self.km.issue_key("alice", "file.csv")
        sid2 = self.km.issue_key("alice", "file.csv")
        self.assertNotEqual(sid1, sid2)

    def test_session_count_increases(self):
        self.km.issue_key("alice", "a.csv")
        self.km.issue_key("bob", "b.csv")
        self.assertEqual(self.km.active_session_count(), 2)


class TestValidateKey(unittest.TestCase):

    def setUp(self):
        self.km = KeyManager()

    def test_valid_session_returns_bytes(self):
        sid = self.km.issue_key("alice", "file.csv")
        key = self.km.validate_key(sid)
        self.assertIsInstance(key, bytes)
        self.assertEqual(len(key), ESK_SIZE_BYTES)

    def test_unknown_session_returns_none(self):
        result = self.km.validate_key("nonexistent-session-id")
        self.assertIsNone(result)

    def test_each_session_has_unique_key(self):
        sid1 = self.km.issue_key("alice", "file.csv")
        sid2 = self.km.issue_key("alice", "file.csv")
        key1 = self.km.validate_key(sid1)
        key2 = self.km.validate_key(sid2)
        self.assertNotEqual(key1, key2)

    def test_expired_session_returns_none(self):
        km = KeyManager(ttl=1)
        sid = km.issue_key("alice", "file.csv")
        time.sleep(1.1)
        result = km.validate_key(sid)
        self.assertIsNone(result)

    def test_expired_session_removed_from_store(self):
        km = KeyManager(ttl=1)
        sid = km.issue_key("alice", "file.csv")
        time.sleep(1.1)
        km.validate_key(sid)
        self.assertEqual(km.active_session_count(), 0)


class TestRevokeKey(unittest.TestCase):

    def setUp(self):
        self.km = KeyManager()

    def test_revoke_existing_session_returns_true(self):
        sid = self.km.issue_key("alice", "file.csv")
        result = self.km.revoke_key(sid)
        self.assertTrue(result)

    def test_revoke_nonexistent_session_returns_false(self):
        result = self.km.revoke_key("ghost-session")
        self.assertFalse(result)

    def test_revoked_session_no_longer_valid(self):
        sid = self.km.issue_key("alice", "file.csv")
        self.km.revoke_key(sid)
        result = self.km.validate_key(sid)
        self.assertIsNone(result)

    def test_revoke_reduces_session_count(self):
        sid = self.km.issue_key("alice", "file.csv")
        self.assertEqual(self.km.active_session_count(), 1)
        self.km.revoke_key(sid)
        self.assertEqual(self.km.active_session_count(), 0)

    def test_replay_after_revoke_fails(self):
        # Issue, use once, revoke, then attempt reuse
        sid = self.km.issue_key("alice", "file.csv")
        self.assertIsNotNone(self.km.validate_key(sid))
        self.km.revoke_key(sid)
        self.assertIsNone(self.km.validate_key(sid))


class TestSessionInfo(unittest.TestCase):

    def setUp(self):
        self.km = KeyManager()

    def test_get_session_info_returns_metadata(self):
        sid = self.km.issue_key("bob", "report.pdf")
        info = self.km.get_session_info(sid)
        self.assertEqual(info["user_id"], "bob")
        self.assertEqual(info["file_id"], "report.pdf")
        self.assertIn("expiry", info)

    def test_get_session_info_does_not_include_key(self):
        sid = self.km.issue_key("bob", "report.pdf")
        info = self.km.get_session_info(sid)
        self.assertNotIn("key", info)

    def test_get_session_info_unknown_returns_none(self):
        result = self.km.get_session_info("no-such-session")
        self.assertIsNone(result)


class TestSweepThread(unittest.TestCase):

    def test_start_and_stop(self):
        km = KeyManager()
        km.start()
        self.assertTrue(km._sweep_thread.is_alive())
        km.stop()
        self.assertFalse(km._sweep_thread.is_alive())

    def test_stop_clears_all_keys(self):
        km = KeyManager()
        km.start()
        km.issue_key("alice", "file.csv")
        km.issue_key("bob", "other.csv")
        km.stop()
        self.assertEqual(km.active_session_count(), 0)

    def test_double_start_is_safe(self):
        km = KeyManager()
        km.start()
        km.start()  # should not raise or spawn a second thread
        self.assertEqual(
            sum(1 for t in threading.enumerate() if t.name == "key-manager-sweep"),
            1
        )
        km.stop()

    def test_sweep_removes_expired_entries(self):
        km = KeyManager(ttl=1)
        km.issue_key("alice", "a.csv")
        km.issue_key("bob", "b.csv")
        self.assertEqual(km.active_session_count(), 2)
        time.sleep(1.1)
        km._sweep_expired()
        self.assertEqual(km.active_session_count(), 0)


class TestThreadSafety(unittest.TestCase):

    def test_concurrent_issue_and_revoke(self):
        km = KeyManager()
        results = []
        errors = []

        def worker(user_id):
            try:
                sid = km.issue_key(user_id, "shared_file.csv")
                key = km.validate_key(sid)
                if key is None:
                    errors.append(f"{user_id}: key was None immediately after issue")
                km.revoke_key(sid)
                results.append(sid)
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=worker, args=(f"user{i}",)) for i in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0, f"Thread errors: {errors}")
        self.assertEqual(len(results), 50)
        self.assertEqual(km.active_session_count(), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
