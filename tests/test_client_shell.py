"""
Tests for client-side shell behavior:
  - Directory send capital-Y confirmation
  - Overwrite prompt [O/S/C/A] requires exact capital letters
  - _safe_completion escapes spaces for readline
  - Completer returns escaped paths for VFS entries with spaces
  - _win_norm converts backslashes to forward slashes (Windows path normalization)
  - _win_complete returns correct candidates for commands, local paths, and VFS paths
"""

import sys
import os
import types
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "client_pkg"))

from client.client import _safe_completion, _make_completer, _win_norm, _win_complete


# ---------------------------------------------------------------------------
# _safe_completion
# ---------------------------------------------------------------------------

class TestSafeCompletion(unittest.TestCase):

    def test_no_spaces_unchanged(self):
        self.assertEqual(_safe_completion("/vfs/reports"), "/vfs/reports")

    def test_trailing_slash_unchanged(self):
        self.assertEqual(_safe_completion("/vfs/reports/"), "/vfs/reports/")

    def test_single_space_escaped(self):
        self.assertEqual(_safe_completion("/vfs/Test Now"), '"/vfs/Test Now"')

    def test_multiple_spaces_escaped(self):
        self.assertEqual(_safe_completion("/vfs/My New Folder/"), '"/vfs/My New Folder"/')

    def test_local_path_with_space(self):
        self.assertEqual(_safe_completion("Test Now/"), '"Test Now"/')

    def test_empty_string(self):
        self.assertEqual(_safe_completion(""), "")

    def test_space_only(self):
        self.assertEqual(_safe_completion(" "), '" "')


# ---------------------------------------------------------------------------
# Completer returns escaped paths for VFS entries with spaces
# ---------------------------------------------------------------------------

class TestCompleterSpacedVfsPaths(unittest.TestCase):
    """Verify the completer escapes spaces in VFS child names."""

    def _make_refs(self, children):
        """Return (conn_ref, token_ref, cwd_ref, allowed_ref) with a mock conn."""
        mock_conn = MagicMock()
        mock_conn.send.return_value = {
            "ok": True,
            "entries": [
                {"name": n.rstrip("/"), "type": "dir" if n.endswith("/") else "file"}
                for n in children
            ],
        }
        return [mock_conn], ["tok"], ["/"], [{"ls", "cd", "rm"}]

    def test_vfs_name_with_space_escaped(self):
        conn_ref, token_ref, cwd_ref, allowed_ref = self._make_refs(["My Reports/"])
        completer = _make_completer(conn_ref, token_ref, cwd_ref, allowed_ref)
        # Simulating: user types "ls M" and presses tab
        with patch("client.client.readline") as mock_rl:
            mock_rl.get_line_buffer.return_value = "ls M"
            result = completer("M", 0)
        self.assertEqual(result, r"/My\ Reports/")

    def test_vfs_name_no_space_unchanged(self):
        conn_ref, token_ref, cwd_ref, allowed_ref = self._make_refs(["reports/"])
        completer = _make_completer(conn_ref, token_ref, cwd_ref, allowed_ref)
        with patch("client.client.readline") as mock_rl:
            mock_rl.get_line_buffer.return_value = "ls r"
            result = completer("r", 0)
        self.assertEqual(result, "/reports/")

    def test_vfs_file_with_space_escaped(self):
        conn_ref, token_ref, cwd_ref, allowed_ref = self._make_refs(["my data.csv"])
        completer = _make_completer(conn_ref, token_ref, cwd_ref, allowed_ref)
        with patch("client.client.readline") as mock_rl:
            mock_rl.get_line_buffer.return_value = "ls my"
            result = completer("my", 0)
        self.assertEqual(result, r"/my\ data.csv")

    def test_vfs_no_match_returns_none(self):
        conn_ref, token_ref, cwd_ref, allowed_ref = self._make_refs(["reports/"])
        completer = _make_completer(conn_ref, token_ref, cwd_ref, allowed_ref)
        with patch("client.client.readline") as mock_rl:
            mock_rl.get_line_buffer.return_value = "ls z"
            result = completer("z", 0)
        self.assertIsNone(result)

    def test_state_increments_through_multiple_matches(self):
        conn_ref, token_ref, cwd_ref, allowed_ref = self._make_refs(["foo/", "foobar/"])
        completer = _make_completer(conn_ref, token_ref, cwd_ref, allowed_ref)
        with patch("client.client.readline") as mock_rl:
            mock_rl.get_line_buffer.return_value = "ls foo"
            m0 = completer("foo", 0)
            m1 = completer("foo", 1)
            m2 = completer("foo", 2)
        self.assertIn(m0, ["/foo/", "/foobar/"])
        self.assertIn(m1, ["/foo/", "/foobar/"])
        self.assertNotEqual(m0, m1)
        self.assertIsNone(m2)


# ---------------------------------------------------------------------------
# Directory send: capital-Y confirmation
# ---------------------------------------------------------------------------

class TestDirSendConfirmation(unittest.TestCase):
    """cmd_vfs_send must prompt and cancel unless the user types exactly 'Y'."""

    def _run_send(self, user_input: str, tmp_path: Path):
        """
        Call cmd_vfs_send with a temp directory as src, patching input() to
        return user_input. Returns the exit code.
        """
        import argparse
        from client.client import cmd_vfs_send

        args = argparse.Namespace(src=str(tmp_path), dst=None)

        mock_conn = MagicMock()
        mock_conn.__enter__ = lambda s: mock_conn
        mock_conn.__exit__ = MagicMock(return_value=False)
        mock_conn.send.return_value = {"ok": True, "path": "/x", "inode_id": 1}

        with patch("client.client._load_session", return_value="tok"), \
             patch("client.client._load_session_role", return_value="Admin"), \
             patch("client.client._guard", return_value=None), \
             patch("builtins.input", return_value=user_input):
            return cmd_vfs_send(args, mock_conn, cwd="/")

    def test_capital_Y_proceeds(self):
        import tempfile, os
        with tempfile.TemporaryDirectory() as d:
            Path(d, "file.txt").write_bytes(b"hello")
            rc = self._run_send("Y", Path(d))
        self.assertEqual(rc, 0)

    def test_lowercase_y_cancels(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            Path(d, "file.txt").write_bytes(b"hello")
            rc = self._run_send("y", Path(d))
        self.assertEqual(rc, 0)  # graceful cancel, not error

    def test_empty_input_cancels(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            Path(d, "file.txt").write_bytes(b"hello")
            rc = self._run_send("", Path(d))
        self.assertEqual(rc, 0)

    def test_no_cancels(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            Path(d, "file.txt").write_bytes(b"hello")
            rc = self._run_send("n", Path(d))
        self.assertEqual(rc, 0)

    def test_N_cancels(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            Path(d, "file.txt").write_bytes(b"hello")
            rc = self._run_send("N", Path(d))
        self.assertEqual(rc, 0)


# ---------------------------------------------------------------------------
# Overwrite conflict menu: exact capital letters required
# ---------------------------------------------------------------------------

class TestOverwriteChoiceCase(unittest.TestCase):
    """
    The [O/S/C/A] overwrite menu must require capital letters.
    Lowercase letters must fall through to the 'skip' branch (no uploads).
    """

    def _run_dir_send_with_conflicts(self, choice_input: str, per_file_input: str = ""):
        """
        Simulate a directory upload where every file already exists (always_exists=True).
        Returns (ok_count, overwrite_attempted).
        """
        import argparse, tempfile
        from client.client import cmd_vfs_send

        uploaded = []

        with tempfile.TemporaryDirectory() as d:
            Path(d, "a.txt").write_bytes(b"data")

            mock_conn = MagicMock()
            mock_conn.__enter__ = lambda s: mock_conn
            mock_conn.__exit__ = MagicMock(return_value=False)

            def fake_send(req):
                cmd = req.get("cmd")
                if cmd == "vfs_mkdir":
                    return {"ok": True}
                if cmd == "vfs_send":
                    if req.get("overwrite"):
                        uploaded.append(req["path"])
                        return {"ok": True, "path": req["path"], "inode_id": 1}
                    # Simulate conflict on first attempt
                    return {
                        "ok": False,
                        "error": "already_exists",
                        "stat": {"size_bytes": 4, "uploaded_at": "2026-01-01",
                                 "content_hash": ""},
                    }
                return {"ok": True}

            mock_conn.send.side_effect = fake_send

            args = argparse.Namespace(src=str(d), dst="/dest")
            inputs = iter(["Y", choice_input, per_file_input])

            with patch("client.client._load_session", return_value="tok"), \
                 patch("client.client._load_session_role", return_value="Admin"), \
                 patch("client.client._guard", return_value=None), \
                 patch("builtins.input", side_effect=lambda _: next(inputs)):
                cmd_vfs_send(args, mock_conn, cwd="/")

        return uploaded

    def test_capital_O_overwrites_all(self):
        uploaded = self._run_dir_send_with_conflicts("O")
        self.assertTrue(len(uploaded) > 0)

    def test_lowercase_o_skips(self):
        # lowercase 'o' is no longer normalized — falls to skip branch
        uploaded = self._run_dir_send_with_conflicts("o")
        self.assertEqual(uploaded, [])

    def test_capital_S_skips_all(self):
        uploaded = self._run_dir_send_with_conflicts("S")
        self.assertEqual(uploaded, [])

    def test_lowercase_s_also_skips(self):
        # 's' is not a valid choice — falls through to skip (no overwrite)
        uploaded = self._run_dir_send_with_conflicts("s")
        self.assertEqual(uploaded, [])

    def test_capital_A_aborts(self):
        uploaded = self._run_dir_send_with_conflicts("A")
        self.assertEqual(uploaded, [])

    def test_lowercase_a_does_not_abort(self):
        # lowercase 'a' is not valid — no abort, falls to skip
        uploaded = self._run_dir_send_with_conflicts("a")
        self.assertEqual(uploaded, [])

    def test_capital_C_prompts_per_file_Y_overwrites(self):
        uploaded = self._run_dir_send_with_conflicts("C", per_file_input="Y")
        self.assertTrue(len(uploaded) > 0)

    def test_capital_C_prompts_per_file_n_skips(self):
        uploaded = self._run_dir_send_with_conflicts("C", per_file_input="n")
        self.assertEqual(uploaded, [])


# ---------------------------------------------------------------------------
# _win_norm: backslash-to-slash conversion
# ---------------------------------------------------------------------------

class TestWinNorm(unittest.TestCase):
    """_win_norm must convert \\ path separators to / on Windows and be a no-op on Linux."""

    def _norm(self, s):
        # Force execution of the Windows branch regardless of current platform.
        with patch("client.client.sys") as mock_sys:
            mock_sys.platform = "win32"
            return _win_norm(s)

    def test_no_backslash_unchanged(self):
        self.assertEqual(self._norm("/vfs/reports"), "/vfs/reports")

    def test_single_backslash_converted(self):
        self.assertEqual(self._norm(r"C:\Users\test"), "C:/Users/test")

    def test_trailing_backslash_converted(self):
        self.assertEqual(self._norm(r"C:\Users\test\ "), r"C:/Users/test\ ")

    def test_space_escape_preserved(self):
        # "\\ " (backslash-space) must survive — it is the space-escape from tab completion
        self.assertEqual(self._norm(r"send Test\ Now"), r"send Test\ Now")

    def test_mixed_path(self):
        # C:\Users\My\ Folder\ Name\ — final \<space> preserved, others converted
        raw = "C:\\Users\\My\\ Folder"
        result = self._norm(raw)
        self.assertEqual(result, r"C:/Users/My\ Folder")

    def test_noop_on_linux(self):
        # On non-Windows platforms the function must return the string unchanged.
        with patch("client.client.sys") as mock_sys:
            mock_sys.platform = "linux"
            result = _win_norm(r"C:\Users\test")
        self.assertEqual(result, r"C:\Users\test")

    def test_empty_string(self):
        self.assertEqual(self._norm(""), "")


# ---------------------------------------------------------------------------
# _win_complete: stateless completion candidates
# ---------------------------------------------------------------------------

class TestWinComplete(unittest.TestCase):
    """_win_complete must return the right completion candidates for each context."""

    # -- helpers -------------------------------------------------------------

    def _mock_conn(self, vfs_entries):
        """Build a mock ServerConn that returns vfs_entries for vfs_ls."""
        conn = MagicMock()
        conn.send.return_value = {
            "ok": True,
            "entries": [
                {"name": n.rstrip("/"), "type": "dir" if n.endswith("/") else "file"}
                for n in vfs_entries
            ],
        }
        return conn

    def _complete(self, line, vfs_entries=None, allowed=None, cwd="/"):
        conn = self._mock_conn(vfs_entries or []) if vfs_entries is not None else None
        cmds = allowed or {"ls", "cd", "send", "fetch", "mkdir", "rm", "mv", "stat",
                           "tree", "chmod", "send-to"}
        return _win_complete(line, conn, "tok", cwd, cmds)

    # -- command completion --------------------------------------------------

    def test_empty_line_returns_all_commands(self):
        results = self._complete("")
        # Should contain all provided cmds + builtins
        for cmd in ("ls", "cd", "send", "help", "clear", "exit", "quit"):
            self.assertIn(cmd + " ", results)

    def test_partial_cmd_filters(self):
        results = self._complete("li")
        self.assertTrue(all(r.startswith("li") for r in results))

    def test_exact_cmd_returns_itself_with_space(self):
        results = self._complete("ls")
        self.assertIn("ls ", results)

    def test_cmd_all_have_trailing_space(self):
        results = self._complete("l")
        self.assertTrue(all(r.endswith(" ") for r in results))

    def test_no_match_returns_empty(self):
        results = self._complete("zzz")
        self.assertEqual(results, [])

    # -- VFS path completion -------------------------------------------------

    def test_vfs_dir_gets_trailing_slash(self):
        results = self._complete("ls r", vfs_entries=["reports/"])
        self.assertIn("/reports/", results)

    def test_vfs_file_no_trailing_slash(self):
        results = self._complete("ls d", vfs_entries=["data.csv"])
        self.assertIn("/data.csv", results)

    def test_vfs_space_in_name_escaped(self):
        results = self._complete("ls M", vfs_entries=["My Reports/"])
        self.assertIn('"/My Reports"/', results)

    def test_vfs_prefix_filter(self):
        results = self._complete("ls fo", vfs_entries=["foo/", "foobar/", "bar/"])
        names = set(results)
        self.assertIn("/foo/", names)
        self.assertIn("/foobar/", names)
        self.assertNotIn("/bar/", names)

    def test_vfs_no_match_empty_list(self):
        results = self._complete("ls z", vfs_entries=["foo/", "bar/"])
        self.assertEqual(results, [])

    def test_vfs_absolute_path_completion(self):
        results = self._complete("ls /fo", vfs_entries=["foo/", "foobar/"])
        self.assertIn("/foo/", results)
        self.assertIn("/foobar/", results)

    # -- send: local path for first arg, VFS for second arg ------------------

    def test_send_first_arg_local(self):
        # First arg after "send" — should do local filesystem completion.
        # We can't control the filesystem, so just verify it doesn't call vfs_ls.
        conn = self._mock_conn([])
        _win_complete("send /tmp/", conn, "tok", "/", {"send"})
        # vfs_ls must NOT have been called for local path completion
        for call in conn.send.call_args_list:
            self.assertNotEqual(call.args[0].get("cmd"), "vfs_ls")

    def test_send_second_arg_vfs(self):
        results = self._complete("send /tmp/file.txt /fo", vfs_entries=["foo/", "bar/"])
        self.assertIn("/foo/", results)

    # -- fetch: VFS for first arg, local for second -------------------------

    def test_fetch_first_arg_vfs(self):
        results = self._complete("fetch /fo", vfs_entries=["foo/", "bar/"])
        self.assertIn("/foo/", results)

    def test_fetch_second_arg_local(self):
        # second arg of fetch is local path — vfs_ls should not be called
        conn = self._mock_conn([])
        _win_complete("fetch /vfs/file.txt /tmp/", conn, "tok", "/", {"fetch"})
        for call in conn.send.call_args_list:
            self.assertNotEqual(call.args[0].get("cmd"), "vfs_ls")

    # -- send-to: no completion on username, VFS on path --------------------

    def test_send_to_username_no_completion(self):
        results = self._complete("send-to al", vfs_entries=["alice/"])
        self.assertEqual(results, [])

    def test_send_to_path_vfs(self):
        results = self._complete("send-to alice /fo", vfs_entries=["foo/"])
        self.assertIn("/foo/", results)

    # -- unknown command: no candidates ------------------------------------

    def test_unknown_cmd_no_completion(self):
        results = self._complete("unknowncmd arg")
        self.assertEqual(results, [])

    # -- _win_norm integration: backslashes in line converted ---------------

    def test_backslash_in_vfs_line_normalized(self):
        # "ls \\reports" should be treated as "ls /reports" after normalization
        results = self._complete("ls \\reports", vfs_entries=["reports/"])
        # The backslash line is normalized to "ls /reports" then prefix is "reports"
        # matching "reports/" under "/"
        self.assertIn("/reports/", results)


if __name__ == "__main__":
    unittest.main(verbosity=2)
