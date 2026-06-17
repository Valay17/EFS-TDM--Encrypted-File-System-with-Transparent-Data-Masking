"""
Tests for Phase 8: Virtual Filesystem (core/vfs.py and core/db.py VFS tables).
"""

import os
import sqlite3
import tempfile
from pathlib import Path

import pytest

from core.db import init_db, ensure_root, get_inode, create_file_meta, get_file_meta
from core.vfs import (
    resolve_path,
    resolve_parent,
    ls,
    mkdir,
    rm,
    mv,
    stat,
    tree,
    check_acl,
    inode_path,
)


@pytest.fixture
def db_path(tmp_path):
    path = str(tmp_path / "test_vfs.db")
    init_db(path)
    ensure_root(path)
    return path


# ---------------------------------------------------------------------------
# Root and path resolution
# ---------------------------------------------------------------------------

class TestResolveRoot:
    def test_root_exists_after_ensure(self, db_path):
        node = resolve_path("/", "/", db_path)
        assert node is not None
        assert node["is_dir"] == 1
        assert node["name"] == "/"

    def test_resolve_nonexistent(self, db_path):
        assert resolve_path("/noexist", "/", db_path) is None

    def test_resolve_empty_path_returns_root(self, db_path):
        node = resolve_path("", "/", db_path)
        assert node["name"] == "/"

    def test_resolve_dot_slash(self, db_path):
        node = resolve_path("./", "/", db_path)
        assert node["name"] == "/"


class TestMkdirResolve:
    def test_mkdir_creates_single_dir(self, db_path):
        mkdir("/docs", "/", owner="admin", db_path=db_path)
        node = resolve_path("/docs", "/", db_path)
        assert node is not None
        assert node["name"] == "docs"
        assert node["is_dir"] == 1

    def test_mkdir_nested(self, db_path):
        mkdir("/a/b/c", "/", owner="admin", db_path=db_path)
        for path in ("/a", "/a/b", "/a/b/c"):
            assert resolve_path(path, "/", db_path) is not None

    def test_mkdir_idempotent_on_existing_dir(self, db_path):
        id1 = mkdir("/docs", "/", owner="admin", db_path=db_path)
        id2 = mkdir("/docs", "/", owner="admin", db_path=db_path)
        assert id1 == id2

    def test_resolve_relative_path(self, db_path):
        mkdir("/home/alice", "/", owner="alice", db_path=db_path)
        node = resolve_path("alice", "/home", db_path)
        assert node["name"] == "alice"

    def test_resolve_dotdot(self, db_path):
        mkdir("/a/b", "/", owner="admin", db_path=db_path)
        node = resolve_path("/a/b/../b", "/", db_path)
        assert node["name"] == "b"

    def test_resolve_deep_dotdot(self, db_path):
        mkdir("/x/y/z", "/", owner="admin", db_path=db_path)
        node = resolve_path("/x/y/z/../../y", "/", db_path)
        assert node["name"] == "y"


# ---------------------------------------------------------------------------
# ls
# ---------------------------------------------------------------------------

class TestLs:
    def test_ls_empty_root(self, db_path):
        entries = ls("/", "/", db_path)
        assert entries == []

    def test_ls_with_subdirs(self, db_path):
        mkdir("/docs", "/", owner="admin", db_path=db_path)
        mkdir("/data", "/", owner="admin", db_path=db_path)
        entries = ls("/", "/", db_path)
        names = {e["name"] for e in entries}
        assert {"docs", "data"} == names

    def test_ls_nonexistent_raises(self, db_path):
        with pytest.raises(FileNotFoundError):
            ls("/noexist", "/", db_path)

    def test_ls_file_raises_not_dir(self, db_path):
        mkdir("/docs", "/", owner="admin", db_path=db_path)
        from core.db import create_inode
        docs = resolve_path("/docs", "/", db_path)
        inode_id = create_inode("readme.txt", docs["id"],
                                 is_dir=False, owner="admin", db_path=db_path)
        create_file_meta(inode_id, "blob.enc", 10, "readme.txt", db_path)
        with pytest.raises(NotADirectoryError):
            ls("/docs/readme.txt", "/", db_path)


# ---------------------------------------------------------------------------
# rm
# ---------------------------------------------------------------------------

class TestRm:
    def test_rm_directory(self, db_path):
        mkdir("/trash", "/", owner="admin", db_path=db_path)
        node = resolve_path("/trash", "/", db_path)
        result = rm(node["id"], db_path)
        assert result is True
        assert resolve_path("/trash", "/", db_path) is None

    def test_rm_nonexistent_returns_false(self, db_path):
        assert rm(9999, db_path) is False

    def test_rm_cascades_children(self, db_path):
        mkdir("/a/b/c", "/", owner="admin", db_path=db_path)
        a = resolve_path("/a", "/", db_path)
        rm(a["id"], db_path)
        assert resolve_path("/a/b", "/", db_path) is None
        assert resolve_path("/a/b/c", "/", db_path) is None


# ---------------------------------------------------------------------------
# mv
# ---------------------------------------------------------------------------

class TestMv:
    def test_mv_rename(self, db_path):
        mkdir("/old", "/", owner="admin", db_path=db_path)
        old = resolve_path("/old", "/", db_path)
        root = resolve_path("/", "/", db_path)
        mv(old["id"], root["id"], "new", db_path)
        assert resolve_path("/old", "/", db_path) is None
        assert resolve_path("/new", "/", db_path) is not None

    def test_mv_to_new_parent(self, db_path):
        mkdir("/src", "/", owner="admin", db_path=db_path)
        mkdir("/dst", "/", owner="admin", db_path=db_path)
        src = resolve_path("/src", "/", db_path)
        dst = resolve_path("/dst", "/", db_path)
        mv(src["id"], dst["id"], "moved", db_path)
        assert resolve_path("/dst/moved", "/", db_path) is not None
        assert resolve_path("/src", "/", db_path) is None


# ---------------------------------------------------------------------------
# stat
# ---------------------------------------------------------------------------

class TestStat:
    def test_stat_directory(self, db_path):
        mkdir("/statme", "/", owner="alice", db_path=db_path)
        node = resolve_path("/statme", "/", db_path)
        info = stat(node["id"], db_path)
        assert info["type"] == "dir"
        assert info["owner"] == "alice"

    def test_stat_file_includes_meta(self, db_path):
        mkdir("/docs", "/", owner="admin", db_path=db_path)
        from core.db import create_inode
        docs = resolve_path("/docs", "/", db_path)
        inode_id = create_inode("f.txt", docs["id"],
                                 is_dir=False, owner="admin", db_path=db_path)
        create_file_meta(inode_id, "blob.enc", 42, "f.txt", db_path)
        info = stat(inode_id, db_path)
        assert info["type"] == "file"
        assert info["size_bytes"] == 42
        assert info["original_name"] == "f.txt"

    def test_stat_nonexistent_raises(self, db_path):
        with pytest.raises(FileNotFoundError):
            stat(9999, db_path)


# ---------------------------------------------------------------------------
# tree
# ---------------------------------------------------------------------------

class TestTree:
    def test_tree_empty(self, db_path):
        root = resolve_path("/", "/", db_path)
        lines = tree(root["id"], db_path)
        assert len(lines) == 1
        assert "/" in lines[0]

    def test_tree_nested(self, db_path):
        mkdir("/a/b/c", "/", owner="admin", db_path=db_path)
        root = resolve_path("/", "/", db_path)
        lines = tree(root["id"], db_path)
        full = "\n".join(lines)
        assert "a" in full
        assert "b" in full
        assert "c" in full


# ---------------------------------------------------------------------------
# ACL / check_acl
# ---------------------------------------------------------------------------

class TestAcl:
    def test_admin_always_allowed(self, db_path):
        mkdir("/secret", "/", owner="admin", db_path=db_path)
        node = resolve_path("/secret", "/", db_path)
        assert check_acl(node["id"], "Admin", "read", db_path) is True

    def test_non_admin_allowed_by_default_in_open_mode(self, db_path):
        mkdir("/secret", "/", owner="admin", db_path=db_path)
        node = resolve_path("/secret", "/", db_path)
        assert check_acl(node["id"], "Guest", "read", db_path) is True

    def test_non_admin_denied_by_default_in_closed_mode(self, db_path):
        mkdir("/locked", "/", owner="admin", db_path=db_path)
        node = resolve_path("/locked", "/", db_path)
        assert check_acl(node["id"], "Guest", "read", db_path,
                         default_mode="closed") is False

    def test_explicit_grant_works(self, db_path):
        from core.db import set_acl
        mkdir("/public", "/", owner="admin", db_path=db_path)
        node = resolve_path("/public", "/", db_path)
        set_acl(node["id"], "Viewer", "read", db_path)
        assert check_acl(node["id"], "Viewer", "read", db_path) is True

    def test_parent_acl_inheritance(self, db_path):
        from core.db import set_acl
        mkdir("/shared/sub", "/", owner="admin", db_path=db_path)
        shared = resolve_path("/shared", "/", db_path)
        sub    = resolve_path("/shared/sub", "/", db_path)
        set_acl(shared["id"], "Viewer", "read", db_path)
        assert check_acl(sub["id"], "Viewer", "read", db_path) is True

    def test_child_acl_overrides_parent(self, db_path):
        from core.db import set_acl
        mkdir("/parent/child", "/", owner="admin", db_path=db_path)
        parent = resolve_path("/parent", "/", db_path)
        child  = resolve_path("/parent/child", "/", db_path)
        set_acl(parent["id"], "Viewer", "read", db_path)
        assert check_acl(child["id"], "Viewer", "read", db_path) is True

    def test_revoke_removes_permission(self, db_path):
        from core.db import set_acl, revoke_acl
        mkdir("/box", "/", owner="admin", db_path=db_path)
        node = resolve_path("/box", "/", db_path)
        set_acl(node["id"], "Viewer", "read", db_path)
        assert check_acl(node["id"], "Viewer", "read", db_path) is True
        revoke_acl(node["id"], "Viewer", "read", db_path)
        assert check_acl(node["id"], "Viewer", "read", db_path) is False


# ---------------------------------------------------------------------------
# inode_path reconstruction
# ---------------------------------------------------------------------------

class TestInodePath:
    def test_root_path(self, db_path):
        root = resolve_path("/", "/", db_path)
        assert inode_path(root["id"], db_path) == "/"

    def test_nested_path(self, db_path):
        mkdir("/a/b/c", "/", owner="admin", db_path=db_path)
        node = resolve_path("/a/b/c", "/", db_path)
        assert inode_path(node["id"], db_path) == "/a/b/c"

    def test_single_level_path(self, db_path):
        mkdir("/mydir", "/", owner="admin", db_path=db_path)
        node = resolve_path("/mydir", "/", db_path)
        assert inode_path(node["id"], db_path) == "/mydir"


# ---------------------------------------------------------------------------
# resolve_parent
# ---------------------------------------------------------------------------

class TestResolveParent:
    def test_resolve_parent_of_root_child(self, db_path):
        parent, name = resolve_parent("/foo", "/", db_path)
        assert parent["name"] == "/"
        assert name == "foo"

    def test_resolve_parent_deep(self, db_path):
        mkdir("/a/b", "/", owner="admin", db_path=db_path)
        parent, name = resolve_parent("/a/b/newfile", "/", db_path)
        assert parent["name"] == "b"
        assert name == "newfile"

    def test_resolve_parent_missing_returns_none(self, db_path):
        parent, name = resolve_parent("/noexist/file", "/", db_path)
        assert parent is None
        assert name == "file"


# ---------------------------------------------------------------------------
# check_acl deny_wins mode
# ---------------------------------------------------------------------------

class TestAclDenyWins:
    """deny_wins=True: any deny in ancestor chain blocks regardless of child grant."""

    def test_deny_wins_false_child_grant_overrides_parent_deny(self, db_path):
        """Default mode: child grant wins over parent deny."""
        from core.db import set_acl, revoke_acl
        mkdir("/parent/child", "/", owner="admin", db_path=db_path)
        parent = resolve_path("/parent", "/", db_path)
        child  = resolve_path("/parent/child", "/", db_path)
        revoke_acl(parent["id"], "Viewer", "read", db_path)
        set_acl(child["id"], "Viewer", "read", db_path)
        # Default closest-wins: child grant wins
        assert check_acl(child["id"], "Viewer", "read", db_path, deny_wins=False) is True

    def test_deny_wins_true_parent_deny_overrides_child_grant(self, db_path):
        """deny_wins=True: parent deny overrides child grant."""
        from core.db import set_acl, revoke_acl
        mkdir("/pdeny/cgrant", "/", owner="admin", db_path=db_path)
        parent = resolve_path("/pdeny", "/", db_path)
        child  = resolve_path("/pdeny/cgrant", "/", db_path)
        revoke_acl(parent["id"], "Viewer", "read", db_path)
        set_acl(child["id"], "Viewer", "read", db_path)
        # deny_wins: parent deny blocks even though child has grant
        assert check_acl(child["id"], "Viewer", "read", db_path, deny_wins=True) is False

    def test_deny_wins_true_no_deny_in_chain_allows(self, db_path):
        """deny_wins=True with grant only in chain still allows."""
        from core.db import set_acl
        mkdir("/clean/sub", "/", owner="admin", db_path=db_path)
        parent = resolve_path("/clean", "/", db_path)
        child  = resolve_path("/clean/sub", "/", db_path)
        set_acl(parent["id"], "Viewer", "read", db_path)
        assert check_acl(child["id"], "Viewer", "read", db_path, deny_wins=True) is True

    def test_deny_wins_true_grandparent_deny_blocks(self, db_path):
        """deny_wins=True: deny anywhere in ancestor chain blocks, not just direct parent."""
        from core.db import revoke_acl
        mkdir("/gp/mid/leaf", "/", owner="admin", db_path=db_path)
        gp   = resolve_path("/gp", "/", db_path)
        leaf = resolve_path("/gp/mid/leaf", "/", db_path)
        revoke_acl(gp["id"], "Contributor", "read", db_path)
        assert check_acl(leaf["id"], "Contributor", "read", db_path, deny_wins=True) is False

    def test_deny_wins_no_acl_uses_default_mode(self, db_path):
        """deny_wins=True with no ACL entries falls back to default_mode."""
        mkdir("/noentry", "/", owner="admin", db_path=db_path)
        node = resolve_path("/noentry", "/", db_path)
        assert check_acl(node["id"], "Viewer", "read", db_path,
                         default_mode="open", deny_wins=True) is True
        assert check_acl(node["id"], "Viewer", "read", db_path,
                         default_mode="closed", deny_wins=True) is False

    def test_deny_wins_admin_always_allowed(self, db_path):
        """Admin bypasses deny_wins check."""
        from core.db import revoke_acl
        mkdir("/admintest", "/", owner="admin", db_path=db_path)
        node = resolve_path("/admintest", "/", db_path)
        revoke_acl(node["id"], "Admin", "read", db_path)
        assert check_acl(node["id"], "Admin", "read", db_path, deny_wins=True) is True


# ---------------------------------------------------------------------------
# tree() with role-based ACL filtering
# ---------------------------------------------------------------------------

class TestTreeAclFiltering:
    """tree() with role= omits entries where read is denied."""

    def test_tree_without_role_shows_all(self, db_path):
        mkdir("/vis/a", "/", owner="admin", db_path=db_path)
        mkdir("/vis/b", "/", owner="admin", db_path=db_path)
        vis = resolve_path("/vis", "/", db_path)
        lines = "\n".join(tree(vis["id"], db_path))
        assert "a" in lines
        assert "b" in lines

    def test_tree_with_role_hides_denied_child(self, db_path):
        from core.db import revoke_acl
        mkdir("/filtered/secret", "/", owner="admin", db_path=db_path)
        mkdir("/filtered/public", "/", owner="admin", db_path=db_path)
        secret = resolve_path("/filtered/secret", "/", db_path)
        revoke_acl(secret["id"], "Viewer", "read", db_path)
        filtered = resolve_path("/filtered", "/", db_path)
        lines = "\n".join(tree(filtered["id"], db_path, role="Viewer"))
        assert "secret" not in lines
        assert "public" in lines

    def test_tree_with_role_parent_deny_hides_entire_subtree(self, db_path):
        """Parent read deny hides the parent and all its children."""
        from core.db import revoke_acl
        mkdir("/blocked/sub/leaf", "/", owner="admin", db_path=db_path)
        blocked = resolve_path("/blocked", "/", db_path)
        revoke_acl(blocked["id"], "Analyst", "read", db_path)
        root = resolve_path("/", "/", db_path)
        lines = "\n".join(tree(root["id"], db_path, role="Analyst"))
        assert "blocked" not in lines
        assert "sub" not in lines
        assert "leaf" not in lines

    def test_tree_with_role_no_acl_open_mode_shows_entry(self, db_path):
        mkdir("/opendir/child", "/", owner="admin", db_path=db_path)
        opendir = resolve_path("/opendir", "/", db_path)
        lines = "\n".join(tree(opendir["id"], db_path, role="Guest", acl_mode="open"))
        assert "child" in lines

    def test_tree_with_role_no_acl_closed_mode_hides_entry(self, db_path):
        mkdir("/closeddir/child", "/", owner="admin", db_path=db_path)
        closeddir = resolve_path("/closeddir", "/", db_path)
        lines = "\n".join(tree(closeddir["id"], db_path, role="Guest", acl_mode="closed"))
        assert "child" not in lines
