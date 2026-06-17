"""
Virtual Filesystem layer for EFS-TDM.

All paths use Unix-style forward-slash notation with a shared root '/'.
Folder structure lives in the inodes table; encrypted blobs are UUID-named
.enc files in data/encrypted/.

Public API:
  resolve_path(path, cwd, db_path)  -> inode dict or None
  ls(path, cwd, db_path)            -> list of inode dicts
  mkdir(path, cwd, owner, db_path)  -> inode_id
  rm(inode_id, db_path)             -> bool
  mv(inode_id, new_parent_id, new_name, db_path) -> bool
  stat(inode_id, db_path)           -> dict
  tree(inode_id, db_path, depth)    -> list of str
  check_acl(inode_id, role, perm, db_path) -> bool
"""

from __future__ import annotations

from core.db import (
    ensure_root,
    get_conn,
    get_inode,
    get_inode_by_path_components,
    list_inodes,
    create_inode,
    delete_inode,
    move_inode,
    get_file_meta,
    get_acl,
)


# ---------------------------------------------------------------------------
# Path resolution
# ---------------------------------------------------------------------------

def _normalise(path: str, cwd: str = "/") -> str:
    """Resolve a (possibly relative) path against cwd into a clean absolute path."""
    if not path.startswith("/"):
        path = cwd.rstrip("/") + "/" + path
    parts = []
    for segment in path.split("/"):
        if segment in ("", "."):
            continue
        if segment == "..":
            if parts:
                parts.pop()
        else:
            parts.append(segment)
    return "/" + "/".join(parts)


def resolve_path(path: str, cwd: str = "/",
                  db_path: str | None = None) -> dict | None:
    """
    Resolve a path string to an inode dict.
    Returns None if any component does not exist.
    All segment lookups share a single DB connection.
    """
    abs_path = _normalise(path, cwd)
    with get_conn(db_path) as conn:
        root = conn.execute(
            "SELECT * FROM inodes WHERE parent_id IS NULL AND name = '/'",
        ).fetchone()
        if root is None:
            ensure_root(db_path)
            root = conn.execute(
                "SELECT * FROM inodes WHERE parent_id IS NULL AND name = '/'",
            ).fetchone()

        if abs_path == "/":
            return dict(root) if root else None

        segments = [s for s in abs_path.split("/") if s]
        node = root
        for seg in segments:
            node = conn.execute(
                "SELECT * FROM inodes WHERE parent_id = ? AND name = ?",
                (node["id"], seg),
            ).fetchone()
            if node is None:
                return None
        return dict(node) if node else None


def resolve_parent(path: str, cwd: str = "/",
                    db_path: str | None = None) -> tuple[dict | None, str]:
    """
    Resolve the parent directory and leaf name from a path.
    Returns (parent_inode_dict, leaf_name).
    parent_inode_dict is None if the parent doesn't exist.
    """
    abs_path = _normalise(path, cwd)
    if abs_path == "/":
        return (None, "/")
    parent_path, _, name = abs_path.rpartition("/")
    parent_path = parent_path or "/"
    parent = resolve_path(parent_path, "/", db_path)
    return (parent, name)


# ---------------------------------------------------------------------------
# Directory operations
# ---------------------------------------------------------------------------

def ls(path: str = "/", cwd: str = "/",
        db_path: str | None = None) -> list[dict]:
    """List contents of a directory."""
    node = resolve_path(path, cwd, db_path)
    if node is None:
        raise FileNotFoundError(f"No such file or directory: {path!r}")
    if not node["is_dir"]:
        raise NotADirectoryError(f"Not a directory: {path!r}")
    with get_conn(db_path) as conn:
        rows = conn.execute(
            """
            SELECT i.*, fm.size_bytes, fm.original_name, fm.uploaded_at
            FROM inodes i
            LEFT JOIN file_meta fm ON fm.inode_id = i.id
            WHERE i.parent_id = ?
            ORDER BY i.is_dir DESC, i.name
            """,
            (node["id"],),
        ).fetchall()
    return [dict(r) for r in rows]


def mkdir(path: str, cwd: str = "/", owner: str = "admin",
           db_path: str | None = None) -> int:
    """
    Create a directory (and any missing parents) at path.
    Returns the new inode_id.
    Raises FileExistsError if the final component already exists as a directory.
    """
    abs_path = _normalise(path, cwd)
    if abs_path == "/":
        root = resolve_path("/", "/", db_path)
        return root["id"]

    segments = [s for s in abs_path.split("/") if s]
    ensure_root(db_path)
    parent = resolve_path("/", "/", db_path)

    for i, seg in enumerate(segments):
        existing = get_inode_by_path_components(parent["id"], seg, db_path)
        if existing is not None:
            if not existing["is_dir"]:
                raise NotADirectoryError(
                    f"Component '{seg}' exists as a file"
                )
            parent = existing
        else:
            new_id = create_inode(seg, parent["id"], is_dir=True,
                                   owner=owner, db_path=db_path)
            if i == len(segments) - 1:
                return new_id
            parent = get_inode(new_id, db_path)

    return parent["id"]


# ---------------------------------------------------------------------------
# File/dir removal
# ---------------------------------------------------------------------------

def rm(inode_id: int, db_path: str | None = None) -> bool:
    """
    Remove an inode (and its children via CASCADE).
    For files, the caller is responsible for deleting the .enc blob on disk.
    Returns True if something was deleted.
    """
    return delete_inode(inode_id, db_path)


# ---------------------------------------------------------------------------
# Move / rename
# ---------------------------------------------------------------------------

def mv(inode_id: int, new_parent_id: int, new_name: str,
        db_path: str | None = None) -> bool:
    """Move or rename an inode. Returns True on success."""
    return move_inode(inode_id, new_parent_id, new_name, db_path)


# ---------------------------------------------------------------------------
# Stat
# ---------------------------------------------------------------------------

def stat(inode_id: int, db_path: str | None = None) -> dict:
    """Return metadata for an inode (merges inode + file_meta in one query)."""
    with get_conn(db_path) as conn:
        row = conn.execute(
            """
            SELECT i.*, fm.blob_name, fm.size_bytes, fm.original_name,
                   fm.content_hash, fm.uploaded_at
            FROM inodes i
            LEFT JOIN file_meta fm ON fm.inode_id = i.id
            WHERE i.id = ?
            """,
            (inode_id,),
        ).fetchone()
    if row is None:
        raise FileNotFoundError(f"Inode {inode_id} not found")
    result = dict(row)
    dir_size = result.pop("dir_size_bytes", 0) or 0
    result["type"] = "dir" if result["is_dir"] else "file"
    if result["is_dir"]:
        result["size_bytes"] = dir_size
        for field in ("blob_name", "original_name", "content_hash", "uploaded_at"):
            result.pop(field, None)
    # ACL entries set directly on this inode (not inherited)
    acl_entries = get_acl(inode_id, db_path)
    if acl_entries:
        acl_by_role: dict[str, dict] = {}
        for e in acl_entries:
            acl_by_role.setdefault(e["role"], {})[e["perm"]] = e["action"]
        result["acl"] = {role: perms for role, perms in sorted(acl_by_role.items())}
    return result


# ---------------------------------------------------------------------------
# Tree
# ---------------------------------------------------------------------------

def tree(inode_id: int, db_path: str | None = None,
          _prefix: str = "", _is_last: bool = True,
          role: str | None = None, acl_mode: str = "open") -> list[str]:
    """Return an ASCII-art tree listing rooted at inode_id.
    If role is given, entries with ACL read denied are omitted."""
    node = get_inode(inode_id, db_path)
    if node is None:
        return []

    connector = "└── " if _is_last else "├── "
    label = node["name"] + ("/" if node["is_dir"] else "")
    lines = [_prefix + (connector if _prefix else "") + label]

    if node["is_dir"]:
        children = list_inodes(inode_id, db_path)
        if role is not None:
            children = [c for c in children
                        if check_acl(c["id"], role, "read", db_path,
                                     default_mode=acl_mode, deny_wins=True)]
        child_prefix = _prefix + ("    " if _is_last else "│   ")
        for i, child in enumerate(children):
            is_last_child = (i == len(children) - 1)
            lines.extend(tree(child["id"], db_path, child_prefix, is_last_child,
                               role=role, acl_mode=acl_mode))

    return lines


# ---------------------------------------------------------------------------
# ACL / permission check with parent-chain inheritance
# ---------------------------------------------------------------------------

def check_acl(inode_id: int, role: str, perm: str,
               db_path: str | None = None,
               default_mode: str = "open",
               deny_wins: bool = False) -> bool:
    """
    Check whether `role` has `perm` on `inode_id`.

    Walks up the inode ancestor chain via recursive CTE.

    deny_wins=False (default): closest node wins — child grant overrides parent deny.
    deny_wins=True: any deny anywhere in the ancestor chain blocks access, even if
                    the node itself has an explicit grant. Used for ls/tree visibility
                    so that revoking read on a parent hides all children.

    When no ACL entry is found:
      - default_mode="open":   returns True  (access allowed without ACL)
      - default_mode="closed": returns False (access denied without ACL)

    Admin role always returns True without consulting the ACL table.
    """
    if role == "Admin":
        return True

    with get_conn(db_path) as conn:
        if deny_wins:
            rows = conn.execute(
                """
                WITH RECURSIVE ancestors(id, parent_id, depth) AS (
                    SELECT id, parent_id, 0 FROM inodes WHERE id = ?
                    UNION ALL
                    SELECT i.id, i.parent_id, a.depth + 1
                    FROM inodes i
                    JOIN ancestors a ON i.id = a.parent_id
                )
                SELECT acl.action
                FROM ancestors
                JOIN acl ON acl.inode_id = ancestors.id
                WHERE acl.role = ? AND acl.perm = ?
                ORDER BY ancestors.depth ASC
                """,
                (inode_id, role, perm),
            ).fetchall()
            if not rows:
                return default_mode == "open"
            if any(r["action"] == "deny" for r in rows):
                return False
            return True
        else:
            row = conn.execute(
                """
                WITH RECURSIVE ancestors(id, parent_id, depth) AS (
                    SELECT id, parent_id, 0 FROM inodes WHERE id = ?
                    UNION ALL
                    SELECT i.id, i.parent_id, a.depth + 1
                    FROM inodes i
                    JOIN ancestors a ON i.id = a.parent_id
                )
                SELECT acl.action
                FROM ancestors
                JOIN acl ON acl.inode_id = ancestors.id
                WHERE acl.role = ? AND acl.perm = ?
                ORDER BY ancestors.depth ASC
                LIMIT 1
                """,
                (inode_id, role, perm),
            ).fetchone()
            if row is None:
                return default_mode == "open"
            return row["action"] == "grant"


# ---------------------------------------------------------------------------
# Path reconstruction (inode_id -> full path string)
# ---------------------------------------------------------------------------

def inode_path(inode_id: int, db_path: str | None = None) -> str:
    """Reconstruct the full path for an inode via recursive CTE ancestor walk."""
    with get_conn(db_path) as conn:
        rows = conn.execute(
            """
            WITH RECURSIVE ancestors(id, name, parent_id, depth) AS (
                SELECT id, name, parent_id, 0 FROM inodes WHERE id = ?
                UNION ALL
                SELECT i.id, i.name, i.parent_id, a.depth + 1
                FROM inodes i
                JOIN ancestors a ON i.id = a.parent_id
            )
            SELECT name FROM ancestors
            WHERE NOT (parent_id IS NULL AND name = '/')
            ORDER BY depth DESC
            """,
            (inode_id,),
        ).fetchall()
    if not rows:
        return "/"
    return "/" + "/".join(r["name"] for r in rows)
