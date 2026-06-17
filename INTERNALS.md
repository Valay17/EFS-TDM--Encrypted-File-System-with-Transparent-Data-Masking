# EFS-TDM Architecture Details

## Overview

Client-server over TLS. The server holds the master key, performs all decryption and masking in memory, and enforces RBAC on every request. The client sends commands and receives already-masked content; it never sees a raw key or plaintext. Two entry points run on the server side: the main TLS socket server handles all file and user operations, and a Flask HTTPS login UI provides the browser-based auth flow. Both share the same TLS certificate.

The project splits cleanly into two deployable packages. `server_pkg/` runs on the server machine and contains the server, core logic, config, certs, and sample data. `client_pkg/` runs on each client machine and contains the Python client source. For binary distribution, `portable_client/` and `portable_client_win/` are ready-to-run builds that require no Python installation.


## Database

SQLite in WAL mode with foreign keys enforced. Seven tables:

| Table | Purpose |
|---|---|
| `roles` | Role names with JSON permission arrays, seeded from `roles.json` on every start |
| `users` | Credentials (scrypt hash), role FK, created_at |
| `audit_log` | Append-only log with HMAC chain hash covering every field in each row |
| `inodes` | VFS directory tree (id, parent_id, name, is_dir, owner, created_at) |
| `file_meta` | Maps file inodes to UUID `.enc` blob names; stores size_bytes, content_hash (SHA-256 of plaintext), uploaded_at |
| `acl` | Per-inode, per-role grant/deny entries |
| `deliveries` | Pending file deliveries between users; unmasked flag controls whether masking is skipped on receipt |

Key design decisions:

- `get_conn()` is a context manager that auto-commits on success and rolls back on exception.
- `init_db()` is idempotent: all tables use `CREATE TABLE IF NOT EXISTS` via `executescript()`. Column migrations run in a separate `get_conn()` block because `executescript()` issues an implicit COMMIT that would prevent the migration from committing if done in the same block.
- `roles` table is seeded with `INSERT OR REPLACE` on every server start so `roles.json` is always the source of truth. Edit `roles.json` and restart to change permissions without wiping the database.
- `inodes.dir_size_bytes` is maintained incrementally by walking the parent chain on every file create, overwrite, delete, and move. `stat` on a directory is O(1) and always current. Backfilled via a one-time recursive CTE on first run after the migration.
- `append_audit()` computes an HMAC-SHA256 chain hash covering all fields of each row plus the previous row's hash. The `_audit_chain_lock` module-level lock serializes the SELECT (previous hash) + INSERT so concurrent threads cannot compute chain hashes against a stale predecessor.

Indexes created at init: `idx_audit_log_username`, `idx_audit_log_action`, `idx_audit_log_timestamp`, `idx_inodes_parent_sort` (composite `parent_id, is_dir DESC, name`).


## Key Hierarchy

```
master.key  (server disk, chmod 600)
    |
    +-- HKDF-SHA256(master key, info=file_uuid) --> DEK  (memory only, per file)
                                                         |
                                                         +-- AES-256-GCM --> .enc blob
```

Three distinct key types exist:

| Key | Location | Purpose |
|---|---|---|
| Master Key (MK) | `certs/master.key` | Root of all file encryption (HKDF source). Persisted so encrypted blobs survive restarts. |
| TLS Private Key | `certs/key.pem` | Authenticates server in TLS handshake. Server only, chmod 600. |
| TLS Certificate | `certs/cert.pem` | Client verifies server identity. Pinned in the compiled binary. |
| DEK | Never stored | AES-256-GCM key for one file. Derived on demand, discarded immediately after use. |
| ESK | Never stored | Short-lived per-session key for in-flight operations. Memory only, 5-minute TTL. |

The MK resolves through a three-tier process at startup: `EFS_MASTER_KEY` environment variable (64 hex chars) takes priority, then `certs/master.key` on disk, then fresh generation with `chmod 600` on first run. A file that exists but cannot be decoded raises an error rather than silently overwriting itself, which would orphan all encrypted blobs.

DEK derivation uses HKDF-SHA256 with `salt=None` and `info=file_uuid.encode()`. The same (MK, file_uuid) pair always produces the same DEK, making decryption deterministic without storing anything. The DEK is deleted from local scope in `finally` blocks immediately after use.

The background sweep thread (60-second interval) purges expired ESKs. All key store mutations are protected by `_lock`.



## Encryption Engine

File format for `.enc` blobs: `[nonce 12B][tag 16B][ciphertext NB]`.

- Nonce: 12 bytes (96-bit), generated via `os.urandom()` per encryption call.
- Tag: 16 bytes (128-bit GCM authentication tag). Tampering with even one byte causes `InvalidTag` and decryption fails outright rather than returning garbage.
- DEK: always 32 bytes (256-bit AES key), derived via HKDF and held only for the duration of the operation.

`encrypt_file_with_km` and `decrypt_file_with_km` derive the DEK from the KeyManager, use it, and immediately `del dek`. No DEK is ever written to disk.



## Masking Engine

Regex-based PII masking dispatched by file extension. Rules and role profiles are loaded from `masking_rules.json`. Admin profile has an empty rules list (sees all content unmasked). All other roles have their profiles applied on every fetch.

`_safe_sub()` runs each regex substitution in a daemon thread with a 5-second timeout as ReDoS protection. `_validate_rules()` validates the JSON schema on load.

Supported formats and how each is handled:

| Format | Extensions | Approach |
|---|---|---|
| CSV | `.csv` | stdlib `csv` module; header row preserved; regex applied cell-by-cell on data rows; multi-line quoted fields handled correctly |
| XLSX | `.xlsx` | openpyxl; all cells read as strings, regex applied per cell, written back preserving formatting |
| XLS | `.xls` | xlrd read-only; output written as `.xlsx` (legacy xls write is unsupported on Python 3.12+) |
| Plain text | `.txt` `.log` `.tex` `.bib` | Regex applied to full string |
| SQL | `.sql` `.dump` | Regex applied to full string; SQL keywords unaffected because patterns only target PII values |
| PDF | `.pdf` | Hybrid routing: all pages inspected first; a page is image-based if `len(page.get_text().strip()) < 50` AND it contains embedded images; any image-based page routes the entire document through OCR (pytesseract + Pillow at 300 DPI, word-level bounding boxes, black fill, raster-only PDF output); otherwise the text-layer path runs via PyMuPDF redaction annotations |
| DOCX | `.docx` | python-docx; paragraphs, tables, section headers/footers masked in-place |
| ODT / ODP | `.odt` `.odp` | odfpy; `text:p` elements walked and masked |
| ODS | `.ods` | odfpy; `table:table-cell` text elements masked |
| PPTX | `.pptx` | python-pptx; shape text frames across all slides masked |
| Unknown / no extension | | Treated as plain text |

Unsupported formats (raise an error, user must convert first): `.doc`, `.ppt`, `.rtf`.

Encrypt-only formats (no masking supported): images, video, audio, archives.

OCR path note: output is raster-only PDF with no searchable text layer. Redaction is permanent.


## Virtual Filesystem

A Unix-style inode tree stored in SQLite. Files are organized into directories; encrypted blobs are stored on disk as UUID-named `.enc` files with no relation to the original filename.

Path resolution: `resolve_path()` walks the inode tree component by component from root using a single shared DB connection. `mkdir()` creates missing parents automatically. `rm()` delegates to `delete_inode()` which cascades children via SQLite `ON DELETE CASCADE`. `mv()` updates `parent_id` and `name`. `inode_path()` walks ancestors to root in one recursive CTE query.

`stat()` returns inode and file metadata in a single `LEFT JOIN` query. For directories it reads `dir_size_bytes` directly (O(1)). Also fetches ACL entries on the inode; section is omitted if none exist.

`ls()` returns inodes and file metadata in a single `LEFT JOIN` query. When called with a role, entries where `check_acl(deny_wins=True)` returns False are filtered out. If the directory itself has read denied for the role, `ls` returns a permission error immediately.

`tree()` produces a recursive ASCII-art tree with box-drawing connectors. When a role is provided, entries denied by `check_acl(deny_wins=True)` are omitted along with their entire subtree.

ACL resolution via `check_acl()`: a single recursive CTE walks the entire ancestor chain in one query. Two modes:

- **Closest-wins** (default for fetch and delete): the nearest ancestor with a matching entry wins. A child grant overrides a parent deny.
- **Deny-wins** (`deny_wins=True`, used for ls and tree): any deny anywhere in the ancestor chain blocks access. A parent directory read deny hides all children even if a child has an explicit grant. This prevents information leakage through directory listings.

Admin role always returns True from `check_acl` without consulting the ACL table.

ACL default mode when no entry is found anywhere in the chain: configurable via `acl.default_mode` in `server_config.json` as `"open"` (allow by default) or `"closed"` (deny by default).

Delete ACL semantics: `delete_own` uses `default_mode="open"` (falls back to global role permission if no ACL entry). `delete_any` uses `default_mode="closed"` (requires an explicit grant; not available by default even if the role has global `delete_any`). An explicit deny on `delete_own` for the file owner is absolute and cannot be overridden by a `delete_any` grant on the same node.

Write ACL enforcement: `send`, `mkdir`, and `mv` check the `write` permission on the target parent directory (and on the existing file node for overwrites) before any data transfer.



## Access Control

Six roles with their default permissions:

| Role | Permissions |
|---|---|
| Admin | list, read, write, delete_own, delete_any, mask, export_raw, manage_permissions, manage_users, view_audit, encrypt, decrypt |
| Analyst | list, read, mask |
| Contributor | list, read, write, delete_own |
| Viewer | list, read |
| Auditor | view_audit |
| Guest | list |

Password hashing uses scrypt with parameters N=2^14, r=8, p=1, dklen=32, and a 32-byte random salt per user. Stored format: `scrypt:N:r:p:hex_salt:hex_dk`. All password comparisons use `hmac.compare_digest` for constant-time comparison.

Root admin protection: the first user created (id=1) cannot be deleted or demoted by anyone, including itself. Only the root admin can delete other admin accounts or reset another admin's password. Non-admin users cannot assign the Admin role to anyone.

Session tokens use `secrets.token_urlsafe(32)` (256-bit CSPRNG). Every session lookup checks the TTL. One-session-per-user: a second login for the same username revokes the existing session and issues a new token. This means a re-login after a client crash succeeds immediately without waiting for TTL expiry.

`assign-role` immediately revokes all active sessions for the target user. `change-password` immediately revokes all sessions for the affected user. In both cases the user must re-authenticate.

Client-side permission guard (`_guard`): checks the session role against `_ROLE_PERMISSIONS` before any server request or interactive prompt. Defense-in-depth: the server enforces RBAC regardless.



## Audit Log and Integrity Monitor

Every audit entry stores `chain_hash = HMAC-SHA256(key, prev_hash + action + outcome + username + user_id + file_id + role + pid + timestamp)`. All fields in the row are covered. Modifying, deleting, or inserting any row breaks the chain.

`verify_audit_chain()` re-derives all hashes from scratch and returns a bool. `verify_audit_chain_incremental(last_id, last_hash)` verifies only rows added since the last check, returning `(ok, new_last_id, new_last_hash)`. State is not advanced on failure.

The `_AuditIntegrityMonitor` background daemon runs two scan modes:

- **Incremental** (every poll, default 60 seconds): covers only rows added since the last poll. Fast, O(new rows).
- **Full scan** (every N incremental polls, default every 10th): re-verifies the entire live chain from row 1. Catches retroactive hash replacement that incremental scans miss.

On detecting tampering: logs `CRITICAL` to `server.log`, sets a module-level `_audit_tamper_alert` dict, and `_dispatch()` injects an `audit_tamper_alert` field into every response for Admin and Auditor sessions. The client displays a bold red multi-line banner to stderr immediately on receipt. The alert persists until `rotate-audit` is called, which resets the monitor state.

The monitor skips polling while `_audit_rotating` is set (rotation is in progress and the chain is transiently incomplete).

Rotation (`rotate-audit`): writes a sentinel entry to the old log, archives the DB via `sqlite3.backup()` (WAL-safe) to `data/audit_<UTC-timestamp-microseconds>.db`, truncates the live `audit_log`, then writes a bootstrap entry in the new log with `file_id=<archive_name>|prev_hash:<chain_tip>`. The encoded `prev_hash` links the new log's chain to the previous archive's last entry. All concurrent audit writes queue behind `_audit_lock` during rotation. Archive files are locked read-only (`chmod 0o444`) immediately after rotation.

`verify_audit_chain_across(db_paths)` verifies the full chain is unbroken across a sequence of archives plus the live DB. Checks internal chain in each file, bootstrap entry linkage, `prev_hash` continuity, and that the first file does not start mid-chain.

Audit log auto-rotation triggers on every write that crosses a threshold. Configurable via `server_config.json["audit"]`:

| Setting | Default | Meaning |
|---|---|---|
| `auto_rotate_max_entries` | 10000 | Rotate when live log exceeds this many entries |
| `auto_rotate_max_days` | 30 | Rotate when oldest entry is older than this many days |
| `retention_max_archives` | 12 | Delete oldest archives beyond this count (0 = keep all) |
| `integrity_check_interval_seconds` | 60 | Seconds between incremental scans |
| `integrity_full_scan_every_n_polls` | 10 | Full scan every N incremental polls |


## Web Login Flow

Flask HTTPS login UI runs alongside the socket server in a background daemon thread.

Security layers: HTTPS only (same TLS cert and cipher configuration as the backend), strict security headers on every response (HSTS, CSP, X-Frame-Options DENY, nosniff, Referrer-Policy, Permissions-Policy, COOP, Server header removed), generic error pages for all 4xx/5xx (no stack traces), IP rate limiting (10 requests per IP per 5-minute window), account lockout (5 failures per username locks for 15 minutes), and identical error messages for wrong username vs wrong password.

Login flow:

1. Client generates a `poll_key`, sends `GET /?init=<key>` which sets an httpOnly+Secure+SameSite=Strict cookie and renders the login page.
2. User submits credentials via the form. Server validates CSRF token (double-submit cookie, constant-time comparison), checks rate limit and lockout, authenticates via DB, calls the TLS backend for a session token, and stores it in `_pending[poll_key]`.
3. Client polls `GET /poll` every 0.5 seconds for up to 120 seconds. On first pickup the token is removed from `_pending` (one-time use, 5-minute expiry). Client writes the token to `~/.efs_session` (chmod 600) and drops into the interactive shell.

Web tokens in `token_store.py` are HMAC-SHA256 signed (`<uuid>.<hmac_hex>`) with a per-process 32-byte secret that is never persisted. Validation checks both an absolute 30-minute TTL and a 15-minute idle timeout independently. `validate()` updates `last_activity` on success.


## TLS Implementation

Certificate generation (`scripts/generate_certs.sh`): RSA-4096, self-signed, 10-year validity, `CN=localhost`, SAN covering `IP:127.0.0.1` and `DNS:localhost`. Private key chmod 600. Certificate copied to both `server_pkg/certs/` and `client_pkg/certs/`. Script is idempotent and skips if both files already exist.

Server-side SSL context:
- Minimum version: TLS 1.2
- Cipher suite: TLS 1.3 suites (AES-256-GCM, AES-128-GCM, ChaCha20-Poly1305) listed first, then TLS 1.2 ECDHE+AEAD fallback. No CBC, no RC4, no static RSA key exchange.
- Options: `OP_NO_COMPRESSION` (CRIME mitigation), `OP_SINGLE_DH_USE`, `OP_SINGLE_ECDH_USE` (fresh DH/ECDH per handshake).

Client-side SSL context: `CERT_REQUIRED` with the local copy of `cert.pem` as the trust anchor. `check_hostname = False` because the self-signed cert does not match a real hostname. On first connect in the compiled binary, the cert is fetched from the server with `ssl.CERT_NONE` and pinned for all subsequent connections (trust-on-first-use).



## Config Files

Three JSON files in `server_pkg/config/` control runtime behavior without code changes. All deep-merge over built-in defaults, so partial configs are valid.

**`roles.json`** — maps role names to permission lists. `init_db()` seeds the `roles` table with `INSERT OR REPLACE` on every server start. To change permissions: edit `roles.json` and restart, no DB wipe required. `_get_valid_roles(db_path)` queries the DB at runtime so custom roles defined here are accepted by `add_user` and `assign_role` without code changes.

**`server_config.json`** — all server tunables: bind address and port, TLS cert and key paths, password policy (min length, complexity), session TTL, idle timeout, upload size limit, socket and Flask rate limit thresholds, default new-user role, ACL default mode, and the full `audit` block (rotation thresholds, retention, integrity monitor intervals). All module-level constants in `server.py` and `web/app.py` derive from this at import time.

**`masking_rules.json`** — PII regex patterns and role profiles. Each rule has a `pattern`, `replacement`, and optional `description`. Role profiles map role names to lists of rule keys to apply. Admin profile is empty (no masking). Roles not listed in a profile receive no masking by default.

`get_my_permissions` (available to any authenticated user): returns `{role, permissions[], password_policy}`. The client caches the password policy in `.password_policy.json` next to the binary for offline password validation without a round-trip.



## Shell Commands

The interactive shell runs over a single persistent TLS connection with readline history and tab completion. Tab completion covers all commands and VFS paths. VFS path cache is cleared on every new Tab press so files added by other users appear immediately. The `help` command is role-aware and only shows commands the current role is permitted to run. Commands outside the allowed set are reported as `Unknown command` to avoid revealing which commands exist but are denied.

Full command set:

| Category | Commands |
|---|---|
| Navigation | `ls` (flags: `-a -d -f -g -h -i -l -r -s -t -u -x -1`), `cd`, `tree`, `stat` |
| File management | `mkdir`, `rm`, `mv` |
| File transfer | `send` (file or directory; conflict handling with overwrite prompts), `fetch` (masked by default; `--raw` admin only) |
| ACL | `chmod --role <role> --perm <perm> [--action grant\|revoke]` |
| Admin delivery | `send-to <user> <path> [--unmasked]` |
| Sessions | `active-users` (admin only) |
| Audit | `audit-log` (flags: `--limit`, `--from`, `--to`, `--action`, `--user`, `--archive`, `--verify`, `--out`), `rotate-audit` |
| User management | `add-user`, `remove-user`, `assign-role`, `list-users`, `list-roles` |
| Account | `whoami`, `get-my-permissions`, `change-password`, `reset-password`, `delete-account` |
| Shell | `clear`, `help`, `exit` / `quit` |

See `COMMANDS.md` for the full reference with examples for every command.

`send-to` delivers a VFS file to a user's downloads folder. Masked deliveries are saved as `admin_delivery_<filename>`; unmasked deliveries (admin only) are saved as `admin_delivery_UNMASKED_<filename>`. The delivery is piggybacked on the recipient's next command response.

`audit-log --limit N` returns the newest N entries, displayed oldest-first. `--limit 0` returns all entries with no cap. `--verify` re-derives the entire HMAC chain and reports pass or fail.

Confirmation prompts for `add-user`, `remove-user`, and `assign-role` require a capital `Y`. All `--role` inputs are case-insensitive.


## Disaster Recovery

To recover a failed server and restore all encrypted files, all three of the following are required:

- `server_pkg/certs/master.key` — without this, all `.enc` blobs are permanently unreadable. No other copy exists anywhere.
- `server_pkg/data/efs_tdm.db` — contains the VFS inode tree, user accounts, RBAC, ACLs, and the file UUIDs used as `info` for DEK derivation.
- `server_pkg/data/encrypted/` — the actual AES-256-GCM `.enc` blobs.

TLS keys (`key.pem`, `cert.pem`) are not needed to recover file data. They can be regenerated with `bash scripts/generate_certs.sh`. After regenerating the cert, rebuild and redistribute the compiled binary because `cert.pem` is pinned at compile time.

Audit archives (`data/audit_*.db`) are not needed for file recovery but should be retained for compliance and HMAC chain continuity across rotation boundaries.

**Master key via environment variable**: for containerized or CI deployments where writing secrets to disk is not desired, set `EFS_MASTER_KEY` to a 64-character hex string (32 bytes). This takes precedence over `certs/master.key`.

**Master key rotation** (no built-in command; manual procedure):
1. Download all VFS files while the old server is running.
2. Stop the server.
3. Delete or replace `certs/master.key` (or unset `EFS_MASTER_KEY`).
4. Start the server; a new random master key is generated.
5. Re-upload all files; they are re-encrypted under new DEKs.
6. Securely destroy the old key material.



## Building the Binary

The client is compiled to a standalone binary using Nuitka `--standalone`. This bundles Python and all dependencies so end users need no Python installation.

```bash
# Linux
bash scripts/build_client.sh
```

Output at `portable_client/`:
```
portable_client/
  EFS          <- shell launcher (what users run)
  libs/
    EFS_bin    <- compiled Nuitka binary
    *.so       <- all Python extension modules and system libraries
    bcrypt/
    cryptography/
```

```cmd
# Windows (run from project root in cmd)
scripts\build_client_win.bat
```

Output at `portable_client_win/`:
```
portable_client_win/
  EFS.bat      <- cmd launcher
  libs/
    EFS_bin.exe  <- compiled Nuitka binary
    *.dll, *.pyd <- all bundled Windows libraries
    bcrypt/
    cryptography/
```

See `WIN_BUILD_REQUIREMENTS.txt` for Windows prerequisites (Python 3.13, C compiler, Nuitka).

Key implementation notes for the compiled binary:

- Built with `--standalone` rather than `--onefile` because Nuitka 4.0.7 + Python 3.13 segfaults when `cryptography._rust.so` is extracted to a temp directory by the onefile bootstrap.
- `web-login` uses a hand-rolled `_https_get()` via raw `ssl`+`socket` instead of `urllib`/`http.cookiejar` to avoid a separate Nuitka-compiled `datetime` segfault.
- Linux path resolution uses `/proc/self/exe` so `config.json`, `certs/`, and `downloads/` always land in the correct location regardless of working directory.
- Windows path resolution uses `sys.argv[0]` because Nuitka on Windows sets `sys.executable` to a Python shim rather than the actual binary.
- The `login` command segfaults on both platforms due to a `getpass`/`termios` interaction with the Nuitka runtime. Use `web-login` instead.
- Tab completion on Windows requires `pyreadline3`. The shell falls back gracefully if it is not present.



## Sample Files

Synthetic PII files in `server_pkg/data/sample/` generated by `scripts/generate_samples.py` using Faker with a deterministic seed (42). Each file contains realistic SSNs, emails, phone numbers, and credit card numbers for testing masking against different formats.

| File | Format | Masking path |
|---|---|---|
| `employees.csv` | CSV | stdlib csv, cell-level |
| `notes.txt` | Plain text | Full-string regex |
| `employees_dump.sql` | SQL | Full-string regex |
| `report.pdf` | PDF (text layer) | PyMuPDF redaction annotations |
| `report_scanned.pdf` | PDF (image-based) | OCR path via pytesseract + Pillow |
| `employees.xlsx` | XLSX | openpyxl, cell-level |
| `report.docx` | DOCX | python-docx, paragraph/table/header level |
| `report.odt` | ODT | odfpy, paragraph level |
| `employees.ods` | ODS | odfpy, cell level |
| `report.odp` | ODP | odfpy, text frame level |
| `report.pptx` | PPTX | python-pptx, shape text frame level |
