# EFS-TDM Command Reference

## Repository Layout

```
EFS_TDM/
├── server_pkg/          # everything that runs on the server
│   ├── server/          # server.py, key_manager.py, access_control.py, audit_logger.py
│   ├── core/            # db.py, encryption.py, masking.py, vfs.py
│   ├── config/          # masking_rules.json, roles.json, server_config.json
│   ├── data/            # efs_tdm.db + data/encrypted/
│   ├── certs/           # cert.pem + key.pem (keep key.pem on server only)
│   └── requirements.txt
├── client_pkg/          # everything that runs on the client
│   ├── client/          # client.py
│   ├── certs/           # cert.pem only (no private key)
│   ├── downloads/       # received files (fetch default output)
│   └── requirements.txt
├── tests/               # full test suite — run from project root
├── scripts/             # generate_certs.sh, generate_samples.py, build scripts
└── conftest.py          # adds server_pkg/ and client_pkg/ to sys.path for tests
```

Server commands run from `server_pkg/`. Client commands run from `client_pkg/`. Tests run from the project root.



## Starting the Server

### Fresh start — wipe everything and seed users

Run from `server_pkg/`:

```bash
rm -f data/efs_tdm.db data/encrypted/*.enc ~/.efs_session

python3 - <<'EOF'
import sys; sys.path.insert(0, ".")
from core.db import init_db
from server.access_control import add_user
init_db()
# The first Admin created (id=1) becomes the root admin.
# The root admin cannot be deleted or demoted by anyone.
# Only the root admin can delete other admin accounts or reset their passwords.
add_user("admin",    "Admin@123",   role="Admin")
add_user("analyst",  "Anal@123",    role="Analyst")
add_user("viewer",   "View@123",    role="Viewer")
add_user("contri",   "Contri@123",  role="Contributor")
add_user("auditor",  "Audi@123",    role="Auditor")
add_user("guest",    "Guest@123",   role="Guest")
print("Done.")
EOF

python -m server.server
```

### DB already exists with users

```bash
cd server_pkg
python -m server.server
```

### DB exists but has no users

```bash
cd server_pkg

python3 - <<'EOF'
import sys; sys.path.insert(0, ".")
from server.access_control import add_user
# First Admin created (id=1) is the root admin — indestructible.
add_user("admin",    "Admin@123",   role="Admin")
add_user("analyst",  "Anal@123",    role="Analyst")
add_user("viewer",   "View@123",    role="Viewer")
add_user("contri",   "Contri@123",  role="Contributor")
add_user("auditor",  "Audi@123",    role="Auditor")
add_user("guest",    "Guest@123",   role="Guest")
print("Done.")
EOF

python -m server.server
```

## Logging In (Client)

Run from `client_pkg/`. The browser flow is recommended — it opens a login page and hands the session back to the terminal automatically, then drops directly into the interactive shell.

```bash
python -m client.client web-login
```

To authenticate via terminal only (no browser):

```bash
python -m client.client login admin
```


## Interactive Shell

After `web-login` the shell starts automatically. To start it manually from `client_pkg/`:

```bash
python -m client.client shell
```

Inside the shell, use commands directly without the `python -m client.client` prefix:

```
EFS:/> list-users
EFS:/> audit-log --limit 10
EFS:/> audit-log --limit 0
EFS:/> whoami
EFS:/> change-password
EFS:/> clear
EFS:/> exit
```

### Navigation and behavior

- Up-arrow cycles through previous commands.
- Tab completion is available for all commands, VFS server paths, and local filesystem paths.
- VFS path cache is cleared on every Tab press — files added by other users appear immediately.
- Only commands permitted for your role appear in tab completion and `help`.
- Paths containing spaces are automatically escaped with `\ ` in completions.
- `exit`, `quit`, `Ctrl+C`, or `Ctrl+D` log out and exit.

### Role-aware help

The `help` command shows only commands your role is permitted to run. Admin sees the full list. Commands outside your role's allowed set are reported as `Unknown command` — the system does not reveal which commands exist but are denied.

### Confirmation prompts

`add-user`, `remove-user`, and `assign-role` require a capital `Y` to confirm. Any other input aborts.

### Role input

All commands that accept `--role` are case-insensitive: `analyst`, `ANALYST`, and `Analyst` all work.

## Password Policy

All passwords must meet:
- At least 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one digit
- At least one special character (e.g. `!`, `@`, `#`, `$`)


## User Management (admin only)

```bash
python -m client.client add-user bob --role Guest
python -m client.client assign-role bob --role Analyst   # immediately revokes bob's active sessions
python -m client.client remove-user bob
python -m client.client list-users
python -m client.client list-roles
```

## Password Management

```bash
# Change your own password (any user — requires current password)
# On success, the shell immediately logs you out. Re-login with the new password.
python -m client.client change-password

# Reset another user's password (admin only — no old password needed)
# Cannot reset your own password this way; use change-password instead.
python -m client.client reset-password bob
```

## Account Info

```bash
python -m client.client whoami
python -m client.client get-my-permissions
```



## Role Permissions

| Operation | Admin | Contributor | Analyst | Viewer | Guest | Auditor |
|---|---|---|---|---|---|---|
| list | Y | Y | Y | Y | Y | N |
| read (masked) | Y | Y | Y | Y | N | N |
| write | Y | Y | N | N | N | N |
| delete (own files) | Y | Y | N | N | N | N |
| mask | Y | N | Y | N | N | N |
| view audit log | Y | N | N | N | N | Y |
| delete (any file) | Y | N | N | N | N | N |
| export raw | Y | N | N | N | N | N |
| manage permissions | Y | N | N | N | N | N |
| manage users | Y | N | N | N | N | N |

Role behavior in brief:
- **Guest** — browse folder and file names only, no content access.
- **Viewer** — read masked content, no write or export.
- **Contributor** — read masked content, write, delete own files.
- **Analyst** — apply masking transformations and read masked content, no write.
- **Auditor** — audit log access only; no VFS navigation (`ls`, `cd`, `tree`, `stat` all denied).
- **Admin** — full access including raw export and user/permission management.



## Role Restrictions in Practice

### Analyst — read masked content, no write

```bash
python -m client.client web-login
# log in as analyst

EFS:/> fetch /team/employees.csv   # works (masked content returned)
EFS:/> send notes.txt              # denied (no write permission)
EFS:/> audit-log                   # denied
EFS:/> help                        # shows only permitted commands
EFS:/> exit
```

### Guest — almost everything denied

```bash
python -m client.client web-login
# log in as guest

EFS:/> fetch /team/employees.csv   # denied (no read permission)
EFS:/> ls /                        # works
EFS:/> help                        # shows ls, cd, tree, stat, whoami only
EFS:/> exit
```

### Viewer — read masked content, no write

```bash
python -m client.client web-login
# log in as viewer

EFS:/> fetch /team/employees.csv             # works (masked content)
EFS:/> fetch /team/employees.csv /tmp/       # saves to /tmp/employees.csv
EFS:/> fetch /team/employees.csv --raw       # denied (no raw export)
EFS:/> send notes.txt                        # denied (no write)
EFS:/> audit-log                             # denied
EFS:/> exit
```

### Contributor — read and write, no raw export

```bash
python -m client.client web-login
# log in as contributor

EFS:/> send data/sample/notes.txt            # works (VFS upload)
EFS:/> fetch /team/notes.txt                 # works (masked content)
EFS:/> fetch /team/notes.txt --raw           # denied (no raw export)
EFS:/> audit-log                             # denied
EFS:/> exit
```

### Auditor — audit log only, no VFS access

```bash
python -m client.client web-login
# log in as auditor

EFS:/> audit-log                                                # works
EFS:/> audit-log --archive audit_2026-03-25_10-00-00.db        # works
EFS:/> audit-log --verify                                       # verify HMAC chain
EFS:/> ls /                                                     # denied (no list permission)
EFS:/> fetch /team/employees.csv                                # denied
EFS:/> list-users                                               # denied
EFS:/> help                                                     # shows audit-log, whoami, change-password, exit
EFS:/> exit
```


## VFS Commands

The virtual filesystem organizes files into directories. The shell prompt shows the current directory: `EFS:/current/path>`.

### Navigation

```
EFS:/> ls                       # list root
EFS:/> ls /docs                 # list /docs
EFS:/> ls -l /docs              # long format
EFS:/> ls -lh /docs             # long format with human-readable sizes
EFS:/> ls -la                   # long format including hidden entries
EFS:/> ls -t                    # sort by creation time
EFS:/> ls -u                    # sort by upload time (files only)
EFS:/> ls -1                    # one entry per line
EFS:/> ls -r                    # reverse sort
EFS:/> ls -i                    # show inode IDs
EFS:/> ls -s                    # show size in 512-byte blocks
EFS:/> ls -g                    # long format, omit owner column
EFS:/> ls -x                    # list across columns
EFS:/> ls -d /docs              # stat /docs itself, not its contents
EFS:/> cd docs                  # change directory
efs:/docs> cd ..                # go up
EFS:/> tree                     # full tree from root
EFS:/> tree /docs               # tree from /docs
EFS:/> stat /docs/report.csv    # file or folder metadata (includes ACL if any are set)
```

### Directory Management

```
EFS:/> mkdir /docs
EFS:/> mkdir /team/reports      # creates parents automatically
EFS:/> rm /docs                 # remove directory (cascades all children)
EFS:/> mv /docs /archive        # move or rename
EFS:/> mv /docs/report.csv /    # move to root
EFS:/> mv /report.csv /docs     # move into existing directory
EFS:/> clear                    # clear the terminal screen
```

### File Upload

Files are encrypted automatically on upload. Each upload produces two audit entries: `send` (the command) and `encrypt` (the per-file encryption).

```
# Upload a single file
EFS:/> send ../server_pkg/data/sample/employees.csv /team/employees.csv
EFS:/> send ../server_pkg/data/sample/notes.txt     # uploads to current VFS directory

# Upload a directory recursively
# All subdirectories and files are uploaded; VFS directories are created automatically.
# Prompts for confirmation before starting (requires capital Y).
EFS:/> send ../server_pkg/data/sample /team/sample
```

**Conflict handling (single file):** if the destination path already exists, the server returns the remote file's metadata. The client shows the remote vs local diff and prompts `Overwrite? [Y/n]`. Requires capital Y.

**Conflict handling (directory):** new files upload immediately; duplicates are batched and shown in a table with remote and local sizes and upload dates. Options: `[O]verwrite all / [S]kip all / [C]hoose for each / [A]bort`. All choices require capital letters.

### File Download

```
# Download with role-based masking applied — saved to downloads/
EFS:/> fetch /team/employees.csv

# Download to a specific local path
EFS:/> fetch /team/employees.csv /tmp/           # saves to /tmp/employees.csv
EFS:/> fetch /team/employees.csv /tmp            # same — existing directory detected
EFS:/> fetch /team/employees.csv /tmp/out.csv    # explicit filename

# Admin only — download without masking
EFS:/> fetch /team/employees.csv --raw
EFS:/> fetch /team/employees.csv --raw /tmp/out.csv
```

### Admin File Delivery

Delivers a VFS file directly to a user's downloads folder. The file is decrypted and masked using the recipient's role before delivery. Delivery is piggybacked on the recipient's next command response.

```
EFS:/> send-to analyst /team/employees.csv              # masked delivery
EFS:/> send-to viewer /reports/q1.csv

# --unmasked: send the raw file without masking (admin only)
EFS:/> send-to analyst /team/employees.csv --unmasked
```

Delivery filenames: masked saves as `admin_delivery_employees.csv`, unmasked saves as `admin_delivery_UNMASKED_employees.csv`.

### Active Sessions (admin only)

```
EFS:/> active-users

# Example output:
# Username    Role         Expires In
# ---------------------------------
# admin       Admin        28m 14s
# analyst     Analyst      12m 05s
```



## ACL Management (admin only)

ACL entries are per-inode and per-role. They inherit up the parent chain. Admin always bypasses ACL checks.

**Resolution modes:**
- **Closest-wins** (fetch, rm): the nearest ancestor with an entry wins. A child grant overrides a parent deny.
- **Deny-wins** (ls, tree): any deny anywhere in the ancestor chain hides the entry and its entire subtree.

```
# Grant Viewer role read access to a file
EFS:/> chmod /team/employees.csv --role Viewer --perm read

# Grant Analyst role read access to a directory (inherited by all children)
EFS:/> chmod /team --role Analyst --perm read

# Grant Contributor role write access to a directory
EFS:/> chmod /team --role Contributor --perm write

# Revoke Viewer read access from a file
# This inserts a deny record — it does not delete the existing grant.
EFS:/> chmod /team/employees.csv --role Viewer --perm read --action revoke

# Lock down a file so only Admin can read it
EFS:/> chmod /private/keys.txt --role Viewer --perm read --action revoke
EFS:/> chmod /private/keys.txt --role Analyst --perm read --action revoke
EFS:/> chmod /private/keys.txt --role Contributor --perm read --action revoke
EFS:/> chmod /private/keys.txt --role Guest --perm read --action revoke

# Role input is case-insensitive
EFS:/> chmod /docs --role viewer --perm read
EFS:/> chmod /docs --role VIEWER --perm read
```

`stat` on any file includes an `acl` section listing permissions set directly on that node. Grants show as `<role>  <perm>` and denies show as `<role>  <perm> (deny)`. The section is omitted if no ACL entries exist on the node.

Available permissions: `read`, `write`, `delete_own`, `delete_any`.

**delete_own vs delete_any:**
- `delete_own`: owner's right to delete their own file. Default is open. An explicit deny on `delete_own` is absolute and cannot be overridden by a `delete_any` grant.
- `delete_any`: right to delete files owned by other users. Default is closed — requires an explicit ACL grant.



## Audit Log

Audit entries are displayed oldest-first. Each column shows: `Timestamp (UTC)  User  Role  Action  Outcome  File`.

Each `send` produces two entries: `send` (the command) and `encrypt` (the per-file encryption). Each carries the full VFS path.

With `--limit N`, the newest N entries are returned (displayed oldest-first within that window). Without `--limit`, the server default of 100 most recent entries applies. Use `--limit 0` for all entries with no cap.

```bash
# Basic queries
python -m client.client audit-log                    # most recent 100 entries
python -m client.client audit-log --limit 10         # most recent 10 entries
python -m client.client audit-log --limit 0          # all entries, no cap
python -m client.client audit-log --action encrypt
python -m client.client audit-log --action login
python -m client.client audit-log --user admin
python -m client.client audit-log --user admin --action login --limit 5
```

Time range filtering (ISO format: `YYYY-MM-DD HH:MM:SS`):

```bash
python -m client.client audit-log --from "2026-03-25 00:00:00" --to "2026-03-25 23:59:59"
python -m client.client audit-log --from "2026-03-25 10:00:00"            # open-ended forward
python -m client.client audit-log --to "2026-03-25 12:00:00"              # open-ended backward
python -m client.client audit-log --from "2026-03-25 10:00:00" --limit 50
```

Save to a file instead of printing to terminal:

```bash
python -m client.client audit-log --out /tmp/audit.txt
python -m client.client audit-log --limit 50 --out /tmp/audit.txt
python -m client.client audit-log --from "2026-03-25 00:00:00" --to "2026-03-25 23:59:59" --out /tmp/audit_today.txt
python -m client.client audit-log --user admin --action encrypt --out /tmp/admin_encrypts.txt
```

Query an archived log file (admin and auditor):

```bash
python -m client.client audit-log --archive audit_2026-03-25_10-00-00.db
python -m client.client audit-log --archive audit_2026-03-25_10-00-00.db --from "2026-03-25 08:00:00"
python -m client.client audit-log --archive audit_2026-03-25_10-00-00.db --from "2026-03-25 08:00:00" --to "2026-03-25 10:00:00" --out /tmp/archive_slice.txt
```

Verify HMAC chain integrity (admin and auditor). Recomputes every `chain_hash` from scratch and reports whether any row has been modified, deleted, or inserted out of order:

```bash
python -m client.client audit-log --verify

# Shell equivalent
EFS:/> audit-log --verify
```


## Audit Log Rotation (admin only)

Rotation archives the current log into a dated file and starts a fresh one. In-flight audit writes queue briefly during rotation; they are not rejected.

```bash
python -m client.client rotate-audit

# Shell equivalents
EFS:/> rotate-audit
EFS:/> audit-log --from "2026-03-25 10:00:00" --to "2026-03-25 11:00:00"
EFS:/> audit-log --archive audit_2026-03-25_10-00-00.db --out /tmp/pre_event.txt
```

### Auto-rotation (server-side, no manual action needed)

Configured in `server_pkg/config/server_config.json` under `audit`:

| Setting | Default | Meaning |
|---|---|---|
| `auto_rotate_max_entries` | 10000 | Rotate when live log exceeds this many entries |
| `auto_rotate_max_days` | 30 | Rotate when oldest entry is older than this many days |
| `retention_max_archives` | 12 | Delete oldest archives beyond this count (0 = keep all) |

A `system` sentinel entry is written to both the old and new log so every rotation is traceable in the audit trail.

### Audit integrity monitor (always running)

The server runs a background daemon thread that automatically verifies the audit log HMAC chain without any admin action.

- **Incremental** (every poll): checks only rows added since the last poll. Fast, O(new rows).
- **Full scan** (every N polls): re-verifies the entire chain from row 1. Catches retroactive hash replacement.

If tampering is detected, a bold red alert banner is sent to all Admin and Auditor terminals on their next command. The alert persists until `rotate-audit` is called.

Configured in `server_config.json` under `audit`:

| Setting | Default | Meaning |
|---|---|---|
| `integrity_check_interval_seconds` | 60 | Seconds between incremental scans |
| `integrity_full_scan_every_n_polls` | 10 | Full scan every N incremental polls |


## Supported Masking Formats

| Format | Extensions | Notes |
|---|---|---|
| CSV | `.csv` | stdlib csv; handles multi-line quoted fields; regex per cell |
| XLSX | `.xlsx` | openpyxl; formatting preserved; regex per cell |
| XLS | `.xls` | xlrd read; output saved as `.xlsx` |
| Plain text | `.txt` `.log` `.tex` `.bib` | Regex on full string |
| SQL dump | `.sql` `.dump` | Regex on full string; SQL keywords unaffected |
| PDF | `.pdf` | Hybrid: text-layer path via PyMuPDF, or OCR path via pytesseract for image-based pages |
| Word | `.docx` | python-docx; paragraphs, tables, headers/footers |
| ODF Writer | `.odt` | odfpy; paragraph text |
| ODF Spreadsheet | `.ods` | odfpy; cell text |
| ODF Presentation | `.odp` | odfpy; slide text frames |
| PowerPoint | `.pptx` | python-pptx; shape text frames across all slides |

**Unsupported formats** (raise an error — convert first):
- `.doc` → convert to `.docx`
- `.ppt` → convert to `.pptx`
- `.rtf` → convert to `.docx` or `.txt`

**Encrypt-only formats** (stored encrypted, masking not applied):
- Images: `.png` `.jpg` `.jpeg` `.gif` `.bmp` `.webp` `.tiff` `.tif` `.heic`
- Video / Audio: `.mp4` `.mkv` `.avi` `.mov` `.wmv` `.mp3` `.wav` `.aac` `.flac` `.ogg` `.m4a`
- Archives: `.zip` `.tar` `.gz` `.bz2` `.xz` `.7z` `.rar`

**PDF OCR note:** when the OCR path is taken, the output is raster-only (no text layer). Redaction is permanent.



## Where Files Are Stored

| Item | Location |
|---|---|
| Encrypted blobs (server) | `server_pkg/data/encrypted/*.enc` |
| Downloads (Python client) | `client_pkg/downloads/` |
| Downloads (Linux binary) | `portable_client/downloads/` |
| Downloads (Windows binary) | `portable_client_win\downloads\` |
| Database (server) | `server_pkg/data/efs_tdm.db` |

The database tracks: `users`, `roles`, `audit_log`, `inodes` (VFS directory tree), `file_meta` (maps VFS inodes to encrypted blob names, stores size and content hash), `acl`, and `deliveries`.

## One-Shot CLI Commands

These work outside the shell, one command per invocation. For development and testing. The compiled binary (`EFS` / `EFS.bat`) only exposes `web-login`, `shell`, and `configure` — all VFS operations are done inside the interactive shell.

```bash
# VFS navigation
python -m client.client ls /
python -m client.client ls /docs
python -m client.client mkdir /docs
python -m client.client stat /docs/report.csv
python -m client.client tree /
python -m client.client rm /docs/old.csv
python -m client.client mv /docs/old.csv /archive/old.csv
python -m client.client send data/sample/employees.csv /team/employees.csv
python -m client.client chmod /docs --role Viewer --perm read
python -m client.client chmod /docs --role Viewer --perm read --action revoke

# Note: fetch is shell-only
```


## Running Tests

Tests spin up their own server and database — no running server needed.

```bash
# Full test suite
python -m pytest tests/ -v

# By module
python -m pytest tests/test_masking.py -v
python -m pytest tests/test_key_manager.py -v
python -m pytest tests/test_rbac.py -v
python -m pytest tests/test_encryption.py -v
python -m pytest tests/test_audit_logger.py -v
python -m pytest tests/test_integration.py -v
python -m pytest tests/test_web_login.py -v
python -m pytest tests/test_vfs.py -v
python -m pytest tests/test_security.py -v
python -m pytest tests/test_concurrent.py -v
python -m pytest tests/test_stress.py -v
python -m pytest tests/test_binary.py -v   # requires compiled binary; auto-skipped if absent
```


## Shutdown and Cleanup

```bash
# Stop the server (Ctrl+C in the server terminal, or from any terminal)
kill $(pgrep -f "server.server")

# Clear session file
rm -f ~/.efs_session

# Full reset — wipe DB and encrypted files
rm -f server_pkg/data/efs_tdm.db server_pkg/data/encrypted/*.enc ~/.efs_session

# Regenerate sample files
python scripts/generate_samples.py
# Optional flags: --count 20 --output-dir server_pkg/data/sample

# Regenerate TLS certificates (idempotent — skips if both files already exist)
bash scripts/generate_certs.sh
# After regenerating: rebuild the binary (client pins cert.pem at compile time)
```


## Key Management and Disaster Recovery

### Key types

| Key | Location | Purpose |
|---|---|---|
| Master Key (MK) | `server_pkg/certs/master.key` | Root of all file encryption (HKDF source). chmod 600. |
| TLS Private Key | `server_pkg/certs/key.pem` | TLS handshake server identity. chmod 600. |
| TLS Certificate | `server_pkg/certs/cert.pem` | Client verifies server; pinned in binary. |
| DEK | Never stored | AES-256-GCM key for one file. Derived on demand, discarded after use. |

The master key is the most critical artifact. All DEKs are derived deterministically from it via HKDF-SHA256. Lose the master key and all encrypted files are permanently unrecoverable.

### Minimum backup set for file recovery

All three are required:

```
server_pkg/certs/master.key        # without this, all .enc blobs are unreadable forever
server_pkg/data/efs_tdm.db         # VFS tree, users, ACLs, file UUIDs (needed for DEK derivation)
server_pkg/data/encrypted/         # the .enc blobs
```

Optional but recommended:

```
server_pkg/certs/key.pem           # avoids cert regen + binary rebuild on restore
server_pkg/certs/cert.pem
server_pkg/data/audit_*.db         # audit archives for compliance and chain continuity
```

### Master key via environment variable

For containerized or CI deployments where writing secrets to disk is not desired:

```bash
export EFS_MASTER_KEY="<64 hex chars>"   # 32 bytes, hex-encoded
python -m server.server --host 0.0.0.0 --port 9999
```

`EFS_MASTER_KEY` takes precedence over `certs/master.key` when set.

### Master key rotation (manual — no built-in command)

1. Download all VFS files via `fetch` while the old server is running.
2. Stop the server.
3. Delete or replace `certs/master.key` (or unset `EFS_MASTER_KEY`).
4. Start the server — a new random master key is generated on first start.
5. Re-upload all files via `send` — they are re-encrypted under new DEKs.
6. Securely destroy the old key material.

### TLS certificate lifecycle

Regenerate only when:
- First deployment on a new machine (files do not exist yet).
- Deploying to a different hostname (edit the SAN in `scripts/generate_certs.sh` first).
- Intentional cert rotation for security reasons.

After regenerating, rebuild and redistribute the binary — `cert.pem` is compiled in and the binary will reject a new cert until rebuilt.

### Utilities

```bash
# Check if server is running on a given port
lsof -i :9999

# Kill anything stuck on the server port
kill $(lsof -t -i :9999)
```
