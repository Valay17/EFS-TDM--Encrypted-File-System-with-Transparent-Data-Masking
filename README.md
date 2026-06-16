<div align="center">

<h1> <p>EFS-TDM – Encrypted File System with Transparent Data Masking</p> </h1>
</div>


A Python based secure file storage system built around four ideas that usually get implemented separately: strong encryption, role aware access control, dynamic field level masking, and key material that never touches disk in a recoverable form. EFS-TDM ties them into one TLS secured client server setup with a virtual filesystem, a browser login flow, and an interactive shell.

Most file security tools pick one lane. Encrypt everything and you get strong confidentiality but no way to give an analyst partial access to a file without exposing the whole thing. Lean on RBAC at the application layer and the moment a file leaves that context (a backup, an export, a breach) the access control disappears with it. EFS-TDM tries to close that gap by making masking and access control properties of the file access path itself, not just the application around it. Decryption, masking, and permission checks all happen server side, in memory, per request. The client never sees a key.



## Features

- Encrypts every file with AES-256-GCM. Nonce, tag, and ciphertext are all stored in one `.enc` blob, so tampering with even one byte causes decryption to fail outright rather than silently returning garbage.
- Derives a fresh Data Encryption Key for every file from a Master Key using HKDF. No DEK is ever written anywhere; it is computed when needed and discarded right after use.
- Masks PII (SSNs, emails, credit cards, phone numbers) on the way out the door, with the masking rule applied depending on the requester's role. Thirteen file formats are supported, from CSV and plain text through DOCX, XLSX, the OpenDocument family, PPTX, and PDF (including a hybrid text layer plus OCR path for scanned documents).
- Enforces six roles (Admin, Analyst, Contributor, Viewer, Auditor, Guest), each with a distinct permission set, on top of a per file access control list that supports both "closest entry wins" and "any deny in the chain wins" resolution modes depending on the operation.
- Keeps a virtual filesystem (a Unix style inode tree backed by SQLite) so files can be organized into folders rather than living as a flat pile of UUID named blobs.
- Logs every sensitive action to an audit table where each row is chained to the previous one with an HMAC, so any retroactive edit, deletion, or reordering breaks the chain and gets flagged by a background integrity monitor.
- Offers two ways in: a direct terminal login, or a browser based login page (Flask, HTTPS, CSRF protected) that hands a session token back to the terminal without it ever appearing in a URL.
- Ships as a Nuitka compiled standalone binary for Linux and Windows, so end users do not need a Python install.



## Tech stack

Python 3.13, the `cryptography` library for AES-256-GCM and HKDF, Flask for the web login UI, SQLite in WAL mode for everything persistent, `hashlib.scrypt` for password hashing, PyMuPDF plus pytesseract and Pillow for PDF masking (text layer and OCR paths), and a handful of format specific libraries (openpyxl, xlrd, python-docx, odfpy, python-pptx) covering the rest of the supported formats. The client is compiled to a standalone binary with Nuitka for distribution on Linux and Windows.

## Roles and permissions

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

Auditor is intentionally narrow: it can query and verify the audit log but has zero VFS navigation rights, not even `ls`. That separation exists so a compliance reviewer can audit the system without also being able to read file content.

## Security measures, briefly

A few things worth calling out since they came out of an explicit threat model rather than being bolted on afterward.

The Master Key resolves through a three tier process at startup (environment variable, then `certs/master.key` on disk, then fresh generation with `chmod 600`), and a file that exists but cannot be decoded raises an error instead of silently overwriting itself, which would otherwise orphan every encrypted file. Session tokens use `secrets.token_urlsafe(32)` rather than UUID4, and every comparison involving a token or password hash goes through `hmac.compare_digest` for constant time comparison. The audit log is HMAC chained: each row's hash depends on every field of that row plus the hash of the row before it, so a background daemon thread can catch tampering (including retroactive hash replacement) without anyone needing to run a manual check. TLS is restricted to ECDHE plus AEAD ciphers only, with TLS 1.3 preferred. Regex based masking runs inside a daemon thread with a five second timeout to guard against ReDoS. The root admin, meaning the first account created, cannot be deleted or demoted by anyone, including itself.

## Known limitations

- PDF masking falls back to OCR for image based pages. OCR accuracy on low resolution scans or handwritten content is not guaranteed, and anything the OCR engine misses passes through unmasked.
- The TLS certificate is self signed. Fine for a localhost setup and for the compiled binary's trust on first use model, but it would not satisfy production certificate validation requirements.
- Session state lives in server memory only, so a server restart logs everyone out. Encrypted data is unaffected since the Master Key persists to disk.
- SQLite serializes writes. WAL mode keeps reads unblocked, but a deployment with very heavy concurrent write load would eventually want PostgreSQL instead.
- The masking rule set covers four PII categories tuned for US centric data. Extending it for other jurisdictions just means editing `masking_rules.json`, but the patterns themselves need to be authored by someone who knows the target format.



## Installation

```bash
git clone <repo-url> EFS_TDM
cd EFS_TDM
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Generate TLS certificates (idempotent, skips if they already exist):

```bash
bash scripts/generate_certs.sh
```

This writes `server_pkg/certs/cert.pem` and `key.pem`, and copies the certificate over to `client_pkg/certs/` automatically.

Initialize the database and seed a few accounts:

```bash
cd server_pkg
python3 - <<'EOF'
import sys; sys.path.insert(0, ".")
from core.db import init_db
from server.access_control import add_user
init_db()
# the first Admin account created becomes the root admin and cannot be
# deleted or demoted by anyone, including itself
add_user("admin_1",   "Admin@123",   role="Admin")
add_user("analyst_1", "Analyst@123", role="Analyst")
add_user("guest_1",   "Guest@123",   role="Guest")
print("Done.")
EOF
```

On Linux, OCR based PDF masking needs the Tesseract system binary:

```bash
sudo apt-get install -y tesseract-ocr
```

## Usage

Start the server (Terminal 1):

```bash
cd server_pkg
python -m server.server
```

Log in from a second terminal. The browser flow is the easiest way in: it opens a login page, then hands the session back to the terminal automatically.

```bash
cd client_pkg
python -m client.client web-login
```

Once the shell starts, a typical session looks something like this:

```
EFS:/> mkdir /team
EFS:/> send ../server_pkg/data/sample/employees.csv /team/employees.csv
EFS:/> ls /team
EFS:/> fetch /team/employees.csv        # returns masked content for non Admin roles
EFS:/> stat /team/employees.csv
EFS:/> chmod /team --role Viewer --perm read
EFS:/> audit-log --limit 10
EFS:/> exit
```

The compiled binary (no Python install required) only exposes `web-login`, `shell`, and `configure`. All file operations happen inside the interactive shell once logged in.

```bash
./EFS configure --host <server-ip> --port 8443
./EFS web-login
```



## Additional notes

A separate reference document is included alongside this README covering architecture details, the full command list, and a few other implementation notes that did not belong here. Worth a look if you need the exact database schema, the complete command reference, or a deeper explanation of how a particular module works.

A handful of things are easy to miss on first use: the `login` command segfaults in the compiled binary on both platforms due to a `getpass`/`termios` interaction with the Nuitka runtime, so `web-login` is the only supported way to authenticate from the binary. Tab completion in the shell requires `pyreadline3` on Windows and falls back gracefully if it is not present. Masking rules, role permissions, and most server tunables live in JSON config files under `server_pkg/config/`, so adjusting them does not require touching any code.

## License

You are free to use and modify this software for personal or internal purposes. However, redistribution or public distribution of this software or any modified versions is not permitted without explicit permission.
