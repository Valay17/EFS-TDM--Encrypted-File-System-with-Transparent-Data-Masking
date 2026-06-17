#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CLIENT_PKG="$PROJECT_ROOT/client_pkg"
PORTABLE="$PROJECT_ROOT/portable_client"

cd "$CLIENT_PKG"

# client/client.py is the single entry point; file I/O helpers are inlined (no file_handler.py)
python -m nuitka \
    --standalone \
    --output-filename=EFS_bin \
    --output-dir=compiled_binary \
    --include-package=cryptography \
    --include-package=bcrypt \
    --include-module=readline \
    --nofollow-import-to=pytest \
    --nofollow-import-to=numpy \
    --nofollow-import-to=PIL \
    --nofollow-import-to=pandas \
    --nofollow-import-to=flask \
    client/client.py

echo ""
echo "Syncing to portable_client/ ..."

# Preserve config.json if it exists (lives in libs/ next to the binary)
if [ -f "$PORTABLE/libs/config.json" ]; then
    cp "$PORTABLE/libs/config.json" /tmp/efs_config_backup.json
fi

# Wipe and replace portable_client contents with fresh build
rm -rf "$PORTABLE"
mkdir -p "$PORTABLE/libs"

# Move everything from dist into libs/
cp -r "$CLIENT_PKG/compiled_binary/client.dist/." "$PORTABLE/libs/"

# Patch RPATH on all .so and lib*.so.* inside libs/ so they find each other
find "$PORTABLE/libs" -name "*.so" -o -name "*.so.*" | while read -r f; do
    patchelf --set-rpath '$ORIGIN:$ORIGIN/..:$ORIGIN/../..' "$f" 2>/dev/null || true
done

# Patch the compiled binary itself to find everything in libs/
patchelf --set-rpath '$ORIGIN' "$PORTABLE/libs/EFS_bin"

# Write the launcher script
cat > "$PORTABLE/EFS" << 'LAUNCHER'
#!/bin/sh
DIR="$(cd "$(dirname "$0")" && pwd)"
export LD_LIBRARY_PATH="$DIR/libs:$LD_LIBRARY_PATH"
exec "$DIR/libs/EFS_bin" "$@"
LAUNCHER
chmod +x "$PORTABLE/EFS"

# Restore config.json into libs/ — certs/ and downloads/ are auto-created on first use
if [ -f /tmp/efs_config_backup.json ]; then
    cp /tmp/efs_config_backup.json "$PORTABLE/libs/config.json"
    rm /tmp/efs_config_backup.json
fi

echo "Done. Launcher at: portable_client/EFS  |  Binary at: portable_client/libs/EFS_bin"

# Write a template config.json in libs/ if one was not restored from backup.
# Edit this file to point the binary at your server before distributing.
CONFIG="$PORTABLE/libs/config.json"
if [ ! -f "$CONFIG" ]; then
    cat > "$CONFIG" << 'CONFIG_EOF'
{
    "host": "127.0.0.1",
    "port": 9999,
    "cert": null,
    "downloads_dir": null
}
CONFIG_EOF
    echo "Template config.json written to portable_client/libs/config.json"
    echo ""
    echo "  host          -- server hostname or IP (run: ./EFS configure --host <host>)"
    echo "  port          -- server port           (run: ./EFS configure --port <port>)"
    echo "  cert          -- path to server cert.pem (null = TOFU on first connect)"
    echo "  downloads_dir -- override download folder (null = portable_client/downloads/)"
fi
