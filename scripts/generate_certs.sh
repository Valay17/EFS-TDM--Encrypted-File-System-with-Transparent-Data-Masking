#!/bin/bash
# Generate self-signed TLS certificate and private key for localhost.
# Output:
#   server_pkg/certs/cert.pem  (certificate — also copied to client_pkg/certs/)
#   server_pkg/certs/key.pem   (private key — server only, chmod 600)
#
# Run from project root (EFS_TDM/):
#   bash scripts/generate_certs.sh

set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SERVER_CERTS="$ROOT/server_pkg/certs"
CLIENT_CERTS="$ROOT/client_pkg/certs"

mkdir -p "$SERVER_CERTS" "$CLIENT_CERTS"

CERT="$SERVER_CERTS/cert.pem"
KEY="$SERVER_CERTS/key.pem"

if [ -f "$CERT" ] && [ -f "$KEY" ]; then
    echo "Certificates already exist at $SERVER_CERTS — skipping generation."
    echo "Delete them and re-run to regenerate."
    exit 0
fi

openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 \
    -nodes \
    -keyout "$KEY" \
    -out "$CERT" \
    -subj "/CN=localhost" \
    -addext "subjectAltName=IP:127.0.0.1,DNS:localhost"

chmod 600 "$KEY"
chmod 644 "$CERT"

cp "$CERT" "$CLIENT_CERTS/cert.pem"
chmod 644 "$CLIENT_CERTS/cert.pem"

echo "Generated:"
echo "  Certificate (server): $CERT"
echo "  Private key (server): $KEY"
echo "  Certificate (client): $CLIENT_CERTS/cert.pem"
