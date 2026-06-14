#!/usr/bin/env bash
#
# Generates a local certificate chain (Root CA -> Intermediate CA -> leaf),
# mirroring how Caddy's internal CA issues certificates.
#
# Following secrets best practice, private keys are kept OUT of the project tree
# (so they are never committed and never packaged into the jar). Material lives
# under the per-user home directory instead:
#
#   ~/.oidcoauth2/certs   server leaf cert (fullchain) + leaf key  <- read by the app
#   ~/.oidcoauth2/ca      Root/Intermediate CA certs + keys        <- used only to issue certs
#
# The app locates the leaf material via ${user.home} at runtime (see
# application.yaml), so there is no hardcoded absolute path and no dependency on
# the current working directory. Override the locations with OIDCOAUTH2_CERT_DIR
# / OIDCOAUTH2_CA_DIR if desired (the app honours OIDCOAUTH2_CERT_DIR too).
#
# Usage:
#   ./generate-certs.sh             # generate certs AND add the Root CA to the System keychain (sudo)
#   ./generate-certs.sh --no-trust  # generate certs only; print the trust command to run later
#
set -euo pipefail

DOMAIN="localhost.apple.com"
CERT_DIR="${OIDCOAUTH2_CERT_DIR:-$HOME/.oidcoauth2/certs}"
CA_DIR="${OIDCOAUTH2_CA_DIR:-$HOME/.oidcoauth2/ca}"

TRUST=1
[ "${1:-}" = "--no-trust" ] && TRUST=0

mkdir -p "$CA_DIR" "$CERT_DIR"
chmod 700 "$CA_DIR" "$CERT_DIR"

echo "==> Generating Root CA"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out "$CA_DIR/rootCA.key"
cat > "$CA_DIR/rootCA.cnf" <<'EOF'
[req]
distinguished_name = dn
x509_extensions    = v3_ca
prompt             = no
[dn]
C  = US
O  = Local Dev
CN = Local Dev Root CA
[v3_ca]
basicConstraints       = critical, CA:true
keyUsage               = critical, keyCertSign, cRLSign
subjectKeyIdentifier   = hash
EOF
openssl req -x509 -new -nodes -key "$CA_DIR/rootCA.key" -sha256 -days 3650 \
  -out "$CA_DIR/rootCA.crt" -config "$CA_DIR/rootCA.cnf"

echo "==> Generating Intermediate CA (signed by Root CA)"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out "$CA_DIR/intermediateCA.key"
openssl req -new -key "$CA_DIR/intermediateCA.key" \
  -subj "/C=US/O=Local Dev/CN=Local Dev Intermediate CA" -out "$CA_DIR/intermediateCA.csr"
cat > "$CA_DIR/intermediateCA.ext" <<'EOF'
[v3_intermediate]
basicConstraints       = critical, CA:true, pathlen:0
keyUsage               = critical, keyCertSign, cRLSign
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always
EOF
openssl x509 -req -in "$CA_DIR/intermediateCA.csr" -CA "$CA_DIR/rootCA.crt" -CAkey "$CA_DIR/rootCA.key" \
  -CAcreateserial -sha256 -days 1825 \
  -extfile "$CA_DIR/intermediateCA.ext" -extensions v3_intermediate \
  -out "$CA_DIR/intermediateCA.crt"

echo "==> Generating leaf certificate for ${DOMAIN} (signed by Intermediate CA)"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$CERT_DIR/${DOMAIN}.key"
chmod 600 "$CERT_DIR/${DOMAIN}.key" "$CA_DIR"/*.key
openssl req -new -key "$CERT_DIR/${DOMAIN}.key" \
  -subj "/C=US/O=Local Dev/CN=${DOMAIN}" -out "$CA_DIR/${DOMAIN}.csr"
cat > "$CA_DIR/${DOMAIN}.ext" <<EOF
[v3_leaf]
basicConstraints       = critical, CA:false
keyUsage               = critical, digitalSignature, keyEncipherment
extendedKeyUsage       = serverAuth
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
subjectAltName         = @alt_names
[alt_names]
DNS.1 = ${DOMAIN}
DNS.2 = localhost
IP.1  = 127.0.0.1
IP.2  = ::1
EOF
# 397 days keeps the leaf within Safari/Chrome's max validity window.
openssl x509 -req -in "$CA_DIR/${DOMAIN}.csr" -CA "$CA_DIR/intermediateCA.crt" -CAkey "$CA_DIR/intermediateCA.key" \
  -CAcreateserial -sha256 -days 397 \
  -extfile "$CA_DIR/${DOMAIN}.ext" -extensions v3_leaf \
  -out "$CA_DIR/${DOMAIN}.leaf.crt"

echo "==> Assembling fullchain (leaf + intermediate)"
cat "$CA_DIR/${DOMAIN}.leaf.crt" "$CA_DIR/intermediateCA.crt" > "$CERT_DIR/${DOMAIN}.crt"

echo "==> Verifying chain"
openssl verify -CAfile "$CA_DIR/rootCA.crt" -untrusted "$CA_DIR/intermediateCA.crt" "$CA_DIR/${DOMAIN}.leaf.crt"

# Tidy up build artifacts (keep CA keys/certs and the server leaf key + fullchain).
rm -f "$CA_DIR/rootCA.cnf" "$CA_DIR/intermediateCA.csr" "$CA_DIR/intermediateCA.ext" \
      "$CA_DIR/${DOMAIN}.csr" "$CA_DIR/${DOMAIN}.ext" "$CA_DIR/${DOMAIN}.leaf.crt" "$CA_DIR"/*.srl

echo
echo "Server material (read by the app) in ${CERT_DIR}:"
echo "  ${DOMAIN}.crt   (fullchain: leaf + intermediate)"
echo "  ${DOMAIN}.key   (server private key)"
echo "CA material (issuing only, never shipped) in ${CA_DIR}:"
echo "  rootCA.crt / rootCA.key, intermediateCA.crt / intermediateCA.key"

if [ "$TRUST" -eq 1 ]; then
  echo
  echo "==> Adding Root CA to the macOS System keychain as a trusted root (sudo password required)"
  sudo security add-trusted-cert -d -r trustRoot \
    -k /Library/Keychains/System.keychain "$CA_DIR/rootCA.crt"
  echo "Root CA trusted. Restart your browser to pick up the new trust setting."
else
  echo
  echo "Skipped keychain trust. To trust the Root CA later, run:"
  echo "  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain \"$CA_DIR/rootCA.crt\""
fi
