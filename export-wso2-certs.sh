#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# export-wso2-certs.sh
#
# Re-generates self-signed TLS certificates for WSO2 IS and WSO2 APIM with
# extended SANs (localhost, host.docker.internal, 127.0.0.1), imports them
# back into the WSO2 keystores, cross-imports into each product's client
# truststore, and copies the certs into config/ so Inferno trusts them.
#
# Usage:
#   ./export-wso2-certs.sh <IS_HOME> <APIM_HOME>
#
# Example:
#   ./export-wso2-certs.sh \
#     /path/to/wso2is-7.3.0 \
#     /path/to/wso2am-4.6.0
# ---------------------------------------------------------------------------

set -euo pipefail

# ---- colours ---------------------------------------------------------------
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
die()   { error "$*"; exit 1; }

require_cmd() { command -v "$1" &>/dev/null || die "'$1' is required but not found in PATH."; }

# ---- argument parsing ------------------------------------------------------

usage() {
    echo "Usage: $0 <IS_HOME> <APIM_HOME>"
    echo ""
    echo "  IS_HOME    Path to WSO2 Identity Server home directory"
    echo "  APIM_HOME  Path to WSO2 API Manager home directory"
    echo ""
    echo "Options:"
    echo "  -h, --help   Show this help message"
    exit 0
}

[[ "${1:-}" == "-h" || "${1:-}" == "--help" ]] && usage
[[ $# -lt 2 ]] && { error "Missing arguments."; echo ""; usage; }

IS_HOME="${1%/}"
APIM_HOME="${2%/}"

[[ -d "$IS_HOME"   ]] || die "IS_HOME directory not found: $IS_HOME"
[[ -d "$APIM_HOME" ]] || die "APIM_HOME directory not found: $APIM_HOME"

require_cmd keytool
require_cmd openssl
require_cmd python3

# ---- paths -----------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="$SCRIPT_DIR/config"
[[ -d "$CONFIG_DIR" ]] || die "config/ directory not found at: $CONFIG_DIR"

# SANs included in every re-generated cert
SANS="DNS:localhost,DNS:host.docker.internal,IP:127.0.0.1"

# ---- TOML parser -----------------------------------------------------------

toml_get() {
    local file="$1" section="$2" key="$3"
    python3 - "$file" "$section" "$key" <<'PYEOF'
import sys, re
path, section, key = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(path).read()
pat = r'^\[' + re.escape(section) + r'\](.*?)(?=^\[|\Z)'
m = re.search(pat, text, re.MULTILINE | re.DOTALL)
if not m:
    sys.exit(0)
block = m.group(1)
for line in block.splitlines():
    km = re.match(r'^\s*' + re.escape(key) + r'\s*=\s*"?([^"#\n]*)"?\s*$', line)
    if km:
        print(km.group(1).strip())
        break
PYEOF
}

detect_keystore() {
    local product_home="$1"
    local toml="$product_home/repository/conf/deployment.toml"
    [[ -f "$toml" ]] || die "deployment.toml not found at: $toml"

    local file_name password ks_alias store_type

    for section in "keystore.tls" "keystore.primary"; do
        file_name=$(toml_get "$toml" "$section" "file_name")
        [[ -n "$file_name" ]] && {
            password=$(toml_get   "$toml" "$section" "password")
            ks_alias=$(toml_get   "$toml" "$section" "alias")
            store_type=$(toml_get "$toml" "$section" "type")
            break
        }
    done

    [[ -z "$file_name"  ]] && file_name="wso2carbon.jks"
    [[ -z "$password"   ]] && password="wso2carbon"
    [[ -z "$ks_alias"   ]] && ks_alias="wso2carbon"
    [[ -z "$store_type" ]] && {
        case "${file_name##*.}" in
            p12|pfx) store_type="PKCS12" ;;
            *)       store_type="JKS"    ;;
        esac
    }

    echo "${file_name}|${password}|${ks_alias}|${store_type}"
}

# ---- re-generate a self-signed cert with extended SANs ---------------------
# Extracts the original private key, generates a new self-signed cert with
# the same subject but extended SANs, imports it back into the keystore.
#
# Args: label ks_path ks_pass ks_alias ks_type out_cert
resign_and_import() {
    local label="$1"
    local ks_path="$2"
    local ks_pass="$3"
    local ks_alias="$4"
    local ks_type="$5"
    local out_cert="$6"

    local tmpdir
    tmpdir=$(mktemp -d)
    trap "rm -rf '$tmpdir'" RETURN

    local orig_p12="$tmpdir/orig.p12"
    local server_key="$tmpdir/server.key"
    local new_cert="$tmpdir/new.crt"
    local new_p12="$tmpdir/new.p12"
    local ext_file="$tmpdir/ext.cnf"

    info "Processing $label ..."

    local ks_backup="${ks_path}.bak"

    # Back up the original keystore — all keytool operations run on the
    # backup copy so the live file is untouched until the final replace,
    # avoiding JKS brute-force lockout from failed attempts.
    cp "$ks_path" "$ks_backup"

    # 1. Export backup → PKCS12 (single keytool call on the backup)
    keytool -importkeystore \
        -srckeystore   "$ks_backup" \
        -srcstoretype  "$ks_type" \
        -srcstorepass  "$ks_pass" \
        -srckeypass    "$ks_pass" \
        -srcalias      "$ks_alias" \
        -destkeystore  "$orig_p12" \
        -deststoretype PKCS12 \
        -deststorepass tmppass \
        -destalias     "$ks_alias" \
        -noprompt 2>/dev/null \
        || { cp "$ks_backup" "$ks_path"; die "keytool export failed for $label"; }

    # 2. Extract private key from PKCS12
    openssl pkcs12 \
        -in "$orig_p12" -nocerts -nodes \
        -passin pass:tmppass \
        -out "$server_key" 2>/dev/null \
        || die "Private key extraction failed for $label"

    # 3. Read original subject from the exported PKCS12
    local orig_subj
    orig_subj=$(openssl pkcs12 -in "$orig_p12" -nokeys -passin pass:tmppass 2>/dev/null \
        | openssl x509 -noout -subject 2>/dev/null \
        | sed 's/subject=//' \
        | python3 -c "
import sys, re
dn = sys.stdin.read().strip()
parts = [p.strip() for p in re.split(r',\s*(?=[A-Z]+=)', dn)]
print('/' + '/'.join(parts))
")

    # 4. Build OpenSSL config for self-signed cert with SANs
    cat > "$ext_file" <<EOF
[req]
distinguished_name = dn
x509_extensions    = v3_req
prompt             = no

[dn]
$(echo "$orig_subj" | tr '/' '\n' | grep '=' | sed 's/^//')

[v3_req]
subjectAltName  = ${SANS}
keyUsage        = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
basicConstraints = CA:FALSE
EOF

    # 5. Generate new self-signed cert using the original private key
    openssl req -new -x509 \
        -key     "$server_key" \
        -out     "$new_cert" \
        -days    1825 \
        -config  "$ext_file" \
        2>/dev/null \
        || die "Self-signed cert generation failed for $label"

    local new_subj new_expiry new_sans
    new_subj=$(openssl x509  -noout -subject -in "$new_cert" 2>/dev/null | sed 's/subject=//')
    new_expiry=$(openssl x509 -noout -enddate -in "$new_cert" 2>/dev/null | sed 's/notAfter=//')
    new_sans=$(openssl x509  -noout -text   -in "$new_cert" 2>/dev/null \
        | grep -A1 "Subject Alternative Name" | tail -1 | xargs)

    info "  Subject : $new_subj"
    info "  SANs    : $new_sans"
    info "  Expires : $new_expiry"

    # 6. Pack new self-signed cert + original key into PKCS12
    openssl pkcs12 -export \
        -in     "$new_cert" \
        -inkey  "$server_key" \
        -out    "$new_p12" \
        -name   "$ks_alias" \
        -passout pass:tmppass 2>/dev/null \
        || die "PKCS12 packing failed for $label"

    # 7. Build replacement keystore from backup, swap only the target alias
    local tmp_ks="$tmpdir/new_keystore.${ks_path##*.}"
    cp "$ks_backup" "$tmp_ks"

    keytool -delete \
        -keystore  "$tmp_ks" \
        -storetype "$ks_type" \
        -storepass "$ks_pass" \
        -alias     "$ks_alias" \
        -noprompt 2>/dev/null || true

    keytool -importkeystore \
        -srckeystore   "$new_p12" \
        -srcstoretype  PKCS12 \
        -srcstorepass  tmppass \
        -srckeypass    tmppass \
        -srcalias      "$ks_alias" \
        -destkeystore  "$tmp_ks" \
        -deststoretype "$ks_type" \
        -deststorepass "$ks_pass" \
        -destkeypass   "$ks_pass" \
        -destalias     "$ks_alias" \
        -noprompt 2>/dev/null \
        || { cp "$ks_backup" "$ks_path"; die "keytool import failed for $label"; }

    # 8. Atomically replace the live keystore
    cp "$tmp_ks" "$ks_path"

    cp "$new_cert" "$out_cert"
    info "  Imported back into : $ks_path"
    info "  Backup retained at : $ks_backup"
    info "  Cert saved to      : $out_cert"
}

# ---- import a cert into a truststore ---------------------------------------
# Removes any existing entry for the alias then re-imports.
#
# Args: label ts_path ts_pass ts_type alias cert_file
import_to_truststore() {
    local label="$1"
    local ts_path="$2"
    local ts_pass="$3"
    local ts_type="$4"
    local ts_alias="$5"
    local cert_file="$6"

    [[ -f "$ts_path"   ]] || { warn "Truststore not found, skipping: $ts_path"; return; }
    [[ -f "$cert_file" ]] || { warn "Cert not found, skipping: $cert_file"; return; }

    keytool -delete \
        -keystore  "$ts_path" \
        -storetype "$ts_type" \
        -storepass "$ts_pass" \
        -alias     "$ts_alias" \
        -noprompt 2>/dev/null || true

    keytool -import \
        -keystore  "$ts_path" \
        -storetype "$ts_type" \
        -storepass "$ts_pass" \
        -alias     "$ts_alias" \
        -file      "$cert_file" \
        -noprompt 2>/dev/null \
        && info "  Imported into $label truststore (alias: $ts_alias)" \
        || warn "  Failed to import into $label truststore: $ts_path"
}

# ---- main ------------------------------------------------------------------

# Step 1: detect keystores
info "Detecting IS keystore configuration ..."
IS_KS_INFO=$(detect_keystore "$IS_HOME")
IS_KS_FILE=$(echo  "$IS_KS_INFO" | cut -d'|' -f1)
IS_KS_PASS=$(echo  "$IS_KS_INFO" | cut -d'|' -f2)
IS_KS_ALIAS=$(echo "$IS_KS_INFO" | cut -d'|' -f3)
IS_KS_TYPE=$(echo  "$IS_KS_INFO" | cut -d'|' -f4)
IS_KS_PATH="$IS_HOME/repository/resources/security/$IS_KS_FILE"
[[ -f "$IS_KS_PATH" ]] || die "IS keystore not found: $IS_KS_PATH"
info "  $IS_KS_PATH (alias: $IS_KS_ALIAS, type: $IS_KS_TYPE)"

info "Detecting APIM keystore configuration ..."
APIM_KS_INFO=$(detect_keystore "$APIM_HOME")
APIM_KS_FILE=$(echo  "$APIM_KS_INFO" | cut -d'|' -f1)
APIM_KS_PASS=$(echo  "$APIM_KS_INFO" | cut -d'|' -f2)
APIM_KS_ALIAS=$(echo "$APIM_KS_INFO" | cut -d'|' -f3)
APIM_KS_TYPE=$(echo  "$APIM_KS_INFO" | cut -d'|' -f4)
APIM_KS_PATH="$APIM_HOME/repository/resources/security/$APIM_KS_FILE"
[[ -f "$APIM_KS_PATH" ]] || die "APIM keystore not found: $APIM_KS_PATH"
info "  $APIM_KS_PATH (alias: $APIM_KS_ALIAS, type: $APIM_KS_TYPE)"

IS_CERT="$CONFIG_DIR/wso2is.crt"
APIM_CERT="$CONFIG_DIR/wso2apim.crt"

IS_TS_PATH="$IS_HOME/repository/resources/security/client-truststore.p12"
APIM_TS_PATH="$APIM_HOME/repository/resources/security/client-truststore.jks"

# Step 2: re-generate self-signed certs with extended SANs and import back
resign_and_import "WSO2 IS"   "$IS_KS_PATH"   "$IS_KS_PASS"   "$IS_KS_ALIAS"   "$IS_KS_TYPE"   "$IS_CERT"
info "Waiting before processing APIM keystore ..."
sleep 30
resign_and_import "WSO2 APIM" "$APIM_KS_PATH" "$APIM_KS_PASS" "$APIM_KS_ALIAS" "$APIM_KS_TYPE" "$APIM_CERT"

# Step 3: cross-import certs into each product's client truststore
# IS trusts APIM cert; APIM trusts IS cert; each trusts its own cert for
# internal calls (e.g. IS calling its own 9443 endpoint).
info "Updating client truststores ..."
import_to_truststore "WSO2 IS (own cert)"   "$IS_TS_PATH"   "wso2carbon" "PKCS12" "wso2is"   "$IS_CERT"
import_to_truststore "WSO2 IS (APIM cert)"  "$IS_TS_PATH"   "wso2carbon" "PKCS12" "wso2apim" "$APIM_CERT"
import_to_truststore "WSO2 APIM (own cert)" "$APIM_TS_PATH" "wso2carbon" "JKS"    "wso2apim" "$APIM_CERT"
import_to_truststore "WSO2 APIM (IS cert)"  "$APIM_TS_PATH" "wso2carbon" "JKS"    "wso2is"   "$IS_CERT"

# Step 4: update local_ssl_trust.rb to trust individual certs
SSL_TRUST="$SCRIPT_DIR/lib/local_ssl_trust.rb"
[[ -f "$SSL_TRUST" ]] || die "lib/local_ssl_trust.rb not found at: $SSL_TRUST"

sed -i.bak "s|'config/local-ca.crt'|'config/wso2is.crt', 'config/wso2apim.crt'|" "$SSL_TRUST" \
    && rm -f "$SSL_TRUST.bak"

if ! grep -q "wso2is.crt" "$SSL_TRUST"; then
    warn "Could not auto-update lib/local_ssl_trust.rb."
    warn "Manually set trusted_certs to include 'config/wso2is.crt' and 'config/wso2apim.crt'."
fi

# Step 5: clean up old CA files if present (no longer needed)
rm -f "$CONFIG_DIR/local-ca.crt" "$CONFIG_DIR/local-ca.key" "$CONFIG_DIR/local-ca.srl"

# ---- summary ---------------------------------------------------------------

echo ""
info "Done."
echo ""
echo "  WSO2 IS   cert → $IS_CERT"
echo "  WSO2 APIM cert → $APIM_CERT"
echo ""
info "SANs in new certs : $SANS"
info "Inferno trusts    : config/wso2is.crt, config/wso2apim.crt (individual self-signed certs)"
echo ""
warn "Restart WSO2 IS and APIM to present the new certificates."
info "Then restart Inferno: docker compose restart inferno worker"
