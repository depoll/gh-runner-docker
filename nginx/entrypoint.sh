#!/bin/sh
# Select nginx config based on HTTPS settings
# If WEBHOOK_DOMAIN is set, use HTTPS config with ACME; otherwise use HTTP-only

set -e

fix_acme_permissions() {
    # /etc/nginx/acme is a persistent volume; older runs may have created files
    # with restrictive permissions. nginx loads ssl_certificate/ssl_certificate_key
    # at handshake time (worker processes), so ensure readability every startup.
    ACME_DIR="/etc/nginx/acme"
    CERT_FILE="$ACME_DIR/fullchain.pem"
    KEY_FILE="$ACME_DIR/privkey.pem"

    mkdir -p "$ACME_DIR" 2>/dev/null || true

    # Allow nginx worker to traverse the directory.
    chown root:nginx "$ACME_DIR" 2>/dev/null || true
    chmod 750 "$ACME_DIR" 2>/dev/null || true

    # Certificate can be world-readable; private key should be group-readable.
    if [ -e "$CERT_FILE" ]; then
        chown root:nginx "$CERT_FILE" 2>/dev/null || true
        chmod 644 "$CERT_FILE" 2>/dev/null || true
    fi

    if [ -e "$KEY_FILE" ]; then
        chown root:nginx "$KEY_FILE" 2>/dev/null || true
        chmod 640 "$KEY_FILE" 2>/dev/null || true
    fi
}

if [ -n "$WEBHOOK_DOMAIN" ] && [ -n "$LETSENCRYPT_EMAIL" ]; then
    echo "HTTPS mode: Using native ACME module for $WEBHOOK_DOMAIN"
    echo "Let's Encrypt contact: $LETSENCRYPT_EMAIL"
    export NGINX_ENVSUBST_TEMPLATE_SUFFIX=".template"
    # Remove HTTP-only template so it's not processed
    rm -f /etc/nginx/templates/default-http.conf.template 2>/dev/null || true
    
    # Ensure ACME state directory exists and is writable
    mkdir -p /var/cache/nginx/acme
    chmod 700 /var/cache/nginx/acme

    # Ensure the persistent ACME volume is usable by nginx workers.
    fix_acme_permissions

    CERT_FILE="/etc/nginx/acme/fullchain.pem"
    KEY_FILE="/etc/nginx/acme/privkey.pem"

    if [ ! -s "$CERT_FILE" ] || [ ! -s "$KEY_FILE" ]; then
        echo "TLS bootstrap: generating temporary self-signed certificate (will be replaced by ACME when available)"

        rm -f "$CERT_FILE.tmp" "$KEY_FILE.tmp" 2>/dev/null || true

        # Prefer SAN-capable certs; fall back if openssl doesn't support -addext.
        if openssl req -x509 -nodes -newkey rsa:2048 -days 1 \
            -subj "/CN=$WEBHOOK_DOMAIN" \
            -addext "subjectAltName=DNS:$WEBHOOK_DOMAIN" \
            -keyout "$KEY_FILE.tmp" -out "$CERT_FILE.tmp" 2>/dev/null; then
            :
        else
            openssl req -x509 -nodes -newkey rsa:2048 -days 1 \
                -subj "/CN=$WEBHOOK_DOMAIN" \
                -keyout "$KEY_FILE.tmp" -out "$CERT_FILE.tmp"
        fi

        mv "$KEY_FILE.tmp" "$KEY_FILE"
        mv "$CERT_FILE.tmp" "$CERT_FILE"

        # Ensure perms/ownership are correct after writing.
        fix_acme_permissions
    fi

    # Even if certs already existed in the volume, ensure permissions are correct.
    fix_acme_permissions
    
    echo "ACME module will automatically obtain and renew certificates"
else
    echo "HTTP mode: WEBHOOK_DOMAIN or LETSENCRYPT_EMAIL not set"
    # Use HTTP-only config
    rm -f /etc/nginx/templates/default.conf.template 2>/dev/null || true
    mv /etc/nginx/templates/default-http.conf.template /etc/nginx/templates/default.conf.template 2>/dev/null || true
fi

# Run the standard nginx entrypoint
exec /docker-entrypoint.sh "$@"
