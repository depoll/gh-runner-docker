#!/bin/sh
# Select nginx config based on HTTPS settings
# If WEBHOOK_DOMAIN is set, use HTTPS config with ACME; otherwise use HTTP-only

set -e

if [ -n "$WEBHOOK_DOMAIN" ] && [ -n "$LETSENCRYPT_EMAIL" ]; then
    echo "HTTPS mode: Using native ACME module for $WEBHOOK_DOMAIN"
    echo "Let's Encrypt contact: $LETSENCRYPT_EMAIL"
    export NGINX_ENVSUBST_TEMPLATE_SUFFIX=".template"
    # Remove HTTP-only template so it's not processed
    rm -f /etc/nginx/templates/default-http.conf.template 2>/dev/null || true
    
    # Ensure ACME state directory exists and is writable
    mkdir -p /var/cache/nginx/acme
    chmod 700 /var/cache/nginx/acme

    # Bootstrap: nginx fails hard if ssl_certificate points at non-existent files.
    # The ACME module should replace these later, but we need something present
    # for the first start.
    mkdir -p /etc/nginx/acme
    # ssl_certificate uses variables in our config, so nginx loads certs/keys at handshake
    # from worker processes. Ensure the nginx user can read the bootstrap cert/key.
    chgrp nginx /etc/nginx/acme 2>/dev/null || true
    chmod 750 /etc/nginx/acme || true

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

        # Make readable by nginx worker processes (group nginx)
        chgrp nginx "$KEY_FILE" "$CERT_FILE" 2>/dev/null || true
        chmod 640 "$KEY_FILE" "$CERT_FILE" 2>/dev/null || true
    fi
    
    echo "ACME module will automatically obtain and renew certificates"
else
    echo "HTTP mode: WEBHOOK_DOMAIN or LETSENCRYPT_EMAIL not set"
    # Use HTTP-only config
    rm -f /etc/nginx/templates/default.conf.template 2>/dev/null || true
    mv /etc/nginx/templates/default-http.conf.template /etc/nginx/templates/default.conf.template 2>/dev/null || true
fi

# Run the standard nginx entrypoint
exec /docker-entrypoint.sh "$@"
