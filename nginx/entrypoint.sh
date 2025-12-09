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
    
    echo "ACME module will automatically obtain and renew certificates"
else
    echo "HTTP mode: WEBHOOK_DOMAIN or LETSENCRYPT_EMAIL not set"
    # Use HTTP-only config
    rm -f /etc/nginx/templates/default.conf.template 2>/dev/null || true
    mv /etc/nginx/templates/default-http.conf.template /etc/nginx/templates/default.conf.template 2>/dev/null || true
fi

# Run the standard nginx entrypoint
exec /docker-entrypoint.sh "$@"
