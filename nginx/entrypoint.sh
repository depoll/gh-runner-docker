#!/bin/sh
# Select nginx config based on HTTPS settings
# If WEBHOOK_DOMAIN is set, use HTTPS config with ACME; otherwise use HTTP-only

set -e

if [ -n "$WEBHOOK_DOMAIN" ] && [ -n "$LETSENCRYPT_EMAIL" ]; then
    echo "HTTPS mode: Using ACME config for $WEBHOOK_DOMAIN"
    export NGINX_ENVSUBST_TEMPLATE_SUFFIX=".conf.template"
    # Remove HTTP-only template so it's not processed
    rm -f /etc/nginx/templates/default-http.conf.template 2>/dev/null || true
else
    echo "HTTP mode: WEBHOOK_DOMAIN or LETSENCRYPT_EMAIL not set"
    # Use HTTP-only config
    rm -f /etc/nginx/templates/default.conf.template 2>/dev/null || true
    mv /etc/nginx/templates/default-http.conf.template /etc/nginx/templates/default.conf.template 2>/dev/null || true
fi

# Run the standard nginx entrypoint
exec /docker-entrypoint.sh "$@"
