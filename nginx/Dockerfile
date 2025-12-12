## syntax=docker/dockerfile:1.7

# nginx reverse proxy for webhook controller with native ACME support
#
# This uses nginx mainline with the ngx_http_acme_module for automatic
# Let's Encrypt certificate management.
#
# Required environment variables:
# - WEBHOOK_DOMAIN: Your domain name (e.g., webhook.example.com)
# - LETSENCRYPT_EMAIL: Email for Let's Encrypt notifications
#
# The ACME module will automatically:
# - Register with Let's Encrypt
# - Obtain certificates for your domain
# - Renew certificates before expiry

# Use official nginx.org mainline image (has matching package repo)
FROM nginx:mainline-bookworm

# Install curl for health checks, openssl for fallback, and gnupg for repo setup
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
    curl \
    openssl \
    gnupg2 \
    ca-certificates \
    && true

# Add nginx.org official repository for dynamic modules
RUN curl -fsSL https://nginx.org/keys/nginx_signing.key | gpg --dearmor -o /usr/share/keyrings/nginx-archive-keyring.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] http://nginx.org/packages/mainline/debian bookworm nginx" > /etc/apt/sources.list.d/nginx.list

# Install the nginx ACME module
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
    nginx-module-acme \
    && true

# Load the ACME module - add to main nginx.conf
RUN sed -i '1i load_module modules/ngx_http_acme_module.so;' /etc/nginx/nginx.conf

# Create directories for ACME state and certificates
RUN mkdir -p /var/cache/nginx/acme /etc/nginx/acme \
    && chmod 700 /var/cache/nginx/acme /etc/nginx/acme

# Copy nginx configuration templates
# nginx automatically processes *.template files from /etc/nginx/templates/
COPY nginx.conf /etc/nginx/templates/default.conf.template
COPY nginx-init.conf /etc/nginx/templates/default-http.conf.template

# Simple entrypoint to select HTTPS vs HTTP config
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 80 443

ENTRYPOINT ["/entrypoint.sh"]
CMD ["nginx", "-g", "daemon off;"]
