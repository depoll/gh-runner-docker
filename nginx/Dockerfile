# nginx with native ACME module for automatic Let's Encrypt certificates
#
# This image uses nginx 1.29+ with the ngx_http_acme_module for automatic
# certificate management without needing a separate certbot container.
#
# Why a custom Dockerfile?
# The ACME module is not included in the base nginx image and must be installed.
# Once nginx includes it by default, this can be replaced with the official image.

FROM nginx:1.29-alpine

# Install the ACME module from nginx's official repository
RUN apk add --no-cache \
    curl \
    nginx-module-acme --repository=https://nginx.org/packages/mainline/alpine/v3.22/main/

# Create ACME state directory with secure permissions
RUN mkdir -p /etc/nginx/acme && chmod 700 /etc/nginx/acme

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
