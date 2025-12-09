# nginx reverse proxy for webhook controller
#
# IMPORTANT: As of early 2025, nginx does not have a native ACME module in official releases.
# This configuration is prepared for future nginx ACME support (expected in nginx 1.29+).
# 
# For production use TODAY, consider one of these alternatives:
# - Use certbot in a sidecar container
# - Use nginx-proxy with acme-companion
# - Use Caddy (which has built-in ACME)
# - Use an external load balancer with TLS termination
#
# The ACME directives in nginx.conf will work once nginx officially releases ACME support.
# Until then, you may need to manually manage certificates or use HTTP-only mode.

FROM nginx:stable-alpine

# Install curl for health checks
RUN apk add --no-cache curl

# Create directory for certificates (manual or future ACME)
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
