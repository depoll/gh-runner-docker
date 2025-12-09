FROM python:3.11-slim

# Install Docker CLI
RUN apt-get update && apt-get install -y \
    docker.io \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Note: This server uses only Python standard library modules (no external dependencies)

# Copy application
COPY webhook_server.py .

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

EXPOSE 8080

CMD ["python", "-u", "webhook_server.py"]
