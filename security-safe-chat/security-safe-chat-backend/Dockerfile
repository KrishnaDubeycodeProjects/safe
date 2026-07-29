# ── Main FastAPI Backend Dockerfile ──────────────────────────────────────────
FROM python:3.11-slim

# Security: run as non-root
RUN groupadd -r appuser && useradd -r -g appuser appuser

WORKDIR /app

# Install system deps (curl for healthcheck)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python deps first (cache layer)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY app/ ./app/
COPY .env.example .env.example

# Data directory for blog storage
RUN mkdir -p /app/data && chown appuser:appuser /app/data

USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["python", "-m", "uvicorn", "app.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--workers", "4", \
     "--proxy-headers", \
     "--forwarded-allow-ips", "*", \
     "--access-log"]
