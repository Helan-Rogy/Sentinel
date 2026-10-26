# ==============================================================================
# Multi-Stage Dockerfile for Aegis Sentinel (Root Context)
# Compatible with Render.com, Railway, Fly.io, and Local Docker
# ==============================================================================

# --- Stage 1: Frontend Build ---
FROM node:20-alpine AS frontend-builder
WORKDIR /build

COPY sentinel/dashboard/package*.json ./
RUN npm ci --prefer-offline --no-audit || npm install

COPY sentinel/dashboard/ ./
RUN npm run build

# --- Stage 2: Production Python Backend & Unified HUD ---
FROM python:3.11-slim AS production

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SENTINEL_TOKEN=dev-token \
    SENTINEL_ALLOW_SUSPEND=1 \
    SENTINEL_DB=/app/data/sentinel.db \
    PORT=8000

WORKDIR /app

# Install Python dependencies directly from PyPI (pre-built wheels)
COPY sentinel/pyproject.toml .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir \
    "fastapi>=0.110" \
    "uvicorn[standard]>=0.29" \
    "pydantic>=2.6" \
    "httpx>=0.27" \
    "websockets>=12" \
    "watchdog>=4" \
    "psutil>=5.9"

# Copy backend modules and source code
COPY sentinel/contracts/ ./contracts/
COPY sentinel/analyzers/ ./analyzers/
COPY sentinel/detection/ ./detection/
COPY sentinel/endpoint/ ./endpoint/
COPY sentinel/sandbox/ ./sandbox/
COPY sentinel/export/ ./export/
COPY sentinel/lab/ ./lab/
COPY sentinel/server/ ./server/
COPY sentinel/agents/ ./agents/

# Copy built frontend assets from Stage 1 into dashboard/dist
COPY --from=frontend-builder /build/dist ./dashboard/dist

# Persistent data directory for SQLite database, audit trails, and exports
RUN mkdir -p /app/data /app/sandbox_evidence

EXPOSE 8000

# Native Python healthcheck probe (dynamic port compatible)
HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import os, urllib.request; port = os.getenv('PORT', '8000'); urllib.request.urlopen(f'http://127.0.0.1:{port}/api/health')" || exit 1

# Launch with dynamic PORT support for Render, Railway, and Docker ($PORT is passed automatically)
CMD ["sh", "-c", "python -m uvicorn server.app:app --host 0.0.0.0 --port ${PORT:-8000}"]
