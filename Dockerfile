# syntax=docker/dockerfile:1
# ---------------------------------------------------------------------------
# Multi-stage build: compile the web console, then a slim Python runtime.
# NOTE: this image is for the API/console and *software* modules (Bluetooth
# over D-Bus, Wi-Fi tooling, firmware analysis). Physical GPIO/SPI/UART rig
# control should run natively on the Raspberry Pi (see deploy/).
# ---------------------------------------------------------------------------
FROM node:20-alpine AS web
WORKDIR /web
COPY web/package.json web/package-lock.json* ./
RUN npm install --no-audit --no-fund
COPY web/ ./
RUN npm run build

FROM python:3.12-slim AS runtime
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

# Runtime tools used by modules (kept minimal; extend as needed).
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap openssl tcpdump tshark bluez bluez-tools \
        binutils file \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY backend/ ./backend/
RUN pip install -e .

COPY --from=web /web/dist ./web/dist

ENV C3I_HOST=0.0.0.0 C3I_PORT=8080 C3I_DATA_DIR=/data
VOLUME ["/data"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/api/v1/health')"

WORKDIR /app/backend
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
