# High-Performance Docker image for TheDrunkBots (VPS 8 vCPU / 48 GB RAM + Railway ready)

FROM python:3.12-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    DBUS_SESSION_BUS_ADDRESS=disabled: \
    NODE_OPTIONS=--no-warnings

# System deps for Chromium (headless + Xvfb headed) & OpenSSL AES-GCM
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        fonts-liberation \
        fonts-noto-color-emoji \
        libasound2 \
        libatk-bridge2.0-0 \
        libatk1.0-0 \
        libcups2 \
        libdbus-1-3 \
        libdbus-glib-1-2 \
        libdrm2 \
        libepoxy0 \
        libcloudproviders0 \
        libgbm1 \
        libgtk-3-0 \
        libnspr4 \
        libnss3 \
        libwayland-cursor0 \
        libwayland-egl1 \
        libx11-xcb1 \
        libxcomposite1 \
        libxdamage1 \
        libxrandr2 \
        libxshmfence1 \
        libxss1 \
        libxtst6 \
        xdg-utils \
        xvfb \
        xauth \
        wget \
        curl \
        procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

# Install Chromium that Patchright/Playwright will use + Camoufox stealth Turnstile engine
RUN python -m patchright install chromium \
    || python -m playwright install chromium \
    || true
RUN mkdir -p /var/tmp/cfx_tmp && TMPDIR=/var/tmp/cfx_tmp python -m camoufox fetch && rm -rf /var/tmp/cfx_tmp || true

# Pre-cache YOLO11x reCAPTCHA v2 ONNX model for instant 0ms cold start
RUN curl -sSL "https://huggingface.co/1simo/recaptcha-classification-57k-224/resolve/main/recaptcha_classification_57k_224.onnx" \
    -o /tmp/recaptcha_classification_57k_224.onnx || true

# App source
COPY . .

# Writable sibling dirs for multi-worker browser pool
RUN mkdir -p /app/profile /app/debug \
        /tmp/g2s-profile-w0 /tmp/g2s-profile-w1 /tmp/g2s-profile-w2 /tmp/g2s-profile-w3 \
        /tmp/g2s-profile-w4 /tmp/g2s-profile-w5 /tmp/g2s-profile-w6 /tmp/g2s-profile-w7 \
    && chmod -R 777 /app/profile /app/debug /tmp/g2s-profile-w*

ENV PORT=8080 \
    HOST=0.0.0.0 \
    G2S_HEADLESS=0 \
    G2S_BROWSER_CHANNEL= \
    G2S_PROFILE_DIR=/tmp/g2s-profile \
    G2S_MAX_WORKERS=10 \
    G2S_SOLVER_CONCURRENCY=12 \
    G2S_LOCAL_SOLVER_WORKERS=12 \
    G2S_NO_OPEN=1

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD curl -f http://127.0.0.1:${PORT}/api/health || exit 1

CMD ["python", "server.py"]
