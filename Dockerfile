# PhantomProbe v0.9.3 - Multi-stage Docker Build
# Stage 1: Base with core functionality (lightweight)
FROM python:3.11-slim-bookworm AS phantomprobe-core

LABEL maintainer="Ravel226"
LABEL description="PhantomProbe - Reconnaissance Scanner for Penetration Testing"
LABEL version="0.9.3"

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    nmap \
    dnsutils \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy source code
COPY src/ ./src/
COPY pyproject.toml ./
COPY README.md ./
COPY LICENSE* ./

# Install PhantomProbe with core dependencies only
RUN pip install --no-cache-dir -e "."

# Create non-root user and give it ownership of the reports volume
RUN useradd -m -u 1000 phantomprobe \
    && mkdir -p /app/reports \
    && chown -R phantomprobe:phantomprobe /app
USER phantomprobe

# Expose volume for reports
VOLUME ["/app/reports"]

# Default command
ENTRYPOINT ["phantomprobe"]
CMD ["--help"]


# Stage 2: With dashboard (medium weight)
FROM phantomprobe-core AS phantomprobe-dashboard

USER root

# Install FastAPI & Uvicorn
RUN pip install --no-cache-dir fastapi uvicorn websockets

USER phantomprobe

# Expose dashboard port
EXPOSE 8080

ENV PHANTOMPROBE_DASHBOARD_PORT=8080
ENV PHANTOMPROBE_DASHBOARD_HOST=0.0.0.0


# Stage 3: Full edition with all features (largest)
FROM phantomprobe-core AS phantomprobe-full

USER root

# Shared browser location. Playwright's default is the installing user's
# ~/.cache, so installing as root leaves the browsers unreadable by the
# non-root runtime user and every screenshot fails. Install them somewhere
# both users can reach, and make it world-readable.
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

# Shared libraries Playwright's bundled Chromium links against, plus
# libatomic1 for the Node driver Playwright itself runs on. Without it
# "playwright install" cannot start at all: Playwright 1.65 failed the build
# with "libatomic.so.1: cannot open shared object file".
RUN apt-get update && apt-get install -y --no-install-recommends \
    libatomic1 \
    libglib2.0-0 \
    libnss3 \
    libnspr4 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libdbus-1-3 \
    libxkbcommon0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    libasound2 \
    && rm -rf /var/lib/apt/lists/*

# The Playwright release this image is built and tested with. The library
# list above has to match what that release's Node driver and Chromium link
# against, so a newer one is taken on purpose: raise this, and the Docker job
# in CI builds the image and takes a screenshot to prove the list still fits.
# Raise it regularly, because it also carries the browser's security fixes.
ARG PLAYWRIGHT_VERSION=1.65.2

# The "all" extra already pulls in playwright and requests; the pin narrows
# it to the tested release.
RUN pip install --no-cache-dir -e ".[all]" "playwright==${PLAYWRIGHT_VERSION}" \
    && playwright install chromium \
    && chmod -R a+rX "$PLAYWRIGHT_BROWSERS_PATH"

USER phantomprobe

# Expose dashboard port
EXPOSE 8080

ENV PHANTOMPROBE_DASHBOARD_PORT=8080
ENV PHANTOMPROBE_DASHBOARD_HOST=0.0.0.0


# Default stage is core
FROM phantomprobe-dashboard
