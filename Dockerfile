# PhantomProbe v0.8.0 - Multi-stage Docker Build
# Stage 1: Base with core functionality (lightweight)
FROM python:3.11-slim-bookworm as phantomprobe-core

LABEL maintainer="Ravel226"
LABEL description="PhantomProbe - Reconnaissance Scanner for Penetration Testing"
LABEL version="0.8.0"

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
COPY packages/ ./packages/
COPY src/ ./src/
COPY pyproject.toml ./
COPY README.md ./
COPY LICENSE* ./

# Install PhantomProbe with core dependencies only
RUN pip install --no-cache-dir -e "."

# Create non-root user
RUN useradd -m -u 1000 phantomprobe
USER phantomprobe

# Expose volume for reports
VOLUME ["/app/reports"]

# Default command
ENTRYPOINT ["phantomprobe"]
CMD ["--help"]


# Stage 2: With dashboard (medium weight)
FROM phantomprobe-core as phantomprobe-dashboard

USER root

# Install FastAPI & Uvicorn
RUN pip install --no-cache-dir fastapi uvicorn websockets

USER phantomprobe

# Expose dashboard port
EXPOSE 8080

ENV PHANTOMPROBE_DASHBOARD_PORT=8080
ENV PHANTOMPROBE_DASHBOARD_HOST=0.0.0.0


# Stage 3: Full edition with all features (largest)
FROM phantomprobe-core as phantomprobe-full

USER root

# Install Playwright dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    chromium \
    chromium-driver \
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

# Install all optional dependencies
RUN pip install --no-cache-dir -e ".[all]"

# Install Playwright browsers
RUN pip install --no-cache-dir playwright && \
    playwright install chromium

# Install Burp integration
RUN pip install --no-cache-dir requests

USER phantomprobe

# Expose dashboard port
EXPOSE 8080

ENV PHANTOMPROBE_DASHBOARD_PORT=8080
ENV PHANTOMPROBE_DASHBOARD_HOST=0.0.0.0


# Default stage is core
FROM phantomprobe-dashboard
