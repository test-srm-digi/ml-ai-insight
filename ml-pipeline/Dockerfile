FROM python:3.11-slim

LABEL maintainer="vuln-insight-team"
LABEL description="ML sidecar for the Vulnerability Insight scoring pipeline"

# Prevent Python from writing .pyc files and enable unbuffered stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install OS-level dependencies (none beyond what slim provides, but keep
# the layer so future additions are cheap)
RUN apt-get update && \
    apt-get install -y --no-install-recommends && \
    rm -rf /var/lib/apt/lists/*

# Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Application source
COPY src/ src/

# Model artifact — expected to be bind-mounted or baked in at build time
# Default path matches what app.py resolves via MODEL_PATH env var
COPY models/ models/

# Make the package importable
ENV PYTHONPATH=/app/src

# Expose the default sidecar port
EXPOSE 8000

# Health-check against the /health endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"]

# Run uvicorn — override MODEL_PATH at runtime if needed
CMD ["uvicorn", "vuln_insight.serving.app:app", "--host", "0.0.0.0", "--port", "8000"]
