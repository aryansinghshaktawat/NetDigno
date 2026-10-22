# Backend Dockerfile — NetScope
FROM python:3.11-slim

# Install nmap and system tools
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        nmap \
        traceroute \
        iputils-ping && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd --system netscope && \
    useradd --system --gid netscope --no-create-home netscope

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY main.py .
COPY app/ ./app/

# Create data directory for SQLite with correct ownership
RUN mkdir -p /data && chown netscope:netscope /data

# Run as non-root
USER netscope

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/v1/health')" || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
