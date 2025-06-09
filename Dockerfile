# SOC Automation Bot Dockerfile
FROM python:3.10-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive

# Set work directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    curl \
    wget \
    vim \
    net-tools \
    iptables \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r socuser && useradd -r -g socuser socuser

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p /app/logs /app/data /app/models && \
    chown -R socuser:socuser /app

# Set permissions
RUN chmod +x main.py

# Switch to non-root user
USER socuser

# Expose port for dashboard
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/api/metrics || exit 1

# Default command
CMD ["python", "main.py", "--mode", "continuous"]

# Labels
LABEL name="soc-automation-bot" \
      version="1.0" \
      description="Level 1 SOC Automation Bot with SIEM integration, AI triage, and automated response" \
      maintainer="SOC Team" 