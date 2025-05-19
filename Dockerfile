# Dockerfile
FROM python:3.10-slim

# Install system dependencies for pyshark
RUN apt-get update && apt-get install -y \
    tshark \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Make the startup script executable
COPY startup.sh /app/startup.sh
RUN chmod +x /app/startup.sh

# Command to run the application using the startup script
CMD ["/app/startup.sh"]
