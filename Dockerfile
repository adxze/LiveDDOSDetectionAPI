FROM python:3.10-slim

WORKDIR /app

# Install system dependencies for pyshark
RUN apt-get update && apt-get install -y \
    tshark \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements file
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Set environment variables
ENV PORT=8000
ENV PYTHONUNBUFFERED=1

# Expose the application port
EXPOSE 8000

# Start the application with uvicorn
CMD uvicorn main:app --host 0.0.0.0 --port $PORT
