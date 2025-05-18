FROM python:3.10-slim

WORKDIR /app

# Install system dependencies 
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements file
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Create temp directory
RUN mkdir -p ./temp

# Create mock models if they don't exist
RUN touch model.pkl encoder.pkl scaler.pkl

# Set environment variables
ENV PYTHONUNBUFFERED=1

# This is the critical part - using shell directly to evaluate $PORT at runtime
CMD ["sh", "-c", "python -m uvicorn main:app --host 0.0.0.0 --port $PORT"]
