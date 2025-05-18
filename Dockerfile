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

# Make sure we have mock models if they don't exist
RUN touch model.pkl encoder.pkl scaler.pkl

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Expose the application port - this is just documentation, Railway will override this
EXPOSE 8000

# Start the application
CMD ["python", "main.py"]
