#!/bin/bash
# startup.sh - Script to properly set environment variables and start the application

# Extract PORT value and ensure it's a valid integer
if [ -n "$PORT" ]; then
  # Remove any quotes or non-numeric characters
  CLEAN_PORT=$(echo $PORT | tr -d '"' | grep -o '[0-9]*')
  
  # If no valid port number found, use default
  if [ -z "$CLEAN_PORT" ]; then
    CLEAN_PORT=8000
    echo "Warning: Invalid PORT environment variable. Using default port 8000."
  fi
else
  CLEAN_PORT=8000
  echo "No PORT environment variable set. Using default port 8000."
fi

echo "Starting application on port: $CLEAN_PORT"

# Start the application with the clean port
exec uvicorn main:app --host 0.0.0.0 --port $CLEAN_PORT
