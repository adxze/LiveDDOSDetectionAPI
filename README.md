# DiddySec FastAPI DDoS Detection Service

This service provides a REST API for real-time DDoS detection using machine learning.

## Features

- Real-time network traffic monitoring
- ML-based DDoS attack detection
- CSV file upload for offline analysis
- Detailed traffic analysis and reporting

## API Endpoints

- `GET /`: API information
- `GET /health`: Health check endpoint
- `GET /interfaces`: List available network interfaces
- `POST /detect`: Start a new DDoS detection session
- `GET /status/{capture_id}`: Get status and results of a detection session
- `POST /predict_csv`: Analyze a CSV file containing network traffic data

## Environment Variables

- `API_KEY`: API key for authentication
- `PORT`: Port to run the service on (set by Railway)

## Deployment

This service is designed to be deployed on Railway. Simply connect your GitHub repository to Railway and it will automatically build and deploy the service.
