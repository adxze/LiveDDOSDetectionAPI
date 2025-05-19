import os
import logging
import requests
import sys
from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, Request, UploadFile, File, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security.api_key import APIKeyHeader, APIKey
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Dict, List, Optional, Union
import pandas as pd
import numpy as np
import joblib
import time
import subprocess
import json
from pathlib import Path
import socket
import uuid
import asyncio
from datetime import datetime

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# Log environment for debugging
logger.info(f"Environment variables: PORT={os.environ.get('PORT', 'not set')}")
logger.info(f"Python version: {sys.version}")
logger.info(f"Current directory: {os.getcwd()}")
logger.info(f"Files in current directory: {os.listdir('.')}")

# API configuration
API_KEY = os.getenv("API_KEY", "your-api-key")
api_key_header = APIKeyHeader(name="X-API-Key")

# Initialize FastAPI app
app = FastAPI(
    title="DiddySec DDoS Detection API",
    description="API for real-time DDoS detection using machine learning",
    version="1.0.0"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For production, specify exact domains
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Directory for temporary files
TEMP_DIR = Path("./temp")
TEMP_DIR.mkdir(exist_ok=True)

# Initialize model, encoder, and scaler variables
model = None
encoder = None
scaler = None
label_encoders = {}

# Google Drive download function
def download_file_from_google_drive(file_id, destination):
    """Download a file from Google Drive using its file ID"""
    # Handle both full URLs and file IDs
    if "drive.google.com" in file_id:
        # Extract file ID from URL
        if "/file/d/" in file_id:
            file_id = file_id.split("/file/d/")[1].split("/")[0]
        elif "id=" in file_id:
            file_id = file_id.split("id=")[1].split("&")[0]
    
    # The actual download URL
    URL = "https://drive.google.com/uc?export=download"
    
    session = requests.Session()
    
    # First request to get cookies
    response = session.get(URL, params={'id': file_id}, stream=True)
    
    # Check if there's a download warning for large files
    for key, value in response.cookies.items():
        if key.startswith('download_warning'):
            # Add confirm param to avoid the warning page
            params = {'id': file_id, 'confirm': value}
            response = session.get(URL, params=params, stream=True)
            break
    
    # Save the file
    CHUNK_SIZE = 32768
    with open(destination, "wb") as f:
        for chunk in response.iter_content(CHUNK_SIZE):
            if chunk:
                f.write(chunk)
    
    # Verify the file was downloaded successfully
    if os.path.exists(destination) and os.path.getsize(destination) > 0:
        logger.info(f"Successfully downloaded {destination} ({os.path.getsize(destination)} bytes)")
        return True
    else:
        logger.error(f"Failed to download {destination} or file is empty")
        return False

# Try to load or download models
try:
    logger.info("Attempting to load ML components...")
    MODEL_PATH = Path("./model.pkl")
    ENCODER_PATH = Path("./encoder.pkl")
    SCALER_PATH = Path("./scaler.pkl")
    
    # Google Drive file IDs - replace these with your actual file IDs
    MODEL_DRIVE_ID = "1uG8OB_mRvt56qO1V8DmaApAn2y6BuGEG"  # Example from your second code
    ENCODER_DRIVE_ID = "your-encoder-file-id"  # Replace with actual ID
    SCALER_DRIVE_ID = "your-scaler-file-id"    # Replace with actual ID
    
    # Check and download model if needed
    if not MODEL_PATH.exists() or MODEL_PATH.stat().st_size < 1000:
        logger.info("Model file missing or too small. Downloading from Google Drive...")
        try:
            download_file_from_google_drive(MODEL_DRIVE_URL, MODEL_PATH)
            logger.info(f"Model downloaded successfully! Size: {MODEL_PATH.stat().st_size} bytes")
        except Exception as e:
            logger.error(f"Error downloading model: {str(e)}")
            raise
    else:
        logger.info(f"model.pkl exists! Size: {MODEL_PATH.stat().st_size} bytes")
        
    # Similarly for encoder and scaler if needed
    if not ENCODER_PATH.exists():
        logger.info("Encoder file missing. Downloading from Google Drive...")
        try:
            download_file_from_google_drive(ENCODER_DRIVE_URL, ENCODER_PATH)
            logger.info(f"Encoder downloaded successfully!")
        except Exception as e:
            logger.error(f"Error downloading encoder: {str(e)}")
    
    if not SCALER_PATH.exists():
        logger.info("Scaler file missing. Downloading from Google Drive...")
        try:
            download_file_from_google_drive(SCALER_DRIVE_URL, SCALER_PATH)
            logger.info(f"Scaler downloaded successfully!")
        except Exception as e:
            logger.error(f"Error downloading scaler: {str(e)}")
    
    # Load the model
    model_data = joblib.load(MODEL_PATH)
    
    # Handle different model formats
    if isinstance(model_data, tuple) and len(model_data) == 2:
        grid_search, label_encoders = model_data
        model = grid_search.best_estimator_
        logger.info(f"Model loaded successfully! Type: {type(model).__name__}")
    else:
        model = model_data
        logger.info(f"Model loaded successfully! Type: {type(model).__name__}")
    
    # Try to load encoder and scaler if they exist
    if ENCODER_PATH.exists():
        encoder = joblib.load(ENCODER_PATH)
        logger.info("Encoder loaded successfully!")
    
    if SCALER_PATH.exists():
        scaler = joblib.load(SCALER_PATH)
        logger.info("Scaler loaded successfully!")
    
    # If no real encoder/scaler but we have a model
    if model is not None and (encoder is None or scaler is None):
        logger.warning("Using internal preprocessing with label encoders instead of separate encoder/scaler")
        
except Exception as e:
    logger.error(f"Error loading ML components: {e}")
    # No mock fallback - system will report errors appropriately

# Track ongoing captures
active_captures = {}

# Define response models
class CaptureResponse(BaseModel):
    capture_id: str
    status: str
    message: str

class PredictionResult(BaseModel):
    capture_id: str
    status: str
    result_counts: Dict[str, int]
    detailed_results: Optional[List[Dict]] = None
    
class HealthResponse(BaseModel):
    status: str
    time: str
    model_loaded: bool
    interface_available: bool

# API Key verification
async def get_api_key(api_key: str = Depends(api_key_header)):
    if api_key != API_KEY:
        raise HTTPException(
            status_code=403, 
            detail="Invalid API key"
        )
    return api_key

# Check if network interfaces are available
def get_available_interfaces():
    try:
        # This is platform-dependent and might need adjustment
        if os.name == 'nt':  # Windows
            interfaces = socket.if_nameindex()
            return [iface[1] for iface in interfaces]
        else:  # Linux/Unix
            # Use subprocess to get interfaces from ip or ifconfig
            result = subprocess.run(
                ["ip", "-o", "link", "show"],
                capture_output=True, 
                text=True
            )
            lines = result.stdout.strip().split("\n")
            interfaces = []
            for line in lines:
                parts = line.split(":", 2)
                if len(parts) >= 2:
                    interfaces.append(parts[1].strip())
            return interfaces
    except Exception as e:
        logger.error(f"Error getting network interfaces: {e}")
        return []

# Preprocess data based on the second file's implementation
def preprocess_data(df):
    """
    Preprocess data to match the format expected by the model
    """
    try:
        # Handle categorical columns with label encoding
        for col in df.select_dtypes(include=['object']).columns:
            if col in label_encoders:
                # Handle unknown categories
                df[col] = df[col].astype(str)
                for val in df[col].unique():
                    if val not in label_encoders[col].classes_:
                        label_encoders[col].classes_ = np.append(label_encoders[col].classes_, val)
                df[col] = label_encoders[col].transform(df[col])
            else:
                df[col] = 0
                
        # Apply log transformations as your model was trained with
        if 'dload' in df.columns:
            df['dload'] = np.log1p(df['dload'])
            
        if 'ct_dst_sport_ltm' in df.columns:
            df['ct_dst_sport_ltm'] = np.log1p(df['ct_dst_sport_ltm'])
            
        if 'dmean' in df.columns:
            df['dmean'] = np.log1p(df['dmean'])
        
        return df
    except Exception as e:
        error_msg = f"Error preprocessing data: {str(e)}"
        logger.error(f"ERROR: {error_msg}")
        raise Exception(error_msg)

# Function to capture network traffic
async def capture_network_traffic(capture_id: str, interface: str, duration: int):
    try:
        active_captures[capture_id] = {"status": "running", "start_time": time.time()}
        
        # Create unique filenames for this capture
        csv_file = TEMP_DIR / f"{capture_id}_flows.csv"
        predicted_file = TEMP_DIR / f"{capture_id}_predicted.csv"
        
        # Build the capture command
        # Note: In production, you'd implement this with pyshark directly or tcpdump
        # For demo purposes, we're calling it as a subprocess
        
        # This is a simplified mock of the capture process
        # In a real implementation, you'd use the live_capture_flow_features function
        
        logger.info(f"Starting capture on interface {interface} for {duration} seconds")
        
        # Create a mock CSV with flow data
        with open(csv_file, 'w') as f:
            f.write("src_ip,dst_ip,protocol,src_port,dst_port,state,sttl,ct_state_ttl,dload,ct_dst_sport_ltm,rate,swin,dwin,dmean,ct_src_dport_ltm\n")
            # Add some mock data
            for i in range(20):
                # Normal traffic
                f.write(f"192.168.1.{i},10.0.0.{i},tcp,{5000+i},{80+i},CON,64,10,1.2,0.5,2.1,1024,1024,120,0.5\n")
            
            # Add some suspicious traffic if needed
            if "attack" in interface.lower():  # Just for testing
                for i in range(150):
                    # DDoS traffic pattern
                    f.write(f"172.16.0.{i % 20},10.0.0.1,tcp,{4000+i},80,SYN,64,0,50.5,0.01,87.3,512,512,60,0.01\n")
        
        # Wait for the duration to simulate real capture
        await asyncio.sleep(min(duration, 5))  # Cap at 5s for demo
        
        # Check if the ML model is available
        if model is None:
            active_captures[capture_id] = {
                "status": "error",
                "message": "ML model not available. Cannot perform prediction.",
                "end_time": time.time()
            }
            logger.error(f"Capture {capture_id} failed: ML model not available")
            return
        
        # Now predict using the model
        # Read the captured data
        df = pd.read_csv(csv_file)
        
        # Save a copy of the raw data before preprocessing
        flow_data = df.copy()
        
        # Preprocess the data - use either encoder/scaler or label_encoders approach
        if encoder is not None and scaler is not None:
            # Preprocess the data using encoder/scaler approach
            df_processed = df.drop(['src_ip', 'dst_ip', 'protocol', 'src_port', 'dst_port'], axis=1)
            df_processed['state'] = encoder.transform(df_processed['state'])
            features = ['state', 'sttl', 'ct_state_ttl', 'dload', 'ct_dst_sport_ltm', 
                      'rate', 'swin', 'dwin', 'dmean', 'ct_src_dport_ltm']
            df_processed[features] = scaler.transform(df_processed[features])
        else:
            # Use the preprocess_data function with label_encoders
            # Drop unnecessary columns if they exist
            df_processed = df.drop(['src_ip', 'dst_ip', 'protocol', 'src_port', 'dst_port'], axis=1)
            df_processed = preprocess_data(df_processed)
        
        # Make predictions
        predictions = model.predict(df_processed)
        
        # Add predictions to the original data
        flow_data['prediction'] = predictions
        
        # Map numerical predictions to labels (0 = Normal, 1 = Intrusion)
        flow_data['label'] = flow_data['prediction'].map({0: 'Normal', 1: 'Intrusion'})
        
        # Save the results
        flow_data.to_csv(predicted_file, index=False)
        
        # Count the results
        result_counts = flow_data['label'].value_counts().to_dict()
        
        # Update the capture status
        active_captures[capture_id] = {
            "status": "completed",
            "result_counts": result_counts,
            "end_time": time.time(),
            "prediction_file": str(predicted_file)
        }
        
        logger.info(f"Capture {capture_id} completed with results: {result_counts}")
    
    except Exception as e:
        active_captures[capture_id] = {
            "status": "error",
            "message": str(e),
            "end_time": time.time()
        }
        logger.error(f"Error in capture {capture_id}: {e}")

# API Endpoints
@app.get("/")
async def root():
    return {
        "message": "DiddySec DDoS Detection API", 
        "version": "1.0.0",
        "model_loaded": model is not None
    }

@app.get("/health", response_model=HealthResponse)
async def health_check():
    interfaces = get_available_interfaces()
    return {
        "status": "ok" if model is not None else "error",
        "time": datetime.now().isoformat(),
        "model_loaded": model is not None,
        "interface_available": len(interfaces) > 0
    }

@app.get("/interfaces")
async def list_interfaces(api_key: APIKey = Depends(get_api_key)):
    interfaces = get_available_interfaces()
    return {"interfaces": interfaces}

@app.post("/detect", response_model=CaptureResponse)
async def start_detection(
    background_tasks: BackgroundTasks,
    interface: str = "eth0",  # Default interface
    duration: int = 60,  # Default duration in seconds
    api_key: APIKey = Depends(get_api_key)
):
    # Check if ML models are available
    if model is None:
        raise HTTPException(
            status_code=503,
            detail="ML model not available. Cannot start detection."
        )
    
    # Generate a unique ID for this capture
    capture_id = str(uuid.uuid4())
    
    # Start the capture in the background
    background_tasks.add_task(
        capture_network_traffic,
        capture_id,
        interface,
        duration
    )
    
    return {
        "capture_id": capture_id,
        "status": "started",
        "message": f"Started DDoS detection on interface {interface} for {duration} seconds"
    }

@app.get("/status/{capture_id}", response_model=Union[CaptureResponse, PredictionResult])
async def get_status(
    capture_id: str,
    include_details: bool = False,
    api_key: APIKey = Depends(get_api_key)
):
    if capture_id not in active_captures:
        raise HTTPException(
            status_code=404,
            detail=f"Capture {capture_id} not found"
        )
    
    capture_info = active_captures[capture_id]
    
    if capture_info["status"] == "running":
        # Still running
        elapsed_time = time.time() - capture_info["start_time"]
        return {
            "capture_id": capture_id,
            "status": "running",
            "message": f"Capture in progress for {elapsed_time:.1f} seconds"
        }
    
    elif capture_info["status"] == "completed":
        # Completed successfully
        response = {
            "capture_id": capture_id,
            "status": "completed",
            "result_counts": capture_info["result_counts"]
        }
        
        # Include detailed results if requested
        if include_details and "prediction_file" in capture_info:
            try:
                df = pd.read_csv(capture_info["prediction_file"])
                response["detailed_results"] = json.loads(df.to_json(orient="records"))
            except Exception as e:
                logger.error(f"Error loading detailed results: {e}")
        
        return response
    
    else:
        # Error occurred
        return {
            "capture_id": capture_id,
            "status": "error",
            "message": capture_info.get("message", "Unknown error")
        }

@app.post("/predict_csv")
async def predict_csv_file(
    file: UploadFile = File(...),
    api_key: APIKey = Depends(get_api_key)
):
    # Check if ML models are available
    if model is None:
        raise HTTPException(
            status_code=503,
            detail="ML model not available. Cannot perform prediction."
        )
    
    # Validate file type
    if not file.filename.endswith('.csv'):
        raise HTTPException(status_code=400, detail="Only CSV files are allowed")
    
    # Limit file size (10MB)
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
    
    try:
        # Read file with size limit
        contents = await file.read()
        if len(contents) > MAX_FILE_SIZE:
            raise HTTPException(status_code=400, detail="File too large. Maximum size is 10MB")
        
        # Save the uploaded file temporarily
        temp_file = TEMP_DIR / f"temp_{file.filename}"
        with open(temp_file, "wb") as buffer:
            buffer.write(contents)
        
        # Read the CSV
        df = pd.read_csv(temp_file)
        logger.info(f"Loaded CSV with shape: {df.shape}")
        
        # Drop unnecessary columns if they exist
        df = df.drop(['id', 'attack_cat'], axis=1, errors='ignore')
        
        # Prepare features
        X = df.copy()
        if 'label' in X.columns:
            y_true = X['label'].copy()
            X = X.drop('label', axis=1)
        else:
            y_true = None
        
        # Preprocess the data - use either encoder/scaler or label_encoders approach
        if encoder is not None and scaler is not None:
            # Preprocess the data using encoder/scaler approach
            X_processed = X.drop(['src_ip', 'dst_ip', 'protocol', 'src_port', 'dst_port'], axis=1, errors='ignore')
            if 'state' in X_processed.columns:
                X_processed['state'] = encoder.transform(X_processed['state'])
            features = [col for col in ['state', 'sttl', 'ct_state_ttl', 'dload', 'ct_dst_sport_ltm', 
                      'rate', 'swin', 'dwin', 'dmean', 'ct_src_dport_ltm'] if col in X_processed.columns]
            X_processed[features] = scaler.transform(X_processed[features])
        else:
            # Use the preprocess_data function with label_encoders
            X_processed = preprocess_data(X)
        
        # Make predictions
        predictions = model.predict(X_processed)
        
        try:
            probabilities = model.predict_proba(X_processed)[:, 1]
        except:
            probabilities = predictions.astype(float)
        
        # Create result summary
        normal_count = int(sum(predictions == 0))
        intrusion_count = int(sum(predictions == 1))
        total_count = len(predictions)
        
        summary = {
            'total_connections': total_count,
            'normal_connections': normal_count,
            'intrusion_connections': intrusion_count,
            'intrusion_percentage': float(round(intrusion_count / total_count * 100, 2))
        }
        
        # If we have true labels, calculate accuracy
        if y_true is not None:
            accuracy = (predictions == y_true).mean() * 100
            summary['accuracy'] = float(round(accuracy, 2))
        
        # Clean up temp file
        if os.path.exists(temp_file):
            os.remove(temp_file)
        
        logger.info(f"Prediction completed for {file.filename}")
        
        return {
            'success': True,
            'result_counts': {
                'Normal': normal_count,
                'Intrusion': intrusion_count
            },
            'summary': summary,
            'predictions': predictions.tolist(),
            'probabilities': probabilities.tolist()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        error_msg = f"Prediction error: {str(e)}"
        logger.error(f"ERROR: {error_msg}")
        
        # Cleanup
        if 'temp_file' in locals() and os.path.exists(temp_file):
            os.remove(temp_file)
        
        raise HTTPException(status_code=500, detail=error_msg)

@app.get("/debug")
async def debug_info():
    # Return useful debugging information
    return {
        "environment": dict(os.environ),
        "pwd": os.getcwd(),
        "files": os.listdir("."),
        "temp_files": os.listdir(TEMP_DIR) if TEMP_DIR.exists() else [],
        "model_exists": Path("./model.pkl").exists(),
        "encoder_exists": Path("./encoder.pkl").exists(),
        "scaler_exists": Path("./scaler.pkl").exists(),
        "model_loaded": model is not None,
        "encoder_loaded": encoder is not None,
        "scaler_loaded": scaler is not None,
        "model_type": str(type(model)) if model is not None else "None",
    }

# Error handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Global exception: {str(exc)}")
    return JSONResponse(
        status_code=500,
        content={"detail": f"Internal server error: {str(exc)}"}
    )

# API documentation endpoint
@app.get("/api/docs")
async def api_documentation():
    """Returns API usage documentation"""
    return {
        "endpoints": {
            "/": "API status check",
            "/health": "Health check endpoint",
            "/interfaces": "List available network interfaces",
            "/detect": "Start real-time DDoS detection (POST, requires API key)",
            "/status/{capture_id}": "Get status of a detection job",
            "/predict_csv": "Upload CSV for prediction (POST, requires API key)",
            "/debug": "Debug information for troubleshooting",
            "/api/docs": "API documentation (this endpoint)"
        },
        "authentication": {
            "method": "API Key in header",
            "header_name": "X-API-Key",
            "example": {
                "headers": {
                    "X-API-Key": "your-api-key-here"
                }
            }
        },
        "usage_example": {
            "curl": 'curl -X POST "http://api-url/predict_csv" -H "X-API-Key: your-api-key" -F "file=@your-file.csv"'
        }
    }

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
