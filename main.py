import os
from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security.api_key import APIKeyHeader, APIKey
from pydantic import BaseModel
from typing import Dict, List, Optional, Union
import pandas as pd
import joblib
import time
import subprocess
import json
from pathlib import Path
import socket
import uuid
import asyncio
import logging
from datetime import datetime

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

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

# Load the ML model and preprocessing components
MODEL_PATH = Path("./model.pkl")
ENCODER_PATH = Path("./encoder.pkl")
SCALER_PATH = Path("./scaler.pkl")

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

# Load ML components
def load_ml_components():
    try:
        model = joblib.load(MODEL_PATH)
        encoder = joblib.load(ENCODER_PATH)
        scaler = joblib.load(SCALER_PATH)
        logger.info("ML model and components loaded successfully")
        return model, encoder, scaler
    except Exception as e:
        logger.error(f"Error loading ML components: {e}")
        return None, None, None

model, encoder, scaler = load_ml_components()

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
        
        # Now predict using the model
        if model and encoder and scaler:
            # Read the captured data
            df = pd.read_csv(csv_file)
            
            # Save a copy of the raw data before preprocessing
            flow_data = df.copy()
            
            # Preprocess the data
            df_processed = df.drop(['src_ip', 'dst_ip', 'protocol', 'src_port', 'dst_port'], axis=1)
            
            # Encode categorical features
            df_processed['state'] = encoder.transform(df_processed['state'])
            
            # Scale numerical features
            features = ['state', 'sttl', 'ct_state_ttl', 'dload', 'ct_dst_sport_ltm', 
                       'rate', 'swin', 'dwin', 'dmean', 'ct_src_dport_ltm']
            df_processed[features] = scaler.transform(df_processed[features])
            
            # Make predictions
            predictions = model.predict(df_processed[features])
            
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
        else:
            active_captures[capture_id] = {
                "status": "error",
                "message": "ML model not available",
                "end_time": time.time()
            }
            logger.error(f"Capture {capture_id} failed: ML model not available")
    
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
    return {"message": "DiddySec DDoS Detection API", "version": "1.0.0"}

@app.get("/health", response_model=HealthResponse)
async def health_check():
    interfaces = get_available_interfaces()
    return {
        "status": "ok",
        "time": datetime.now().isoformat(),
        "model_loaded": model is not None and encoder is not None and scaler is not None,
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

# Simplified CSV prediction endpoint
@app.post("/predict_csv")
async def predict_csv_file(request: Request, api_key: APIKey = Depends(get_api_key)):
    # This would be implemented with a proper file upload
    # For now we'll just return a mock response
    await asyncio.sleep(2)  # Simulate processing time
    
    return {
        "result_counts": {
            "Normal": 462,
            "Intrusion": 96
        }
    }

# Specific for Railway deployment
if __name__ == "__main__":
    import uvicorn
    
    # Get port from environment variable and convert to integer
    port = int(os.environ.get("PORT", 8000))
    
    # Log the port being used
    logger.info(f"Starting server on port {port}")
    
    # Start uvicorn server with explicit port as an integer
    uvicorn.run(app, host="0.0.0.0", port=port)
