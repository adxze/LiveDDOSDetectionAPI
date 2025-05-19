@app.get("/debug")
async def debug_info():
    """Provide detailed information for debugging model loading issues"""
    # Get model file sizes and detailed info
    model_path = Path("./model.pkl")
    encoder_path = Path("./encoder.pkl")
    scaler_path = Path("./scaler.pkl")
    
    model_info = {
        "exists": model_path.exists(),
        "size_bytes": model_path.stat().st_size if model_path.exists() else 0,
        "loaded": model is not None,
        "type": str(type(model)) if model is not None else "None"
    }
    
    encoder_info = {
        "exists": encoder_path.exists(),
        "size_bytes": encoder_path.stat().st_size if encoder_path.exists() else 0,
        "loaded": encoder is not None,
        "type": str(type(encoder)) if encoder is not None else "None"
    }
    
    scaler_info = {
        "exists": scaler_path.exists(),
        "size_bytes": scaler_path.stat().st_size if scaler_path.exists() else 0,
        "loaded": scaler is not None,
        "type": str(type(scaler)) if scaler is not None else "None"
    }
    
    # Get more detailed environment info
    try:
        # Check for sklearn and joblib versions
        import sklearn
        joblib_version = joblib.__version__
        sklearn_version = sklearn.__version__
    except:
        joblib_version = "unknown"
        sklearn_version = "unknown"
    
    # Check write permissions
    write_access = os.access('.', os.W_OK)
    
    # Check memory usage if psutil is available
    memory_usage = {"error": "psutil not available"}
    if psutil:
        try:
            process = psutil.Process(os.getpid())
            memory_info = process.memory_info()
            memory_usage = {
                "rss_mb": memory_info.rss / (1024 * 1024),  # Convert to MB
                "vms_mb": memory_info.vms / (1024 * 1024)   # Convert to MB
            }
        except Exception as e:
            memory_usage = {"error": f"Could not get memory info: {str(e)}"}
    
    return {
        "model": model_info,
        "encoder": encoder_info,
        "scaler": scaler_info,
        "environment": {
            "python_version": sys.version,
            "sklearn_version": sklearn_version,
            "joblib_version": joblib_version,
            "write_access": write_access,
            "memory_usage": memory_usage,
            "pwd": os.getcwd(),
            "files": os.listdir("."),
            "temp_files": os.listdir(TEMP_DIR) if TEMP_DIR.exists() else []
        },
        "error_info": {
            "tip1": "If model exists but not loaded, there might be compatibility issues with the model format",
            "tip2": "If model doesn't exist, check Google Drive URLs and download logs",
            "tip3": "If model exists but size is small, it might be a placeholder or corrupt file",
            "tip4": "Try uploading model files directly using the /upload_model endpoint"
        }
    }
import os
import logging
import requests
import sys
import traceback
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

# Try to import psutil for memory monitoring
try:
    import psutil
except ImportError:
    # Not critical, so we'll just log it
    psutil = None

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

# Google Drive file URLs from your shared links
MODEL_DRIVE_URL = "https://drive.google.com/file/d/1A5qsfi1fF-SKmQfeDn3_-57qchSVsgt6/view?usp=sharing"
ENCODER_DRIVE_URL = "https://drive.google.com/file/d/1sN4XIfQrVvbiFQycXgSeIMOZ_sjlaMKH/view?usp=sharing"
SCALER_DRIVE_URL = "https://drive.google.com/file/d/1NU1-XtorK4_3eWs6298tECI2ISNSaUAF/view?usp=sharing"

# Google Drive download function
def download_file_from_google_drive(file_id, destination):
    """Download a file from Google Drive using its file ID"""
    logger.info(f"Starting download from Google Drive: {file_id}")
    
    # Handle both full URLs and file IDs
    original_file_id = file_id
    if "drive.google.com" in file_id:
        # Extract file ID from URL
        logger.info(f"Extracting file ID from URL: {file_id}")
        if "/file/d/" in file_id:
            file_id = file_id.split("/file/d/")[1].split("/")[0]
        elif "id=" in file_id:
            file_id = file_id.split("id=")[1].split("&")[0]
        logger.info(f"Extracted file ID: {file_id}")
    
    try:
        # The actual download URL
        URL = "https://drive.google.com/uc?export=download"
        
        session = requests.Session()
        logger.info(f"Making initial request to: {URL}?id={file_id}")
        
        # First request to get cookies
        response = session.get(URL, params={'id': file_id}, stream=True)
        logger.info(f"Initial response status code: {response.status_code}")
        
        if response.status_code != 200:
            logger.error(f"Failed to download: HTTP status {response.status_code}")
            return False
        
        # Check if there's a download warning for large files
        confirm_token = None
        for key, value in response.cookies.items():
            if key.startswith('download_warning'):
                confirm_token = value
                logger.info(f"Found download warning token: {confirm_token}")
                break
                
        # If there's a warning token, make a second request with confirmation
        if confirm_token:
            logger.info(f"Making second request with confirmation token")
            params = {'id': file_id, 'confirm': confirm_token}
            response = session.get(URL, params=params, stream=True)
            logger.info(f"Second response status code: {response.status_code}")
            
            if response.status_code != 200:
                logger.error(f"Failed to download after confirmation: HTTP status {response.status_code}")
                return False
        
        # Alternative approach using direct download URL 
        if response.url.startswith("https://drive.google.com/file/d/"):
            logger.info("Redirected to file view page, trying alternate method...")
            # Try with another URL format
            direct_url = f"https://drive.google.com/uc?export=download&id={file_id}"
            logger.info(f"Trying direct URL: {direct_url}")
            response = session.get(direct_url, stream=True)
            
            # Check for the Google Drive "virus scan" page
            if "Google Drive - Virus scan warning" in response.text:
                logger.info("Encountered virus scan page, trying to bypass...")
                direct_url = f"https://drive.google.com/uc?export=download&id={file_id}&confirm=t"
                response = session.get(direct_url, stream=True)
        
        # Save the file
        logger.info(f"Saving file to: {destination}")
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
            
    except Exception as e:
        logger.error(f"Exception during download: {str(e)}")
        logger.exception("Download exception details:")
        return False

# Try to load or download models
try:
    logger.info("Attempting to load ML components...")
    MODEL_PATH = Path("./model.pkl")
    ENCODER_PATH = Path("./encoder.pkl")
    SCALER_PATH = Path("./scaler.pkl")
    
    # Log current directory and permissions
    logger.info(f"Current working directory: {os.getcwd()}")
    logger.info(f"Directory is writable: {os.access('.', os.W_OK)}")
    logger.info(f"Model path exists: {MODEL_PATH.exists()}")
    logger.info(f"Encoder path exists: {ENCODER_PATH.exists()}")
    logger.info(f"Scaler path exists: {SCALER_PATH.exists()}")
    
    # Check and download model if needed
    if not MODEL_PATH.exists() or MODEL_PATH.stat().st_size < 1000:
        logger.info("Model file missing or too small. Downloading from Google Drive...")
        try:
            logger.info(f"Downloading model from: {MODEL_DRIVE_URL}")
            success = download_file_from_google_drive(MODEL_DRIVE_URL, MODEL_PATH)
            if success:
                logger.info(f"Model downloaded successfully! Size: {MODEL_PATH.stat().st_size} bytes")
            else:
                logger.error("Failed to download model file from Google Drive")
                raise Exception("Failed to download model file")
        except Exception as e:
            logger.error(f"Error downloading model: {str(e)}")
            raise
    else:
        logger.info(f"model.pkl exists! Size: {MODEL_PATH.stat().st_size} bytes")
        
    # Similarly for encoder and scaler if needed
    if not ENCODER_PATH.exists():
        logger.info("Encoder file missing. Downloading from Google Drive...")
        try:
            logger.info(f"Downloading encoder from: {ENCODER_DRIVE_URL}")
            success = download_file_from_google_drive(ENCODER_DRIVE_URL, ENCODER_PATH)
            if success:
                logger.info(f"Encoder downloaded successfully! Size: {ENCODER_PATH.stat().st_size} bytes")
            else:
                logger.error("Failed to download encoder file from Google Drive")
        except Exception as e:
            logger.error(f"Error downloading encoder: {str(e)}")
    
    if not SCALER_PATH.exists():
        logger.info("Scaler file missing. Downloading from Google Drive...")
        try:
            logger.info(f"Downloading scaler from: {SCALER_DRIVE_URL}")
            success = download_file_from_google_drive(SCALER_DRIVE_URL, SCALER_PATH)
            if success:
                logger.info(f"Scaler downloaded successfully! Size: {SCALER_PATH.stat().st_size} bytes")
            else:
                logger.error("Failed to download scaler file from Google Drive")
        except Exception as e:
            logger.error(f"Error downloading scaler: {str(e)}")
    
    # Log file status after download attempts
    logger.info(f"After download attempts - Model exists: {MODEL_PATH.exists()}, Size: {MODEL_PATH.stat().st_size if MODEL_PATH.exists() else 0} bytes")
    logger.info(f"After download attempts - Encoder exists: {ENCODER_PATH.exists()}, Size: {ENCODER_PATH.stat().st_size if ENCODER_PATH.exists() else 0} bytes")
    logger.info(f"After download attempts - Scaler exists: {SCALER_PATH.exists()}, Size: {SCALER_PATH.stat().st_size if SCALER_PATH.exists() else 0} bytes")
    
    # Load the model
    logger.info("Attempting to load model file...")
    model_data = joblib.load(MODEL_PATH)
    logger.info(f"Model file loaded successfully. Type: {type(model_data)}")
    
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
        logger.info("Attempting to load encoder file...")
        encoder = joblib.load(ENCODER_PATH)
        logger.info("Encoder loaded successfully!")
    
    if SCALER_PATH.exists():
        logger.info("Attempting to load scaler file...")
        scaler = joblib.load(SCALER_PATH)
        logger.info("Scaler loaded successfully!")
    
    # If no real encoder/scaler but we have a model
    if model is not None and (encoder is None or scaler is None):
        logger.warning("Using internal preprocessing with label encoders instead of separate encoder/scaler")
        
except Exception as e:
    logger.error(f"Error loading ML components: {e}")
    logger.exception("Stack trace:")
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

@app.post("/upload_model")
async def upload_model_file(
    file: UploadFile = File(...),
    model_type: str = "model",  # can be "model", "encoder", or "scaler"
    api_key: APIKey = Depends(get_api_key)
):
    """
    Upload model files directly instead of downloading from Google Drive.
    This is useful if Google Drive download is not working.
    """
    # Determine the file path based on model type
    if model_type.lower() == "model":
        file_path = Path("./model.pkl")
    elif model_type.lower() == "encoder":
        file_path = Path("./encoder.pkl")
    elif model_type.lower() == "scaler":
        file_path = Path("./scaler.pkl")
    else:
        raise HTTPException(status_code=400, detail=f"Invalid model type: {model_type}. Must be 'model', 'encoder', or 'scaler'")
    
    try:
        # Save the uploaded file
        contents = await file.read()
        with open(file_path, "wb") as buffer:
            buffer.write(contents)
        
        file_size = file_path.stat().st_size
        logger.info(f"Uploaded {model_type} file successfully. Size: {file_size} bytes")
        
        if file_size < 1000:
            return {
                "success": False,
                "message": f"File uploaded but seems too small ({file_size} bytes). It might be invalid."
            }
        
        # Try to validate by loading (but don't actually replace the loaded model in memory)
        try:
            loaded_data = joblib.load(file_path)
            if model_type.lower() == "model":
                if isinstance(loaded_data, tuple) and len(loaded_data) == 2:
                    logger.info("Verified model file with grid_search and label_encoders")
                else:
                    logger.info(f"Verified model file of type: {type(loaded_data).__name__}")
            else:
                logger.info(f"Verified {model_type} file of type: {type(loaded_data).__name__}")
                
            return {
                "success": True,
                "message": f"{model_type.capitalize()} file uploaded successfully ({file_size} bytes). Restart the API to use it.",
                "file_path": str(file_path),
                "file_type": str(type(loaded_data).__name__)
            }
            
        except Exception as e:
            logger.error(f"Error validating the uploaded {model_type} file: {str(e)}")
            return {
                "success": False,
                "message": f"File uploaded but failed validation. It may not be a valid {model_type} file: {str(e)}",
                "file_path": str(file_path)
            }
    
    except Exception as e:
        logger.error(f"Error uploading {model_type} file: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error uploading file: {str(e)}")

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
            "/upload_model": "Upload model file directly (POST, requires API key)",
            "/debug": "Detailed debugging information for troubleshooting",
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
        "model_files": {
            "description": "The API requires three ML model files to function:",
            "model.pkl": "The main ML model for DDoS detection",
            "encoder.pkl": "Categorical feature encoder",
            "scaler.pkl": "Numerical feature scaler",
            "notes": "If model download from Google Drive fails, you can upload them directly with /upload_model"
        },
        "usage_examples": {
            "detect_ddos": 'curl -X POST "http://api-url/detect?interface=eth0&duration=60" -H "X-API-Key: your-api-key"',
            "predict_csv": 'curl -X POST "http://api-url/predict_csv" -H "X-API-Key: your-api-key" -F "file=@your-file.csv"',
            "upload_model": 'curl -X POST "http://api-url/upload_model?model_type=model" -H "X-API-Key: your-api-key" -F "file=@model.pkl"'
        },
        "troubleshooting": {
            "model_not_available": "If you see 'ML model not available' errors, check /debug for detailed information",
            "manual_upload": "Use /upload_model to manually upload model files if automatic download fails"
        }
    }

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
