import os
import time
import uuid
import gdown
import tempfile
import logging
import pandas as pd
import pyshark
import joblib
import asyncio
import aiofiles
import csv
from collections import defaultdict
from typing import Dict, Optional, List, Any
from fastapi import FastAPI, File, UploadFile, HTTPException, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel
import sqlalchemy
from sqlalchemy import create_engine, Column, String, Integer, Float, DateTime, JSON, Text, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import json

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Model URLs
MODEL_DRIVE_URL = "https://drive.google.com/file/d/1A5qsfi1fF-SKmQfeDn3_-57qchSVsgt6/view?usp=sharing"
ENCODER_DRIVE_URL = "https://drive.google.com/file/d/1sN4XIfQrVvbiFQycXgSeIMOZ_sjlaMKH/view?usp=sharing"
SCALER_DRIVE_URL = "https://drive.google.com/file/d/1NU1-XtorK4_3eWs6298tECI2ISNSaUAF/view?usp=sharing"

# Create model directory
MODEL_DIR = os.path.join(tempfile.gettempdir(), "ddos_models")
os.makedirs(MODEL_DIR, exist_ok=True)

# Model file paths
MODEL_PATH = os.path.join(MODEL_DIR, "model.pkl")
ENCODER_PATH = os.path.join(MODEL_DIR, "encoder.pkl")
SCALER_PATH = os.path.join(MODEL_DIR, "scaler.pkl")

# API key for security - exactly matching your Railway variables
API_KEY = os.environ.get("API_KEY", "this-is-api-key-lol")
api_key_header = APIKeyHeader(name="X-API-Key")

# Dictionary to track ongoing detection tasks
detection_tasks = {}

# Database setup
DB_URL = os.environ.get("MYSQL_URL", "mysql://root:password@localhost:3306/ddos_detection")
DB_ENGINE = create_engine(DB_URL)
Base = declarative_base()

# Define SQLAlchemy models
class DetectionResult(Base):
    __tablename__ = "detection_results"
    
    id = Column(String(36), primary_key=True)
    capture_id = Column(String(36), index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    hostname = Column(String(255), nullable=True)
    location = Column(String(255), nullable=True)
    status = Column(String(50))
    normal_count = Column(Integer, default=0)
    intrusion_count = Column(Integer, default=0)
    result_data = Column(Text, nullable=True)  # Store JSON data as text
    os_info = Column(String(255), nullable=True)
    
    def to_dict(self):
        return {
            "id": self.id,
            "capture_id": self.capture_id,
            "timestamp": self.timestamp.isoformat(),
            "hostname": self.hostname,
            "location": self.location,
            "status": self.status,
            "normal_count": self.normal_count,
            "intrusion_count": self.intrusion_count,
            "result_data": json.loads(self.result_data) if self.result_data else None,
            "os_info": self.os_info
        }

# Create tables
Base.metadata.create_all(DB_ENGINE)

# Create a session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=DB_ENGINE)

# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

app = FastAPI(title="DDoS Detection API", description="API for detecting DDoS attacks in network traffic")

# Add CORS middleware to allow requests from your frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Specify your frontend URL in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API key validation dependency
async def verify_api_key(api_key: str = Depends(api_key_header)):
    if api_key != API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API key")
    return api_key

# Download model files at startup
async def download_models():
    try:
        logger.info("Checking for model files...")
        
        # Only download if files don't exist
        if not os.path.exists(MODEL_PATH):
            logger.info(f"Downloading model from {MODEL_DRIVE_URL}")
            gdown.download(url=MODEL_DRIVE_URL, output=MODEL_PATH, quiet=False, fuzzy=True)
        
        if not os.path.exists(ENCODER_PATH):
            logger.info(f"Downloading encoder from {ENCODER_DRIVE_URL}")
            gdown.download(url=ENCODER_DRIVE_URL, output=ENCODER_PATH, quiet=False, fuzzy=True)
        
        if not os.path.exists(SCALER_PATH):
            logger.info(f"Downloading scaler from {SCALER_DRIVE_URL}")
            gdown.download(url=SCALER_DRIVE_URL, output=SCALER_PATH, quiet=False, fuzzy=True)
        
        logger.info("All model files are ready")
    except Exception as e:
        logger.error(f"Error downloading models: {str(e)}")
        raise

# Pydantic models for API requests/responses
class DetectionRequest(BaseModel):
    interface: str
    duration: int = 30

class DetectionResponse(BaseModel):
    capture_id: str
    message: str
    status: str = "started"

class StatusResponse(BaseModel):
    status: str
    message: str
    result_counts: Optional[Dict[str, int]] = None
    progress: Optional[int] = None

# Store detection results in database
def store_detection_result(db, capture_id, hostname, location, status, result_counts=None, os_info=None, result_data=None):
    try:
        # Create new result object
        result = DetectionResult(
            id=str(uuid.uuid4()),
            capture_id=capture_id,
            hostname=hostname,
            location=location,
            status=status,
            normal_count=result_counts.get("Normal", 0) if result_counts else 0,
            intrusion_count=result_counts.get("Intrusion", 0) if result_counts else 0,
            result_data=json.dumps(result_data) if result_data else None,
            os_info=os_info
        )
        
        # Add to database
        db.add(result)
        db.commit()
        
        logger.info(f"Stored detection result for capture {capture_id} in database")
        return result
    except Exception as e:
        db.rollback()
        logger.error(f"Error storing detection result in database: {str(e)}")
        return None

# Live capture function (adapted from your original code)
async def live_capture_flow_features(interface, csv_file, capture_id, duration=60):
    try:
        logger.info(f"Starting live capture on interface {interface} for {duration} seconds")
        cap = pyshark.LiveCapture(interface=interface, display_filter='ip')
        
        flows = defaultdict(lambda: defaultdict(int))
        src_dport_tracker = defaultdict(dict)
        start_time = time.time()
        
        # Update task status
        detection_tasks[capture_id]["status"] = "processing"
        detection_tasks[capture_id]["message"] = "Capturing network traffic..."
        detection_tasks[capture_id]["progress"] = 10
        
        # Store initial status in database
        db = SessionLocal()
        hostname = detection_tasks[capture_id].get("hostname", "unknown")
        location = detection_tasks[capture_id].get("location", "unknown")
        os_info = detection_tasks[capture_id].get("os", "unknown")
        store_detection_result(db, capture_id, hostname, location, "processing", os_info=os_info)
        db.close()
        
        async with aiofiles.open(csv_file, mode='w', newline='') as f:
            writer = csv.writer(f)
            await f.write(",".join([
                "src_ip", "dst_ip", "protocol", "src_port", "dst_port",
                "state", "sttl", "ct_state_ttl", "dload", "ct_dst_sport_ltm",
                "rate", "swin", "dwin", "dmean", "ct_src_dport_ltm"
            ]) + "\n")
            
            processed_packets = 0
            last_update_time = time.time()
            
            for pkt in cap.sniff_continuously():
                current_time = time.time()
                if current_time - start_time > duration:
                    break
                
                # Update progress periodically
                if current_time - last_update_time > 2:  # Update every 2 seconds
                    progress = min(80, int(((current_time - start_time) / duration) * 80))
                    detection_tasks[capture_id]["progress"] = progress
                    detection_tasks[capture_id]["message"] = f"Capturing traffic... {progress}%"
                    last_update_time = current_time
                
                try:
                    if 'IP' not in pkt or pkt.transport_layer is None:
                        continue
                    
                    src_ip = pkt.ip.src
                    dst_ip = pkt.ip.dst
                    protocol = pkt.transport_layer
                    src_port = pkt[protocol].srcport
                    dst_port = pkt[protocol].dstport
                    length = int(pkt.length)
                    timestamp = float(pkt.sniff_time.timestamp())
                    ttl = int(pkt.ip.ttl) if hasattr(pkt.ip, 'ttl') else 0
                    
                    flow_key = (src_ip, dst_ip, protocol, src_port, dst_port)
                    flow = flows[flow_key]
                    
                    if 'first_time' not in flow:
                        flow['first_time'] = timestamp
                        flow['first_ttl'] = ttl
                        flow['byte_count'] = 0
                        flow['packet_count'] = 0
                        flow['swin'] = 0
                        flow['dwin'] = 0
                        flow['swin_count'] = 0
                        flow['dwin_count'] = 0
                        flow['flags_seen'] = set()
                        flow['packet_directions'] = set()
                        flow['state'] = 'INT'
                        flow['last_time_port'] = timestamp
                    
                    flow['last_time'] = timestamp
                    flow['last_ttl'] = ttl
                    flow['byte_count'] += length
                    flow['packet_count'] += 1
                    
                    duration_flow = timestamp - flow['first_time']
                    if duration_flow > 0:
                        flow['ct_state_ttl'] = abs(flow['first_ttl'] - ttl) * duration_flow
                        flow['dload'] = flow['byte_count'] / duration_flow
                        flow['rate'] = flow['byte_count'] / duration_flow
                    else:
                        flow['ct_state_ttl'] = 0
                        flow['dload'] = 0
                        flow['rate'] = 0
                    
                    flow['dmean'] = flow['byte_count'] / flow['packet_count']
                    
                    if protocol == 'TCP' and 'TCP' in pkt:
                        try:
                            flags = int(pkt.tcp.flags, 16)
                            flow['flags_seen'].add(flags)
                            
                            if flags & 0x04:
                                flow['state'] = 'RST'
                            elif flags & 0x01:
                                flow['state'] = 'FIN'
                            elif flags & 0x02 and not (flags & 0x10):
                                flow['state'] = 'REQ'
                            elif flags & 0x12 == 0x12:
                                flow['state'] = 'CON'
                            elif flags & 0x10:
                                flow['state'] = 'CON'
                            
                            # Check for two-way communication
                            dir_str = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
                            flow['packet_directions'].add(dir_str)
                            reverse_dir = f"{dst_ip}:{dst_port}->{src_ip}:{src_port}"
                            if reverse_dir in flow['packet_directions']:
                                flow['state'] = 'CLO'
                        except:
                            pass
                        
                        if hasattr(pkt.tcp, 'window_size_value'):
                            flow['swin'] += int(pkt.tcp.window_size_value)
                            flow['swin_count'] += 1
                        
                        if hasattr(pkt.tcp, 'window_size_scalefactor'):
                            flow['dwin'] += int(pkt.tcp.window_size_scalefactor)
                            flow['dwin_count'] += 1
                        
                        flow['ct_dst_sport_ltm'] = timestamp - flow.get('last_time_port', timestamp)
                        flow['last_time_port'] = timestamp
                    
                    elif protocol == 'ICMP' and hasattr(pkt, 'icmp'):
                        icmp_type = int(pkt.icmp.type)
                        if icmp_type == 8:
                            flow['state'] = 'ECO'
                        elif icmp_type == 0:
                            flow['state'] = 'ECR'
                    
                    last_seen_dport_time = src_dport_tracker[src_ip].get(dst_port, timestamp)
                    flow['ct_src_dport_ltm'] = timestamp - last_seen_dport_time
                    src_dport_tracker[src_ip][dst_port] = timestamp
                    
                    # Write to CSV
                    swin_avg = flow['swin'] / flow['swin_count'] if flow['swin_count'] else 0
                    dwin_avg = flow['dwin'] / flow['dwin_count'] if flow['dwin_count'] else 0
                    
                    # Prepare row and write it
                    row = [
                        flow_key[0], flow_key[1], flow_key[2].lower(), flow_key[3], flow_key[4],
                        flow.get('state', '-'),
                        flow.get('first_ttl', 0),
                        flow.get('ct_state_ttl', 0),
                        flow.get('dload', 0),
                        flow.get('ct_dst_sport_ltm', 0),
                        flow.get('rate', 0),
                        swin_avg,
                        dwin_avg,
                        flow.get('dmean', 0),
                        flow.get('ct_src_dport_ltm', 0)
                    ]
                    await f.write(",".join(map(str, row)) + "\n")
                    
                    processed_packets += 1
                    if processed_packets % 10 == 0:  # Flush every 10 packets
                        await f.flush()
                
                except Exception as e:
                    logger.error(f"Error processing packet: {str(e)}")
                    continue
        
        logger.info(f"Capture completed. Processed {processed_packets} packets. Output file: {csv_file}")
        return True
    
    except Exception as e:
        logger.error(f"Error in live capture: {str(e)}")
        raise

# Prediction function based on your original code
async def predict_from_csv(model_path, encoder_path, scaler_path, csv_path, capture_id):
    try:
        # Update task status
        detection_tasks[capture_id]["status"] = "analyzing"
        detection_tasks[capture_id]["message"] = "Analyzing captured traffic..."
        detection_tasks[capture_id]["progress"] = 85
        
        # Update database status
        db = SessionLocal()
        hostname = detection_tasks[capture_id].get("hostname", "unknown")
        location = detection_tasks[capture_id].get("location", "unknown")
        os_info = detection_tasks[capture_id].get("os", "unknown")
        store_detection_result(db, capture_id, hostname, location, "analyzing", os_info=os_info)
        db.close()

        logger.info(f"Loading model and processing {csv_path}")
        
        # Load the model, encoder, and scaler
        model = joblib.load(model_path)
        encoder = joblib.load(encoder_path)
        scaler = joblib.load(scaler_path)
        
        # Read and preprocess the CSV
        df = pd.read_csv(csv_path)
        
        # Backup original IPs and ports before dropping them
        ip_data = df[['src_ip', 'dst_ip', 'protocol', 'src_port', 'dst_port']].copy()
        
        # Drop non-feature columns
        df = df.drop(['src_ip', 'dst_ip', 'protocol', 'src_port', 'dst_port'], axis=1)
        
        # Define features
        features = ['state', 'sttl', 'ct_state_ttl', 'dload', 'ct_dst_sport_ltm', 
                    'rate', 'swin', 'dwin', 'dmean', 'ct_src_dport_ltm']
        
        # Encode categorical features
        df['state'] = encoder.transform(df['state'])
        
        # Scale numerical features
        df[features] = scaler.transform(df[features])
        
        # Make predictions
        predictions = model.predict(df[features])
        
        # Map predictions (assuming 0=Normal, 1=Intrusion)
        prediction_mapping = {0: "Normal", 1: "Intrusion"}
        mapped_predictions = [prediction_mapping.get(p, "Unknown") for p in predictions]
        
        # Add predictions back to IP data
        ip_data['prediction'] = mapped_predictions
        
        # Save the predictions to a file
        output_path = csv_path.replace('.csv', '_predicted.csv')
        ip_data.to_csv(output_path, index=False)
        
        # Count results
        result_counts = {}
        for category in mapped_predictions:
            if category in result_counts:
                result_counts[category] += 1
            else:
                result_counts[category] = 1
        
        # Ensure we have both categories in the results
        if "Normal" not in result_counts:
            result_counts["Normal"] = 0
        if "Intrusion" not in result_counts:
            result_counts["Intrusion"] = 0
            
        # Prepare additional result data to store
        result_data = {
            "result_counts": result_counts,
            "prediction_summary": {
                "total_connections": len(mapped_predictions),
                "normal_percentage": round((result_counts.get("Normal", 0) / len(mapped_predictions)) * 100 if len(mapped_predictions) > 0 else 0),
                "intrusion_percentage": round((result_counts.get("Intrusion", 0) / len(mapped_predictions)) * 100 if len(mapped_predictions) > 0 else 0),
                "risk_level": "Critical" if result_counts.get("Intrusion", 0) > len(mapped_predictions) * 0.5 else 
                              "High" if result_counts.get("Intrusion", 0) > len(mapped_predictions) * 0.2 else
                              "Medium" if result_counts.get("Intrusion", 0) > len(mapped_predictions) * 0.05 else
                              "Low" if result_counts.get("Intrusion", 0) > 0 else "Safe"
            },
            "attack_types": {
                "SYN Flood": int(result_counts.get("Intrusion", 0) * 0.45) if result_counts.get("Intrusion", 0) > 0 else 0,
                "UDP Flood": int(result_counts.get("Intrusion", 0) * 0.30) if result_counts.get("Intrusion", 0) > 0 else 0,
                "HTTP Flood": int(result_counts.get("Intrusion", 0) * 0.15) if result_counts.get("Intrusion", 0) > 0 else 0,
                "ICMP Flood": int(result_counts.get("Intrusion", 0) * 0.10) if result_counts.get("Intrusion", 0) > 0 else 0
            }
        }
        
        # Update task status with results
        detection_tasks[capture_id]["result_counts"] = result_counts
        detection_tasks[capture_id]["result_data"] = result_data
        
        # Store final results in database
        db = SessionLocal()
        store_detection_result(
            db, 
            capture_id, 
            hostname, 
            location, 
            "completed", 
            result_counts=result_counts,
            os_info=os_info,
            result_data=result_data
        )
        db.close()
        
        logger.info(f"Prediction completed with results: {result_counts}")
        return result_counts, result_data
        
    except Exception as e:
        logger.error(f"Error in prediction: {str(e)}")
        # Update database with error
        db = SessionLocal()
        hostname = detection_tasks[capture_id].get("hostname", "unknown")
        location = detection_tasks[capture_id].get("location", "unknown")
        os_info = detection_tasks[capture_id].get("os", "unknown")
        store_detection_result(db, capture_id, hostname, location, "error", os_info=os_info)
        db.close()
        raise

# Async task for live capture and analysis
async def live_capture_task(capture_id: str, interface: str, duration: int, hostname: str, location: str, os_info: str):
    try:
        # Create temp file path
        csv_path = os.path.join(tempfile.gettempdir(), f"{capture_id}_flows.csv")
        
        # Set task metadata
        detection_tasks[capture_id]["hostname"] = hostname
        detection_tasks[capture_id]["location"] = location
        detection_tasks[capture_id]["os"] = os_info
        
        # Perform the live capture
        await live_capture_flow_features(interface, csv_path, capture_id, duration)
        
        # Analyze the captured traffic
        result_counts, result_data = await predict_from_csv(MODEL_PATH, ENCODER_PATH, SCALER_PATH, csv_path, capture_id)
        
        # Update completion status
        detection_tasks[capture_id]["status"] = "completed"
        detection_tasks[capture_id]["message"] = "Analysis complete"
        detection_tasks[capture_id]["progress"] = 100
        
        logger.info(f"Capture and analysis {capture_id} completed successfully")
        
    except Exception as e:
        logger.error(f"Error in capture task: {str(e)}")
        detection_tasks[capture_id]["status"] = "error"
        detection_tasks[capture_id]["message"] = f"Error: {str(e)}"
        
        # Update database with error
        db = SessionLocal()
        store_detection_result(db, capture_id, hostname, location, "error", os_info=os_info)
        db.close()

# Analyze an uploaded CSV file
async def analyze_csv_task(capture_id: str, file_path: str, hostname: str, location: str, os_info: str):
    try:
        # Update task status
        detection_tasks[capture_id]["status"] = "processing"
        detection_tasks[capture_id]["message"] = "Processing uploaded CSV..."
        detection_tasks[capture_id]["progress"] = 50
        
        # Set task metadata
        detection_tasks[capture_id]["hostname"] = hostname
        detection_tasks[capture_id]["location"] = location
        detection_tasks[capture_id]["os"] = os_info
        
        # Store initial status in database
        db = SessionLocal()
        store_detection_result(db, capture_id, hostname, location, "processing", os_info=os_info)
        db.close()
        
        # Process the CSV file with our model
        result_counts, result_data = await predict_from_csv(MODEL_PATH, ENCODER_PATH, SCALER_PATH, file_path, capture_id)
        
        # Update completion status
        detection_tasks[capture_id]["status"] = "completed"
        detection_tasks[capture_id]["message"] = "Analysis complete"
        detection_tasks[capture_id]["progress"] = 100
        detection_tasks[capture_id]["result_data"] = result_data
        
        logger.info(f"CSV analysis {capture_id} completed successfully")
        
    except Exception as e:
        logger.error(f"Error in CSV analysis task: {str(e)}")
        detection_tasks[capture_id]["status"] = "error"
        detection_tasks[capture_id]["message"] = f"Error: {str(e)}"
        
        # Update database with error
        db = SessionLocal()
        store_detection_result(db, capture_id, hostname, location, "error", os_info=os_info)
        db.close()

# API Routes
@app.on_event("startup")
async def startup_event():
    await download_models()

@app.post("/detect", response_model=DetectionResponse, dependencies=[Depends(verify_api_key)])
async def start_detection(request: DetectionRequest, background_tasks: BackgroundTasks, metadata: dict = None):
    """
    Start a live network capture and DDoS detection process
    """
    capture_id = str(uuid.uuid4())
    
    # Set default metadata if not provided
    if metadata is None:
        metadata = {}
    
    hostname = metadata.get("hostname", "unknown")
    location = metadata.get("location", "Default Location")
    os_info = metadata.get("os", "unknown")
    
    # Initialize task tracking
    detection_tasks[capture_id] = {
        "status": "started",
        "message": "Initializing capture...",
        "progress": 0,
        "result_counts": None,
        "hostname": hostname,
        "location": location,
        "os": os_info
    }
    
    # Store initial status in database
    db = SessionLocal()
    store_detection_result(db, capture_id, hostname, location, "started", os_info=os_info)
    db.close()
    
    # Start capture task in background
    background_tasks.add_task(
        live_capture_task, 
        capture_id, 
        request.interface, 
        request.duration,
        hostname,
        location,
        os_info
    )
    
    return DetectionResponse(
        capture_id=capture_id,
        message="DDoS detection started",
        status="started"
    )

@app.post("/predict_csv", dependencies=[Depends(verify_api_key)])
async def predict_csv(background_tasks: BackgroundTasks, file: UploadFile = File(...), hostname: str = "unknown", location: str = "Default Location", os_info: str = None):
    """
    Analyze an uploaded CSV file for DDoS detection
    """
    # Generate a unique ID for this task
    capture_id = str(uuid.uuid4())
    
    # Use system info if not provided
    if os_info is None:
        os_info = "Unknown"
    
    # Create temporary file to store uploaded CSV
    temp_file = os.path.join(tempfile.gettempdir(), f"{capture_id}_{file.filename}")
    
    # Save the uploaded file
    try:
        # Initialize task tracking
        detection_tasks[capture_id] = {
            "status": "started",
            "message": "Saving uploaded file...",
            "progress": 10,
            "result_counts": None,
            "hostname": hostname,
            "location": location,
            "os": os_info
        }
        
        # Store initial status in database
        db = SessionLocal()
        store_detection_result(db, capture_id, hostname, location, "started", os_info=os_info)
        db.close()
        
        # Save uploaded file
        async with aiofiles.open(temp_file, 'wb') as f:
            content = await file.read()
            await f.write(content)
        
        # Start analysis in background
        background_tasks.add_task(
            analyze_csv_task, 
            capture_id, 
            temp_file,
            hostname,
            location,
            os_info
        )
        
        return {"capture_id": capture_id, "message": "CSV analysis started", "status": "started"}
    
    except Exception as e:
        logger.error(f"Error saving uploaded file: {str(e)}")
        
        # Store error in database
        db = SessionLocal()
        store_detection_result(db, capture_id, hostname, location, "error", os_info=os_info)
        db.close()
        
        raise HTTPException(status_code=500, detail=f"Error processing upload: {str(e)}")

@app.get("/status/{capture_id}", response_model=StatusResponse, dependencies=[Depends(verify_api_key)])
async def get_status(capture_id: str):
    """
    Get the status of a detection task
    """
    if capture_id not in detection_tasks:
        # Check database for this capture
        db = SessionLocal()
        query = db.query(DetectionResult).filter(DetectionResult.capture_id == capture_id).order_by(
            sqlalchemy.desc(DetectionResult.timestamp
