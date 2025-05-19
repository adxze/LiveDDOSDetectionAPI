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

# New imports for database
import sqlalchemy
from sqlalchemy import create_engine, Column, Integer, String, DateTime, JSON, Float, Text, Boolean, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime, timedelta
import databases

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

# Database configuration
DATABASE_URL = os.environ.get("DATABASE_URL", "").replace("postgres://", "postgresql://")
if not DATABASE_URL:
    logger.warning("No DATABASE_URL environment variable found. Using SQLite database.")
    DATABASE_URL = "sqlite:///./diddysec.db"

# SQLAlchemy setup
database = databases.Database(DATABASE_URL)
Base = declarative_base()

# Define database models
class DetectionResult(Base):
    __tablename__ = "detection_results"
    
    id = Column(Integer, primary_key=True, index=True)
    capture_id = Column(String, unique=True, index=True)
    hostname = Column(String)
    location = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)
    status = Column(String)
    normal_count = Column(Integer, default=0)
    intrusion_count = Column(Integer, default=0)
    os = Column(String)
    result_json = Column(sqlalchemy.JSON)
    is_critical = Column(Boolean, default=False)

# Initialize database engine
engine = create_engine(DATABASE_URL)
Base.metadata.create_all(bind=engine)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

app = FastAPI(title="DDoS Detection API", description="API for detecting DDoS attacks in network traffic")

# Add CORS middleware to allow requests from your frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Specify your frontend URL in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Function to clean up old data (older than 24 hours)
async def cleanup_old_data():
    while True:
        try:
            logger.info("Running scheduled cleanup of old detection data")
            one_day_ago = datetime.utcnow() - timedelta(days=1)
            
            # Proper SQL query for databases package
            query = "DELETE FROM detection_results WHERE timestamp < :old_time"
            await database.execute(query=query, values={"old_time": one_day_ago})
            
            logger.info("Cleanup completed")
        except Exception as e:
            logger.error(f"Error during cleanup: {str(e)}")
        
        # Run cleanup every 6 hours
        await asyncio.sleep(6 * 60 * 60)  # 6 hours in seconds

# API key validation dependency
async def verify_api_key(api_key: str = Depends(api_key_header)):
    if api_key != API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API key")
    return api_key

# Modified function to save results to database
async def save_detection_result(capture_id, metadata, result_counts):
    try:
        is_critical = False
        if result_counts and "Intrusion" in result_counts and "Normal" in result_counts:
            total = result_counts["Intrusion"] + result_counts["Normal"]
            if total > 0 and (result_counts["Intrusion"] / total) > 0.2:
                is_critical = True
        
        # Create query for databases package
        query = """
        INSERT INTO detection_results (
            capture_id, hostname, location, timestamp, status,
            normal_count, intrusion_count, os, result_json, is_critical
        ) VALUES (
            :capture_id, :hostname, :location, :timestamp, :status,
            :normal_count, :intrusion_count, :os, :result_json, :is_critical
        )
        """
        
        values = {
            "capture_id": capture_id,
            "hostname": metadata.get("hostname", "unknown"),
            "location": metadata.get("location", "unknown"),
            "timestamp": datetime.utcnow(),
            "status": "completed",
            "normal_count": result_counts.get("Normal", 0),
            "intrusion_count": result_counts.get("Intrusion", 0),
            "os": metadata.get("os", "unknown"),
            "result_json": result_counts,
            "is_critical": is_critical
        }
        
        await database.execute(query=query, values=values)
        logger.info(f"Detection result for {capture_id} saved to database")
    
    except Exception as e:
        logger.error(f"Error saving to database: {str(e)}")

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

# Live capture function
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

# Updated predict_from_csv function to save results to the database
async def predict_from_csv(model_path, encoder_path, scaler_path, csv_path, capture_id, metadata=None):
    try:
        # Update task status
        detection_tasks[capture_id]["status"] = "analyzing"
        detection_tasks[capture_id]["message"] = "Analyzing captured traffic..."
        detection_tasks[capture_id]["progress"] = 85

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
        
        # Update task status with results
        detection_tasks[capture_id]["result_counts"] = result_counts
        
        # Save results to the database
        if metadata is None:
            metadata = {}
        await save_detection_result(capture_id, metadata, result_counts)
        
        logger.info(f"Prediction completed with results: {result_counts}")
        return result_counts
        
    except Exception as e:
        logger.error(f"Error in prediction: {str(e)}")
        raise

# Async task for live capture and analysis
async def live_capture_task(capture_id: str, interface: str, duration: int):
    try:
        # Create temp file path
        csv_path = os.path.join(tempfile.gettempdir(), f"{capture_id}_flows.csv")
        
        # Perform the live capture
        await live_capture_flow_features(interface, csv_path, capture_id, duration)
        
        # Analyze the captured traffic
        await predict_from_csv(MODEL_PATH, ENCODER_PATH, SCALER_PATH, csv_path, capture_id)
        
        # Update completion status
        detection_tasks[capture_id]["status"] = "completed"
        detection_tasks[capture_id]["message"] = "Analysis complete"
        detection_tasks[capture_id]["progress"] = 100
        
        logger.info(f"Capture and analysis {capture_id} completed successfully")
        
    except Exception as e:
        logger.error(f"Error in capture task: {str(e)}")
        detection_tasks[capture_id]["status"] = "error"
        detection_tasks[capture_id]["message"] = f"Error: {str(e)}"

# Updated analyze_csv_task to use metadata
async def analyze_csv_task(capture_id: str, file_path: str, metadata: dict = None):
    try:
        # Update task status
        detection_tasks[capture_id]["status"] = "processing"
        detection_tasks[capture_id]["message"] = "Processing uploaded CSV..."
        detection_tasks[capture_id]["progress"] = 50
        
        # Process the CSV file with our model and pass metadata
        await predict_from_csv(MODEL_PATH, ENCODER_PATH, SCALER_PATH, file_path, capture_id, metadata)
        
        # Update completion status
        detection_tasks[capture_id]["status"] = "completed"
        detection_tasks[capture_id]["message"] = "Analysis complete"
        detection_tasks[capture_id]["progress"] = 100
        
        logger.info(f"CSV analysis {capture_id} completed successfully")
        
    except Exception as e:
        logger.error(f"Error in CSV analysis task: {str(e)}")
        detection_tasks[capture_id]["status"] = "error"
        detection_tasks[capture_id]["message"] = f"Error: {str(e)}"

# API Routes
@app.on_event("startup")
async def startup_event():
    await download_models()
    await database.connect()
    # Setup periodic clean up task
    asyncio.create_task(cleanup_old_data())

@app.on_event("shutdown")
async def shutdown_event():
    await database.disconnect()

@app.post("/detect", response_model=DetectionResponse, dependencies=[Depends(verify_api_key)])
async def start_detection(request: DetectionRequest, background_tasks: BackgroundTasks):
    """
    This endpoint is kept for API compatibility, but for actual network capture,
    we recommend using the local capture client which sends data to the /predict_csv endpoint.
    """
    capture_id = str(uuid.uuid4())
    
    # Initialize task tracking
    detection_tasks[capture_id] = {
        "status": "started",
        "message": "Initializing capture...",
        "progress": 0,
        "result_counts": None
    }
    
    # Start capture task in background
    background_tasks.add_task(live_capture_task, capture_id, request.interface, request.duration)
    
    return DetectionResponse(
        capture_id=capture_id,
        message="DDoS detection started",
        status="started"
    )

@app.post("/predict_csv", dependencies=[Depends(verify_api_key)])
async def predict_csv(
    background_tasks: BackgroundTasks, 
    file: UploadFile = File(...),
    hostname: str = None,
    location: str = None,
    os: str = None
):
    # Generate a unique ID for this task
    capture_id = str(uuid.uuid4())
    

    temp_file = f"/tmp/{capture_id}_upload.csv"
    
    
    # Save the uploaded file
    try:
        # Initialize task tracking
        detection_tasks[capture_id] = {
            "status": "started",
            "message": "Saving uploaded file...",
            "progress": 10,
            "result_counts": None
        }
        
        # Save uploaded file
        async with aiofiles.open(temp_file, 'wb') as f:
            content = await file.read()
            await f.write(content)
        
        # Create metadata dict
        metadata = {
            "hostname": hostname or "unknown",
            "location": location or "unknown",
            "os": os or "unknown",
            "capture_time": datetime.utcnow().isoformat()
        }
        
        # Start analysis in background with metadata
        background_tasks.add_task(
            analyze_csv_task, 
            capture_id, 
            temp_file,
            metadata
        )
        
        return {"capture_id": capture_id, "message": "CSV analysis started", "status": "started"}
    
    except Exception as e:
        logger.error(f"Error saving uploaded file: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error processing upload: {str(e)}")

@app.get("/status/{capture_id}", response_model=StatusResponse, dependencies=[Depends(verify_api_key)])
async def get_status(capture_id: str):
    if capture_id not in detection_tasks:
        raise HTTPException(status_code=404, detail="Task not found")
    
    task = detection_tasks[capture_id]
    return StatusResponse(
        status=task["status"],
        message=task["message"],
        result_counts=task["result_counts"],
        progress=task["progress"]
    )

@app.get("/results", dependencies=[Depends(verify_api_key)])
async def get_results(
    limit: int = 100, 
    critical_only: bool = False,
    hostname: Optional[str] = None
):
    """Get detection results from the database with optional filtering"""
    try:
        # Build the query
        query = "SELECT * FROM detection_results WHERE 1=1"
        params = {}
        
        if critical_only:
            query += " AND is_critical = :critical"
            params["critical"] = True
            
        if hostname:
            query += " AND hostname = :hostname"
            params["hostname"] = hostname
            
        # Add order and limit
        query += " ORDER BY timestamp DESC LIMIT :limit"
        params["limit"] = limit
        
        # Execute query
        results = await database.fetch_all(query=query, values=params)
        
        # Convert to list of dicts
        return [dict(result) for result in results]
        
    except Exception as e:
        logger.error(f"Error fetching results: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

@app.get("/stats", dependencies=[Depends(verify_api_key)])
async def get_statistics():
    """Get overall statistics of detections"""
    try:
        # Get count of all results
        total_query = "SELECT COUNT(*) as total FROM detection_results"
        total_result = await database.fetch_one(total_query)
        
        # Get count of critical detections
        critical_query = "SELECT COUNT(*) as critical FROM detection_results WHERE is_critical = true"
        critical_result = await database.fetch_one(critical_query)
        
        # Get stats by time period (last 24 hours)
        timeperiod_query = """
        SELECT 
            SUM(normal_count) as total_normal,
            SUM(intrusion_count) as total_intrusion
        FROM detection_results 
        WHERE timestamp > :day_ago
        """
        day_ago = datetime.utcnow() - timedelta(days=1)
        timeperiod_result = await database.fetch_one(
            timeperiod_query, 
            values={"day_ago": day_ago}
        )
        
        # Get hostname statistics
        hostname_query = """
        SELECT hostname, COUNT(*) as count 
        FROM detection_results 
        GROUP BY hostname 
        ORDER BY count DESC
        """
        hostname_results = await database.fetch_all(hostname_query)
        
        return {
            "total_detections": total_result["total"] if total_result else 0,
            "critical_detections": critical_result["critical"] if critical_result else 0,
            "last_24h": {
                "normal": timeperiod_result["total_normal"] if timeperiod_result else 0,
                "intrusion": timeperiod_result["total_intrusion"] if timeperiod_result else 0
            },
            "hosts": [
                {"hostname": result["hostname"], "count": result["count"]} 
                for result in hostname_results
            ]
        }
        
    except Exception as e:
        logger.error(f"Error getting statistics: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
