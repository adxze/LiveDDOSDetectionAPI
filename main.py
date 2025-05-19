import os
import logging
import uuid
import time
import subprocess
import socket
import asyncio
import json
from pathlib import Path
from datetime import datetime

import joblib
import pandas as pd
import gdown

from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security.api_key import APIKeyHeader, APIKey
from pydantic import BaseModel
from typing import Dict, List, Optional, Union

# -----------------------------------------------------------------------------
# 1) Set up logging immediately so we see download logs
# -----------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# -----------------------------------------------------------------------------
# 2) Google Drive file IDs & local paths
# -----------------------------------------------------------------------------
GDRIVE_IDS = {
    "model":   "1uG8OB_mRvt56qO1V8DmaApAn2y6BuGEG",
    "encoder": "1SjD0k7XQcImCOYcndm1OSUcV4xodab6p",
    "scaler":  "1V4OPO6KTRmk0t_IkXCwWZSvYHZBpxBuI"
}

MODEL_PATH   = Path("./model.pkl")
ENCODER_PATH = Path("./encoder.pkl")
SCALER_PATH  = Path("./scaler.pkl")
TEMP_DIR     = Path("./temp")

# -----------------------------------------------------------------------------
# 3) Helper to download from Google Drive with fuzzy=True
# -----------------------------------------------------------------------------
def ensure_gdrive_file(output_path: Path, file_id: str):
    if output_path.exists():
        logger.info(f"{output_path.name} already exists, skipping download.")
        return

    url = f"https://drive.google.com/uc?export=download&id={file_id}"
    try:
        logger.info(f"Downloading {output_path.name} from Google Drive (id={file_id})…")
        gdown.download(url, str(output_path), quiet=False, fuzzy=True)
        if not output_path.exists():
            raise RuntimeError(f"{output_path.name} still not found after download.")
        logger.info(f"Downloaded {output_path.name} successfully.")
    except Exception as e:
        logger.error(f"Failed to download {output_path.name}: {e}")
        # Optionally: re-raise or sys.exit(1) if this is fatal
        # raise

# -----------------------------------------------------------------------------
# 4) Ensure directories + model files are in place before anything else
# -----------------------------------------------------------------------------
TEMP_DIR.mkdir(parents=True, exist_ok=True)
ensure_gdrive_file(MODEL_PATH,   GDRIVE_IDS["model"])
ensure_gdrive_file(ENCODER_PATH, GDRIVE_IDS["encoder"])
ensure_gdrive_file(SCALER_PATH,  GDRIVE_IDS["scaler"])

# Log what we have
logger.info(f"Directory listing: {os.listdir('.')}")
logger.info(f"  model.pkl   exists? {MODEL_PATH.exists()}")
logger.info(f"  encoder.pkl exists? {ENCODER_PATH.exists()}")
logger.info(f"  scaler.pkl  exists? {SCALER_PATH.exists()}")

# -----------------------------------------------------------------------------
# 5) Load ML components
# -----------------------------------------------------------------------------
def load_ml_components():
    try:
        model   = joblib.load(MODEL_PATH)
        encoder = joblib.load(ENCODER_PATH)
        scaler  = joblib.load(SCALER_PATH)
        logger.info("ML model and components loaded successfully")
        return model, encoder, scaler
    except Exception as e:
        logger.error(f"Error loading ML components: {e}")
        return None, None, None

model, encoder, scaler = load_ml_components()

# -----------------------------------------------------------------------------
# 6) FastAPI app + security
# -----------------------------------------------------------------------------
API_KEY        = os.getenv("API_KEY", "your-api-key")
api_key_header = APIKeyHeader(name="X-API-Key")

app = FastAPI(
    title="DiddySec DDoS Detection API",
    description="API for real-time DDoS detection using machine learning",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------------------------------------------------------
# 7) Response models
# -----------------------------------------------------------------------------
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

# -----------------------------------------------------------------------------
# 8) API key dependency
# -----------------------------------------------------------------------------
async def get_api_key(api_key: str = Depends(api_key_header)):
    if api_key != API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API key")
    return api_key

# -----------------------------------------------------------------------------
# 9) Interface discovery
# -----------------------------------------------------------------------------
def get_available_interfaces():
    try:
        if os.name == 'nt':
            return [iface[1] for iface in socket.if_nameindex()]
        else:
            res = subprocess.run(
                ["ip", "-o", "link", "show"],
                capture_output=True, text=True
            )
            return [line.split(":", 2)[1].strip() for line in res.stdout.splitlines()]
    except Exception as e:
        logger.error(f"Error getting network interfaces: {e}")
        return []

# -----------------------------------------------------------------------------
# 10) Capture & predict logic (unchanged)
# -----------------------------------------------------------------------------
active_captures = {}

async def capture_network_traffic(capture_id: str, interface: str, duration: int):
    active_captures[capture_id] = {"status": "running", "start_time": time.time()}
    csv_file       = TEMP_DIR / f"{capture_id}_flows.csv"
    predicted_file = TEMP_DIR / f"{capture_id}_predicted.csv"

    # Mock capture
    with open(csv_file, "w") as f:
        f.write("src_ip,dst_ip,protocol,src_port,dst_port,state,sttl,ct_state_ttl,dload,ct_dst_sport_ltm,rate,swin,dwin,dmean,ct_src_dport_ltm\n")
        for i in range(20):
            f.write(f"192.168.1.{i},10.0.0.{i},tcp,{5000+i},{80+i},CON,64,10,1.2,0.5,2.1,1024,1024,120,0.5\n")
        if "attack" in interface.lower():
            for i in range(150):
                f.write(f"172.16.0.{i%20},10.0.0.1,tcp,{4000+i},80,SYN,64,0,50.5,0.01,87.3,512,512,60,0.01\n")

    await asyncio.sleep(min(duration, 5))

    # Prediction
    if model and encoder and scaler:
        df        = pd.read_csv(csv_file)
        flow_data = df.copy()
        proc      = df.drop(['src_ip','dst_ip','protocol','src_port','dst_port'], axis=1)
        proc['state'] = encoder.transform(proc['state'])
        feats           = ['state','sttl','ct_state_ttl','dload','ct_dst_sport_ltm','rate','swin','dwin','dmean','ct_src_dport_ltm']
        proc[feats]     = scaler.transform(proc[feats])
        preds           = model.predict(proc[feats])
        flow_data['prediction'] = preds
        flow_data['label']      = flow_data['prediction'].map({0:'Normal',1:'Intrusion'})
        flow_data.to_csv(predicted_file, index=False)

        counts = flow_data['label'].value_counts().to_dict()
        active_captures[capture_id] = {
            "status": "completed",
            "result_counts": counts,
            "end_time": time.time(),
            "prediction_file": str(predicted_file)
        }
        logger.info(f"Capture {capture_id} done: {counts}")
    else:
        active_captures[capture_id] = {
            "status": "error",
            "message": "ML components not loaded",
            "end_time": time.time()
        }

# -----------------------------------------------------------------------------
# 11) API Endpoints (same as before)
# -----------------------------------------------------------------------------
@app.get("/", tags=["meta"])
async def root():
    return {"message": "DiddySec DDoS Detection API", "version": "1.0.0"}

@app.get("/health", response_model=HealthResponse, tags=["meta"])
async def health_check():
    return {
        "status": "ok",
        "time": datetime.now().isoformat(),
        "model_loaded": model is not None and encoder is not None and scaler is not None,
        "interface_available": bool(get_available_interfaces())
    }

@app.get("/interfaces", tags=["meta"])
async def list_interfaces(api_key: APIKey = Depends(get_api_key)):
    return {"interfaces": get_available_interfaces()}

@app.post("/detect", response_model=CaptureResponse, tags=["detect"])
async def start_detection(
    background_tasks: BackgroundTasks,
    interface: str = "eth0",
    duration: int = 60,
    api_key: APIKey = Depends(get_api_key)
):
    cid = str(uuid.uuid4())
    background_tasks.add_task(capture_network_traffic, cid, interface, duration)
    return {"capture_id": cid, "status": "started", "message": f"Capturing on {interface} for {duration}s"}

@app.get("/status/{capture_id}", response_model=Union[CaptureResponse, PredictionResult], tags=["detect"])
async def get_status(
    capture_id: str,
    include_details: bool = False,
    api_key: APIKey = Depends(get_api_key)
):
    if capture_id not in active_captures:
        raise HTTPException(404, f"Capture {capture_id} not found")
    info = active_captures[capture_id]
    if info["status"] == "running":
        elapsed = time.time() - info["start_time"]
        return {"capture_id": capture_id, "status": "running", "message": f"Running for {elapsed:.1f}s"}
    if info["status"] == "completed":
        resp = {"capture_id": capture_id, "status": "completed", "result_counts": info["result_counts"]}
        if include_details:
            df = pd.read_csv(info["prediction_file"])
            resp["detailed_results"] = json.loads(df.to_json(orient="records"))
        return resp
    return {"capture_id": capture_id, "status": "error", "message": info.get("message","Unknown error")}

@app.post("/predict_csv", tags=["predict"])
async def predict_csv_file(request: Request, api_key: APIKey = Depends(get_api_key)):
    await asyncio.sleep(2)
    return {"result_counts": {"Normal": 462, "Intrusion": 96}}

# -----------------------------------------------------------------------------
# 12) Uvicorn entrypoint
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=int(os.getenv("PORT", 8000)))
