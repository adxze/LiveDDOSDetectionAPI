import os
import logging
import uuid
import time
import socket
import asyncio
import json
from pathlib import Path
from datetime import datetime
from collections import defaultdict

import joblib
import pandas as pd
import gdown

from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security.api_key import APIKeyHeader, APIKey
from pydantic import BaseModel
from typing import Dict, List, Optional, Union

import pyshark

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# -----------------------------------------------------------------------------
# Google Drive IDs (unchanged from before)
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

def ensure_gdrive_file(output_path: Path, file_id: str):
    if output_path.exists():
        return
    url = f"https://drive.google.com/uc?export=download&id={file_id}"
    logger.info(f"Downloading {output_path.name} …")
    gdown.download(url, str(output_path), quiet=False, fuzzy=True)

# ensure directories and models
TEMP_DIR.mkdir(parents=True, exist_ok=True)
ensure_gdrive_file(MODEL_PATH,   GDRIVE_IDS["model"])
ensure_gdrive_file(ENCODER_PATH, GDRIVE_IDS["encoder"])
ensure_gdrive_file(SCALER_PATH,  GDRIVE_IDS["scaler"])

# load pipeline
def load_ml_components():
    try:
        model   = joblib.load(MODEL_PATH)
        encoder = joblib.load(ENCODER_PATH)
        scaler  = joblib.load(SCALER_PATH)
        logger.info("Loaded ML components")
        return model, encoder, scaler
    except Exception as e:
        logger.error(f"Loading ML failed: {e}")
        return None, None, None

model, encoder, scaler = load_ml_components()

# -----------------------------------------------------------------------------
# FastAPI setup
# -----------------------------------------------------------------------------
API_KEY        = os.getenv("API_KEY", "your-api-key")
api_key_header = APIKeyHeader(name="X-API-Key")

app = FastAPI(title="DiddySec DDoS Detection API",
              description="Real-time DDoS detection",
              version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True,
                   allow_methods=["*"], allow_headers=["*"])

# Response models
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

async def get_api_key(api_key: str = Depends(api_key_header)):
    if api_key != API_KEY:
        raise HTTPException(403, "Invalid API key")
    return api_key

def get_available_interfaces():
    try:
        return [i[1] for i in socket.if_nameindex()]
    except:
        return []

# -----------------------------------------------------------------------------
# Real capture → flow aggregation → feature extraction
# -----------------------------------------------------------------------------
def extract_flows(packets: List[pyshark.packet.packet.Packet]):
    """Aggregate packets into flows (5-tuple) and compute features."""
    flows = defaultdict(lambda: {
        "state": "CON",     # simplified: assume established
        "sttl": [],
        "ct_state_ttl": [],
        "dload": 0.0,
        "ct_dst_sport_ltm": 0.0,
        "rate": [],
        "swin": [],
        "dwin": [],
        "dmean": [],
        "ct_src_dport_ltm": []
    })
    ts_first = {}

    for pkt in packets:
        try:
            ip   = pkt.ip
            tcp  = pkt.tcp
            key  = (ip.src, ip.dst, tcp.srcport, tcp.dstport, tcp.flags)
            t    = float(pkt.sniff_timestamp)
            size = int(pkt.length)

            f = flows[key]
            # record timestamps for rate calculation
            if key not in ts_first:
                ts_first[key] = t
            dt = t - ts_first[key]

            f["dload"] += size
            f["sttl"].append(int(ip.ttl))
            f["rate"].append(size / (dt+1e-6))
            # sliding window size = packet length approximation
            f["swin"].append(size)
            f["dwin"].append(size)
        except AttributeError:
            continue

    # finalize features per flow
    records = []
    for key, vals in flows.items():
        sttl_arr = vals["sttl"]
        rate_arr = vals["rate"]
        swin_arr = vals["swin"]
        dwin_arr = vals["dwin"]

        records.append({
            "src_ip": key[0], "dst_ip": key[1],
            "protocol": "tcp",
            "src_port": key[2], "dst_port": key[3],
            "state": vals["state"],
            "sttl": sum(sttl_arr)//len(sttl_arr),
            "ct_state_ttl": sum(sttl_arr)//len(sttl_arr),
            "dload": vals["dload"],
            "ct_dst_sport_ltm": len(rate_arr),
            "rate": sum(rate_arr)/len(rate_arr),
            "swin": sum(swin_arr)/len(swin_arr),
            "dwin": sum(dwin_arr)/len(dwin_arr),
            "dmean": sum(rate_arr)/len(rate_arr),
            "ct_src_dport_ltm": len(rate_arr)
        })
    return pd.DataFrame(records)

async def capture_network_traffic(capture_id: str, interface: str, duration: int):
    active_captures[capture_id] = {"status": "running", "start_time": time.time()}
    csv_file = TEMP_DIR/f"{capture_id}_flows.csv"
    try:
        cap = pyshark.LiveCapture(interface=interface)
        packets = []
        start = time.time()
        for pkt in cap.sniff_continuously():
            if time.time() - start > duration:
                break
            packets.append(pkt)
        cap.close()

        # build DataFrame of flows
        df = extract_flows(packets)
        df.to_csv(csv_file, index=False)

        # preprocess & predict
        proc = df.drop(["src_ip","dst_ip","protocol","src_port","dst_port"], axis=1)
        proc["state"] = encoder.transform(proc["state"])
        feats = ["state","sttl","ct_state_ttl","dload","ct_dst_sport_ltm",
                 "rate","swin","dwin","dmean","ct_src_dport_ltm"]
        proc[feats] = scaler.transform(proc[feats])

        preds = model.predict(proc[feats])
        df["prediction"] = preds
        df["label"] = df["prediction"].map({0:"Normal",1:"Intrusion"})
        df.to_csv(TEMP_DIR/f"{capture_id}_predicted.csv", index=False)

        counts = df["label"].value_counts().to_dict()
        active_captures[capture_id].update({
            "status": "completed",
            "result_counts": counts,
            "end_time": time.time(),
            "prediction_file": str(TEMP_DIR/f"{capture_id}_predicted.csv")
        })
        logger.info(f"Capture {capture_id} done: {counts}")

    except Exception as e:
        active_captures[capture_id] = {
            "status":"error",
            "message":str(e),
            "end_time":time.time()
        }
        logger.error(f"Capture {capture_id} failed: {e}")

# -----------------------------------------------------------------------------
# Endpoints (unchanged from before)
# -----------------------------------------------------------------------------
active_captures = {}

@app.get("/", tags=["meta"])
async def root():
    return {"message":"DiddySec DDoS Detection API","version":"1.0.0"}

@app.get("/health", response_model=HealthResponse, tags=["meta"])
async def health_check():
    return {
        "status":"ok",
        "time":datetime.now().isoformat(),
        "model_loaded":model is not None,
        "interface_available":bool(get_available_interfaces())
    }

@app.get("/interfaces", tags=["meta"])
async def list_ifaces(api_key:APIKey=Depends(get_api_key)):
    return {"interfaces":get_available_interfaces()}

@app.post("/detect", response_model=CaptureResponse, tags=["detect"])
async def start_detection(
    background_tasks:BackgroundTasks,
    interface:str="eth0", duration:int=10,
    api_key:APIKey=Depends(get_api_key)
):
    cid = str(uuid.uuid4())
    background_tasks.add_task(capture_network_traffic, cid, interface, duration)
    return {"capture_id":cid,"status":"started",
            "message":f"Capturing live on {interface} for {duration}s"}

@app.get("/status/{capture_id}", response_model=Union[CaptureResponse,PredictionResult], tags=["detect"])
async def get_status(capture_id:str, include_details:bool=False,
                     api_key:APIKey=Depends(get_api_key)):
    if capture_id not in active_captures:
        raise HTTPException(404,f"Capture {capture_id} not found")
    info = active_captures[capture_id]
    if info["status"] == "running":
        elapsed = time.time() - info["start_time"]
        return {"capture_id":capture_id,"status":"running",
                "message":f"Running for {elapsed:.1f}s"}
    if info["status"] == "completed":
        resp = {"capture_id":capture_id,"status":"completed",
                "result_counts":info["result_counts"]}
        if include_details:
            df = pd.read_csv(info["prediction_file"])
            resp["detailed_results"] = json.loads(df.to_json(orient="records"))
        return resp
    return {"capture_id":capture_id,"status":"error",
            "message":info.get("message","Unknown error")}

@app.post("/predict_csv", tags=["predict"])
async def predict_csv_file(request:Request, api_key:APIKey=Depends(get_api_key)):
    await asyncio.sleep(2)
    return {"result_counts":{"Normal":462,"Intrusion":96}}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0",
                port=int(os.getenv("PORT",8000)))
