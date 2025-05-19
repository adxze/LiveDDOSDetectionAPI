import os
import time
import csv
import joblib
import gdown
import pyshark
import pandas as pd
from collections import defaultdict
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

# Google Drive file URLs (you can also put these in ENV vars on Railway)
MODEL_DRIVE_URL    = os.getenv("MODEL_DRIVE_URL",    "https://drive.google.com/uc?id=1A5qsfi1fF-SKmQfeDn3_-57qchSVsgt6")
ENCODER_DRIVE_URL  = os.getenv("ENCODER_DRIVE_URL",  "https://drive.google.com/uc?id=1sN4XIfQrVvbiFQycXgSeIMOZ_sjlaMKH")
SCALER_DRIVE_URL   = os.getenv("SCALER_DRIVE_URL",   "https://drive.google.com/uc?id=1NU1-XtorK4_3eWs6298tECI2ISNSaUAF")

MODEL_PATH   = "model.pkl"
ENCODER_PATH = "encoder.pkl"
SCALER_PATH  = "scaler.pkl"

app = FastAPI(title="Live Flow Predictor")

class CaptureParams(BaseModel):
    interface: str = "4"
    duration: int = 10  # seconds

def download_if_missing(url: str, out: str):
    if not os.path.exists(out):
        print(f"Downloading {out} from Drive…")
        gdown.download(url, out, quiet=False)

@app.on_event("startup")
def load_models():
    # get raw download links (use uc?id=… form for gdown)
    download_if_missing(MODEL_DRIVE_URL,   MODEL_PATH)
    download_if_missing(ENCODER_DRIVE_URL, ENCODER_PATH)
    download_if_missing(SCALER_DRIVE_URL,  SCALER_PATH)
    # load into memory
    app.state.model   = joblib.load(MODEL_PATH)
    app.state.encoder = joblib.load(ENCODER_PATH)
    app.state.scaler  = joblib.load(SCALER_PATH)
    print("Models loaded.")

def live_capture(interface: str, duration: int, csv_file: str):
    cap = pyshark.LiveCapture(interface=interface, display_filter="ip")
    flows = defaultdict(lambda: defaultdict(int))
    src_dport_tracker = defaultdict(dict)
    start_time = time.time()

    with open(csv_file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "src_ip","dst_ip","protocol","src_port","dst_port",
            "state","sttl","ct_state_ttl","dload","ct_dst_sport_ltm",
            "rate","swin","dwin","dmean","ct_src_dport_ltm"
        ])

        for pkt in cap.sniff_continuously():
            if time.time() - start_time > duration:
                break
            try:
                if 'IP' not in pkt or not pkt.transport_layer:
                    continue
                src_ip = pkt.ip.src; dst_ip = pkt.ip.dst
                proto  = pkt.transport_layer
                sport  = pkt[proto].srcport; dport = pkt[proto].dstport
                length = int(pkt.length)
                ts      = pkt.sniff_time.timestamp()
                ttl     = int(pkt.ip.ttl) if hasattr(pkt.ip, 'ttl') else 0

                key = (src_ip,dst_ip,proto,sport,dport)
                flow = flows[key]
                # init
                if 'first_time' not in flow:
                    flow.update({
                        'first_time': ts, 'first_ttl': ttl,
                        'byte_count': 0, 'packet_count': 0,
                        'swin':0,'dwin':0,'swin_count':0,'dwin_count':0,
                        'flags_seen': set(),'packet_directions': set(),
                        'state':'INT','last_time_port':ts
                    })
                # update
                flow['byte_count']   += length
                flow['packet_count'] += 1
                flow['last_ttl']     = ttl
                flow['last_time']    = ts

                dur = ts - flow['first_time']
                if dur>0:
                    flow['ct_state_ttl'] = abs(flow['first_ttl'] - ttl) * dur
                    flow['dload']        = flow['byte_count'] / dur
                    flow['rate']         = flow['byte_count'] / dur
                flow['dmean'] = flow['byte_count'] / flow['packet_count']

                # TCP state machine
                if proto=='TCP':
                    flags = int(pkt.tcp.flags, 16)
                    flow['flags_seen'].add(flags)
                    # simple mapping:
                    if flags & 0x04:
                        flow['state']='RST'
                    elif flags & 0x01:
                        flow['state']='FIN'
                    elif flags & 0x12==0x12:
                        flow['state']='CON'
                    elif flags & 0x02:
                        flow['state']='REQ'
                    # bidir close?
                    dir1 = f"{src_ip}:{sport}->{dst_ip}:{dport}"
                    dir2 = f"{dst_ip}:{dport}->{src_ip}:{sport}"
                    flow['packet_directions'].add(dir1)
                    if dir2 in flow['packet_directions']:
                        flow['state']='CLO'
                    # windows
                    if hasattr(pkt.tcp, 'window_size_value'):
                        flow['swin'] += int(pkt.tcp.window_size_value)
                        flow['swin_count'] += 1
                    if hasattr(pkt.tcp, 'window_size_scalefactor'):
                        flow['dwin'] += int(pkt.tcp.window_size_scalefactor)
                        flow['dwin_count'] += 1
                    # inter‐arrival of dst port
                    flow['ct_dst_sport_ltm'] = ts - flow.get('last_time_port', ts)
                    flow['last_time_port']  = ts

                # ICMP
                elif proto=='ICMP' and hasattr(pkt, 'icmp'):
                    itype = int(pkt.icmp.type)
                    flow['state'] = 'ECO' if itype==8 else 'ECR' if itype==0 else flow['state']

                # src→dst port inter‐arrival
                last = src_dport_tracker[src_ip].get(dport, ts)
                flow['ct_src_dport_ltm'] = ts - last
                src_dport_tracker[src_ip][dport] = ts

                # average windows
                swin_avg = flow['swin']/flow['swin_count'] if flow['swin_count'] else 0
                dwin_avg = flow['dwin']/flow['dwin_count'] if flow['dwin_count'] else 0

                writer.writerow([
                    *key,
                    flow['state'],
                    flow['first_ttl'],
                    flow.get('ct_state_ttl',0),
                    flow.get('dload',0),
                    flow.get('ct_dst_sport_ltm',0),
                    flow.get('rate',0),
                    swin_avg,
                    dwin_avg,
                    flow.get('dmean',0),
                    flow.get('ct_src_dport_ltm',0)
                ])
                f.flush()

            except Exception as e:
                # skip malformed packets
                continue

    return csv_file

def do_predict(csv_file: str):
    df = pd.read_csv(csv_file)
    # drop meta
    df2 = df.drop(['src_ip','dst_ip','protocol','src_port','dst_port'], axis=1)
    feats = ['state','sttl','ct_state_ttl','dload','ct_dst_sport_ltm',
             'rate','swin','dwin','dmean','ct_src_dport_ltm']

    # encode + scale
    df2['state'] = app.state.encoder.transform(df2['state'])
    df2[feats]  = app.state.scaler.transform(df2[feats])

    preds = app.state.model.predict(df2[feats])
    df['prediction'] = preds
    return df.to_dict(orient="records")


@app.post("/capture_and_predict")
def capture_and_predict(p: CaptureParams):
    try:
        tmp_csv = f"/tmp/flows_{int(time.time())}.csv"
        live_capture(p.interface, p.duration, tmp_csv)
        results = do_predict(tmp_csv)
        return {"count": len(results), "flows": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
