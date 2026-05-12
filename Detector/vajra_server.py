"""
vajra_server.py — Vajra DDoS Detection System: WebSocket + REST API Backend
============================================================================
Bridges vajra_detector logic to the dashboard frontend.

Requirements:
    pip install fastapi uvicorn websockets joblib pandas scapy

Run:
    python vajra_server.py

Then open http://localhost:8888 in your browser.

Architecture:
    ┌──────────────┐     WebSocket /ws      ┌──────────────┐
    │  Dashboard   │ ◄─────────────────────► │  This server │
    │  (HTML/JS)   │     REST /api/*         │              │
    └──────────────┘                         │  Detection   │
                                             │  thread runs │
                                             │  sniff() loop│
                                             └──────────────┘
"""

import argparse
import asyncio
import json
import os
import subprocess
import threading
import time
import warnings
from collections import defaultdict
from datetime import datetime
from pathlib import Path

import joblib
import pandas as pd
import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from scapy.all import IP, TCP, UDP, sniff

warnings.filterwarnings("ignore", category=UserWarning)

# ──────────────────────────────────────────────
#  CONFIGURATION  (edit these for your setup)
# ──────────────────────────────────────────────

VICTIM_IP       = "192.168.68.20"
INTERFACE       = "Intel(R) PRO/1000 MT Desktop Adapter"   # Windows NIC name
WINDOW_TIME     = 1          # seconds per detection window
ATTACK_THRESHOLD = 2         # suspicious packets per window to trigger alert
SERVER_PORT     = 8888       # dashboard port
MAX_FEED_ROWS   = 500        # packets kept in memory for the feed
MAX_HISTORY     = 30         # traffic-history windows shown in chart

# ──────────────────────────────────────────────
#  SHARED STATE  (written by detector thread,
#                read by WebSocket/REST handlers)
# ──────────────────────────────────────────────

state = {
    "status":          "IDLE",      # IDLE | MONITORING | ALERT | BLOCKED
    "total_packets":   0,
    "attack_packets":  0,
    "normal_packets":  0,
    "blocked_ips":     [],
    "model_mode":      "Loading...",
    "uptime":          0,
}

blocked_ips:      set              = set()
attack_type_counts: dict           = defaultdict(int)
traffic_history:  list             = []   # [{ts, total, attacks, normal}]
recent_packets:   list             = []   # last MAX_FEED_ROWS packet dicts
recent_alerts:    list             = []   # last 60 alert dicts

# ML artefacts (hot-swappable)
model        = None
scaler       = None
feature_list = None

# Thread-safe lock for model hot-swap
model_lock = threading.Lock()

# Last training report (shown in dashboard Analysis tab)
training_report: dict = {}

# Auto-retrain: trigger after this many new labelled rows since last train
AUTO_RETRAIN_ROWS     = 999999999
_rows_since_retrain   = 0
_retrain_in_progress  = False

# Control flags
detection_running = False
detection_thread  = None
start_time        = None

# asyncio event loop (set at startup)
_loop: asyncio.AbstractEventLoop = None

# WebSocket connection manager
connected_clients: list[WebSocket] = []

# ──────────────────────────────────────────────
#  MODEL LOADING
# ──────────────────────────────────────────────

def load_model():
    global model, scaler, feature_list
    try:
        model        = joblib.load("ddos_model.pkl")
        scaler       = joblib.load("scaler.pkl")
        feature_list = joblib.load("feature_list.pkl")
        state["model_mode"] = "ML + Rules"
        print("[MODEL] Loaded ddos_model.pkl successfully")
    except Exception:
        state["model_mode"] = "Rule-only"
        print("[MODEL] No model file found — running rule-only mode")


def reload_model_if_new():
    """
    Atomically hot-swap model artefacts written by train.py.
    train.py writes *_new.pkl files; we rename them to production names
    under a lock so the detection thread never reads half-written files.
    Also loads training_report.json produced by the pipeline.
    """
    global model, scaler, feature_list, training_report
    if not os.path.exists("ddos_model_new.pkl"):
        return
    with model_lock:
        try:
            # Load into temporaries first — don't touch globals until both succeed
            new_model        = joblib.load("ddos_model_new.pkl")
            new_scaler       = joblib.load("scaler_new.pkl")
            new_feature_list = joblib.load("feature_list.pkl")

            # Atomic rename: production files replaced only after successful load
            os.replace("ddos_model_new.pkl", "ddos_model.pkl")
            os.replace("scaler_new.pkl",     "scaler.pkl")

            # Swap into globals
            model        = new_model
            scaler       = new_scaler
            feature_list = new_feature_list
            state["model_mode"] = "ML + Rules"

            # Load accuracy report if train.py wrote one
            if os.path.exists("training_report.json"):
                with open("training_report.json") as f:
                    training_report = json.load(f)
                f1  = training_report.get("f1_score", "?")
                acc = training_report.get("accuracy", "?")
                print(f"[MODEL] Hot-swapped ✓  F1={f1}  Acc={acc}")
                broadcast_sync({
                    "type":    "model_reloaded",
                    "f1":      f1,
                    "acc":     acc,
                    "report":  training_report,
                })
            else:
                print("[MODEL] Hot-swapped ✓ (no report found)")
                broadcast_sync({"type": "model_reloaded"})

        except Exception as e:
            print(f"[MODEL] Hot-swap failed: {e}")
            broadcast_sync({"type": "error", "msg": f"Model hot-swap failed: {e}"})

# ──────────────────────────────────────────────
#  FEATURE EXTRACTION
# ──────────────────────────────────────────────

def extract_features(pkt) -> dict | None:
    if IP not in pkt:
        return None

    ip  = pkt[IP]
    src = ip.src
    dst = ip.dst

    # Filter out noise
    if src == VICTIM_IP:           return None
    if dst.endswith(".255"):       return None
    if dst.startswith("239."):     return None
    if dst.startswith("224."):     return None
    if src == "192.168.68.1":      return None   # gateway

    proto     = ip.proto
    frame_len = len(pkt)

    tcp_srcport = tcp_dstport = tcp_flags = tcp_ack = tcp_syn = tcp_push = 0

    if TCP in pkt:
        tcp         = pkt[TCP]
        tcp_srcport = tcp.sport
        tcp_dstport = tcp.dport
        tcp_flags   = int(tcp.flags)
        tcp_ack     = 1 if tcp.flags & 0x10 else 0
        tcp_syn     = 1 if tcp.flags & 0x02 else 0
        tcp_push    = 1 if tcp.flags & 0x08 else 0

    return {
        "frame.len":        frame_len,
        "ip.proto":         proto,
        "tcp.srcport":      tcp_srcport,
        "tcp.dstport":      tcp_dstport,
        "tcp.flags":        tcp_flags,
        "tcp.flags.ack":    tcp_ack,
        "tcp.flags.push":   tcp_push,
        "tcp.flags.syn":    tcp_syn,
        "src":              src,
        "dst":              dst,
    }

# ──────────────────────────────────────────────
#  ML PREDICTION
# ──────────────────────────────────────────────

def predict_ml(features: dict) -> int:
    with model_lock:
        if model is None:
            return 0
        try:
            x = {k: v for k, v in features.items() if k not in ("src", "dst")}
            for col in feature_list:
                if col not in x:
                    x[col] = 0
            df       = pd.DataFrame([x])[feature_list]
            X_scaled = scaler.transform(df)
            return int(model.predict(X_scaled)[0])
        except Exception:
            return 0

# ──────────────────────────────────────────────
#  RULE-BASED ATTACK IDENTIFICATION
# ──────────────────────────────────────────────

def identify_attack(features: dict) -> tuple[str | None, str | None]:
    if features["tcp.flags.syn"] == 1 and features["tcp.flags.ack"] == 0:
        return "SYN Flood", "Pure SYN with no ACK"

    if features["ip.proto"] == 17:
        return "UDP Flood", "High UDP traffic"

    if features["tcp.dstport"] in (80, 8000, 8080, 443):
        return "HTTP Flood", "High HTTP request rate"

    return None, None

# ──────────────────────────────────────────────
#  TRAINING DATA LOG
# ──────────────────────────────────────────────

def log_training_data(features: dict, label: int):
    row        = features.copy()
    row["label"] = label
    df         = pd.DataFrame([row])
    csv_path   = "training_data_live.csv"
    df.to_csv(csv_path, mode="a", header=not os.path.exists(csv_path), index=False)

# ──────────────────────────────────────────────
#  FIREWALL BLOCK  (Windows netsh)
# ──────────────────────────────────────────────

def block_ip(ip: str):
    if ip in blocked_ips:
        return
    if ip in (VICTIM_IP, "127.0.0.1"):
        return

    print(f"[MITIGATION] Blocking {ip}")
    cmd = (
        f'netsh advfirewall firewall add rule '
        f'name="Vajra_Block_{ip}" dir=in action=block '
        f'remoteip={ip} protocol=any'
    )
    try:
        result  = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        success = result.returncode == 0
        if success:
            blocked_ips.add(ip)
            state["blocked_ips"] = list(blocked_ips)
            print(f"[MITIGATION] Blocked {ip} ✓")
        else:
            print(f"[ERROR] netsh failed for {ip}: {result.stderr.strip()}")
    except Exception as e:
        success = False
        print(f"[ERROR] block_ip exception: {e}")

    # Notify dashboard
    alert = {"type": "blocked", "ip": ip, "success": success}
    recent_alerts.append(alert)
    if len(recent_alerts) > 60:
        recent_alerts.pop(0)
    broadcast_sync(alert)


def unblock_all():
    """Remove all Vajra firewall rules (Windows)."""
    for ip in list(blocked_ips):
        cmd = f'netsh advfirewall firewall delete rule name="Vajra_Block_{ip}"'
        subprocess.run(cmd, shell=True, capture_output=True)
    blocked_ips.clear()
    state["blocked_ips"] = []
    print("[MITIGATION] All blocks cleared")

# ──────────────────────────────────────────────
#  BROADCAST HELPER  (thread → asyncio loop)
# ──────────────────────────────────────────────

def broadcast_sync(msg: dict):
    """Safe to call from the detector thread."""
    if _loop is None:
        return
    asyncio.run_coroutine_threadsafe(_broadcast(msg), _loop)


async def _broadcast(msg: dict):
    dead = []
    data = json.dumps(msg)
    for ws in connected_clients:
        try:
            await ws.send_text(data)
        except Exception:
            dead.append(ws)
    for ws in dead:
        if ws in connected_clients:
            connected_clients.remove(ws)

# ──────────────────────────────────────────────
#  DETECTION LOOP  (runs in background thread)
# ──────────────────────────────────────────────

def detection_loop():
    global detection_running, start_time

    print("[DETECTOR] Detection loop started")
    state["status"] = "MONITORING"
    broadcast_sync({"type": "status", "status": "MONITORING"})
    start_time = time.time()

    try:
        while detection_running:
            # ── Capture one time window ──
            packets = sniff(timeout=WINDOW_TIME, iface=INTERFACE, promisc=True)

            if not detection_running:
                break

            attack_count   = 0
            normal_count   = 0
            attackers      = {}          # src_ip → attack_pkt_count
            window_types   = defaultdict(int)

            for pkt in packets:
                features = extract_features(pkt)
                if not features:
                    continue

                src = features["src"]
                if src in blocked_ips:
                    continue

                ml_pred                = predict_ml(features)
                attack_type, reason    = identify_attack(features)
                is_attack              = bool(ml_pred == 1 or attack_type)
    
                # ── Build packet dict for dashboard ──
                proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(features["ip.proto"], str(features["ip.proto"]))
                pkt_dict = {
                    "type":        "packet",
                    "ts":          datetime.now().strftime("%H:%M:%S"),
                    "src":         src,
                    "dst":         features["dst"],
                    "proto":       proto_name,
                    "len":         features["frame.len"],
                    "ml":          ml_pred,
                    "attack_type": attack_type or "—",
                    "is_attack":   is_attack,
                }

                # Update counters
                state["total_packets"] += 1
                if is_attack:
                    attack_count              += 1
                    state["attack_packets"]   += 1
                    attackers[src]             = attackers.get(src, 0) + 1
                    if attack_type:
                        attack_type_counts[attack_type] += 1
                        window_types[attack_type]       += 1
                else:
                    normal_count             += 1
                    state["normal_packets"]  += 1

                # Store in rolling feed
                recent_packets.append(pkt_dict)
                if len(recent_packets) > MAX_FEED_ROWS:
                    recent_packets.pop(0)

                # Push to dashboard
                broadcast_sync(pkt_dict)
                log_training_data(features, 1 if is_attack else 0)

            # ── Window summary ──
            ts_label = datetime.now().strftime("%H:%M:%S")
            window   = {
                "type":    "window_summary",
                "ts":      ts_label,
                "total":   len(packets),
                "attacks": attack_count,
                "normal":  normal_count,
                "attack_types": dict(window_types),
                "cumulative": {
                    "total":   state["total_packets"],
                    "attacks": state["attack_packets"],
                    "normal":  state["normal_packets"],
                },
            }
            traffic_history.append({"ts": ts_label, "total": len(packets),
                                     "attacks": attack_count, "normal": normal_count})
            if len(traffic_history) > MAX_HISTORY:
                traffic_history.pop(0)

            broadcast_sync(window)
            state["uptime"] = int(time.time() - start_time)
            print(f"[WINDOW] pkts={len(packets)} attack={attack_count} normal={normal_count}")

            # ── Threshold check → DDoS alert ──
            if attack_count >= ATTACK_THRESHOLD:
                state["status"] = "ALERT"
                alert_msg = {
                    "type":      "alert",
                    "count":     attack_count,
                    "attackers": list(attackers.keys()),
                }
                recent_alerts.append(alert_msg)
                if len(recent_alerts) > 60:
                    recent_alerts.pop(0)
                broadcast_sync(alert_msg)
                print(f"[ALERT] DDoS detected from: {list(attackers.keys())}")

                for ip in attackers:
                    block_ip(ip)

                state["status"] = "MONITORING"
                broadcast_sync({"type": "status", "status": "MONITORING"})
            else:
                print("[INFO] Traffic normal")

            # ── Hot-swap model if train.py wrote new files ──
            reload_model_if_new()

            # ── Auto-retrain trigger ──────────────────────
            _check_auto_retrain(attack_count + normal_count)

    except Exception as e:
        print(f"[DETECTOR] Loop error: {e}")
    finally:
        detection_running = False
        state["status"] = "IDLE"
        broadcast_sync({"type": "status", "status": "IDLE"})
        print("[DETECTOR] Detection loop stopped")

# ──────────────────────────────────────────────
#  RETRAIN PIPELINE  (called by API + auto-trigger)
# ──────────────────────────────────────────────

def _run_retrain_pipeline(quick: bool = False):
    """
    Runs train.py in a subprocess (so it can't crash the server).
    Broadcasts progress events to all dashboard clients.
    train.py writes ddos_model_new.pkl → reload_model_if_new() picks it up.
    """
    global _retrain_in_progress
    if _retrain_in_progress:
        broadcast_sync({"type": "error", "msg": "Retrain already in progress"})
        return

    _retrain_in_progress = True
    broadcast_sync({"type": "retrain_start"})
    print("[PIPELINE] Retrain started")

    def _run():
        global _retrain_in_progress, _rows_since_retrain
        cmd = ["python", "train.py"]
        if quick:
            cmd.append("--quick")
        try:
            result = subprocess.run(
                cmd,
                capture_output=True, text=True, timeout=300   # 5-min cap
            )
            success = result.returncode == 0
            output  = (result.stdout + result.stderr).strip()[-800:]

            if success:
                _rows_since_retrain = 0           # reset auto-trigger counter
                reload_model_if_new()             # immediate hot-swap
                print("[PIPELINE] Retrain succeeded — model deployed")
            else:
                print(f"[PIPELINE] Retrain FAILED:\n{output}")

            broadcast_sync({
                "type":    "retrain_done",
                "success": success,
                "output":  output,
            })

        except subprocess.TimeoutExpired:
            broadcast_sync({"type": "retrain_done", "success": False, "output": "Timed out (>5min)"})
        except FileNotFoundError:
            broadcast_sync({"type": "retrain_done", "success": False,
                            "output": "train.py not found — place it next to vajra_server.py"})
        except Exception as e:
            broadcast_sync({"type": "retrain_done", "success": False, "output": str(e)})
        finally:
            _retrain_in_progress = False

    threading.Thread(target=_run, daemon=True).start()


def _check_auto_retrain(new_rows: int):
    """Called each window. Fires retrain automatically when enough new data collected."""
    global _rows_since_retrain
    _rows_since_retrain += new_rows
    if _rows_since_retrain >= AUTO_RETRAIN_ROWS and not _retrain_in_progress:
        print(f"[AUTO-RETRAIN] {_rows_since_retrain} new rows — triggering retrain")
        broadcast_sync({
            "type": "info",
            "msg":  f"Auto-retraining triggered ({_rows_since_retrain} new samples)"
        })
        _run_retrain_pipeline(quick=True)   # use quick=True for auto to avoid long pauses


# ──────────────────────────────────────────────
#  FASTAPI APP
# ──────────────────────────────────────────────

app = FastAPI(title="Vajra DDoS Backend")

# Serve the dashboard HTML at root
DASHBOARD_HTML = Path("vajra_dashboard.html")

@app.get("/")
async def serve_dashboard():
    if DASHBOARD_HTML.exists():
        return FileResponse(str(DASHBOARD_HTML), media_type="text/html")
    return JSONResponse({"error": "vajra_dashboard.html not found next to this script"}, status_code=404)

# ── WebSocket ──────────────────────────────────

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    connected_clients.append(ws)
    print(f"[WS] Client connected ({len(connected_clients)} total)")

    # Send full state snapshot to new client
    init_msg = {
        "type":               "init",
        "state":              state,
        "blocked_ips":        list(blocked_ips),
        "attack_type_counts": dict(attack_type_counts),
        "traffic_history":    traffic_history[-MAX_HISTORY:],
        "recent_packets":     recent_packets[-50:],
        "recent_alerts":      recent_alerts[-20:],
        "uptime":             state["uptime"],
        "training_report":    training_report,
        "retrain_in_progress": _retrain_in_progress,
        "rows_since_retrain": _rows_since_retrain,
    }
    await ws.send_text(json.dumps(init_msg))

    try:
        while True:
            data = await ws.receive_text()
            msg  = json.loads(data)
            if msg.get("ping"):
                await ws.send_text(json.dumps({"pong": 1}))
    except WebSocketDisconnect:
        pass
    finally:
        if ws in connected_clients:
            connected_clients.remove(ws)
        print(f"[WS] Client disconnected ({len(connected_clients)} remaining)")

# ── REST API ───────────────────────────────────

@app.post("/api/start")
async def api_start():
    global detection_running, detection_thread
    if detection_running:
        return {"ok": False, "msg": "Detection already running"}
    detection_running = True
    detection_thread  = threading.Thread(target=detection_loop, daemon=True)
    detection_thread.start()
    return {"ok": True, "msg": "Detection started"}


@app.post("/api/stop")
async def api_stop():
    global detection_running
    if not detection_running:
        return {"ok": False, "msg": "Detection is not running"}
    detection_running = False
    return {"ok": True, "msg": "Detection stopping after current window…"}


@app.post("/api/retrain")
async def api_retrain(quick: bool = False):
    """
    Trigger a full retrain-evaluate-deploy pipeline via train.py.
    Pass ?quick=true to skip GridSearchCV (faster, slightly less optimal).
    """
    if _retrain_in_progress:
        return {"ok": False, "msg": "Retrain already in progress"}
    threading.Thread(
        target=_run_retrain_pipeline, kwargs={"quick": quick}, daemon=True
    ).start()
    return {"ok": True, "msg": "Retrain pipeline started"}


@app.get("/api/training_report")
async def api_training_report():
    """Return the last training accuracy report produced by train.py."""
    if training_report:
        return training_report
    if os.path.exists("training_report.json"):
        with open("training_report.json") as f:
            return json.load(f)
    return {"error": "No training report yet — run retrain first"}


@app.post("/api/clear_blocked")
async def api_clear_blocked():
    unblock_all()
    broadcast_sync({"type": "blocked_cleared"})
    return {"ok": True, "msg": "All blocked IPs cleared"}


@app.get("/api/state")
async def api_state():
    return {
        **state,
        "blocked_ips":         list(blocked_ips),
        "attack_type_counts":  dict(attack_type_counts),
        "uptime":              int(time.time() - start_time) if start_time else 0,
        "training_report":     training_report,
        "retrain_in_progress": _retrain_in_progress,
        "rows_since_retrain":  _rows_since_retrain,
        "auto_retrain_rows":   AUTO_RETRAIN_ROWS,
    }

# ──────────────────────────────────────────────
#  STARTUP
# ──────────────────────────────────────────────

@app.on_event("startup")
async def on_startup():
    global _loop
    _loop = asyncio.get_event_loop()
    load_model()
    print(f"[SERVER] Vajra running at http://localhost:{SERVER_PORT}")
    print(f"[SERVER] Open your browser to http://localhost:{SERVER_PORT}")


# ──────────────────────────────────────────────
#  ENTRY POINT
# ──────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Vajra DDoS Server")
    parser.add_argument("--port",  type=int, default=SERVER_PORT)
    parser.add_argument("--host",  type=str, default="0.0.0.0")
    parser.add_argument("--iface", type=str, default=INTERFACE,
                        help="Network interface name for sniffing")
    args = parser.parse_args()

    INTERFACE = args.iface   # allow CLI override

    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
