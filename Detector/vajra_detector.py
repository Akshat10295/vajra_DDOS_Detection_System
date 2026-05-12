"""
vajra_detector.py  (standalone mode — no WebSocket server)
===========================================================
Run this if you only want the terminal-based detector without the dashboard.
The dashboard version is built into vajra_server.py.

Key upgrades over v1:
  - Per-IP request rate window (detects distributed low-rate attacks)
  - Entropy-based detection (flags IPs from same /24 subnet acting together)
  - Block threshold is now per-IP, not just per-window total
  - Windows netsh + Linux iptables auto-detected
"""

import argparse
import os
import platform
import subprocess
import time
import warnings
from collections import defaultdict

import joblib
import pandas as pd
from scapy.all import IP, TCP, UDP, sniff

warnings.filterwarnings("ignore", category=UserWarning)

print("Initialising Vajra DDoS Detection System...\n")

# ──────────────────────────────────────────────
#  CONFIGURATION
# ──────────────────────────────────────────────

VICTIM_IP        = "192.168.68.20"
INTERFACE        = "Intel(R) PRO/1000 MT Desktop Adapter"   # Windows NIC name
                                                             # Linux example: "eth0"

WINDOW_TIME      = 5     # seconds per sniff window
ATTACK_THRESHOLD = 5     # suspicious pkts in one window → alert
PER_IP_THRESHOLD = 3     # suspicious pkts from ONE IP in one window → block it

IS_LINUX         = platform.system() == "Linux"

# ──────────────────────────────────────────────
#  SHARED STATE
# ──────────────────────────────────────────────

blocked_ips = set()
model       = None
scaler      = None
feature_list = None

# ──────────────────────────────────────────────
#  MODEL LOADING
# ──────────────────────────────────────────────

def load_model():
    global model, scaler, feature_list
    try:
        model        = joblib.load("ddos_model.pkl")
        scaler       = joblib.load("scaler.pkl")
        feature_list = joblib.load("feature_list.pkl")
        print("✓ ML model loaded (ML + Rules mode)\n")
    except Exception:
        print("⚠ ML model not found — running in Rule-only mode\n")


def reload_model_if_new():
    global model, scaler, feature_list
    if os.path.exists("ddos_model_new.pkl"):
        try:
            model        = joblib.load("ddos_model_new.pkl")
            scaler       = joblib.load("scaler_new.pkl")
            feature_list = joblib.load("feature_list.pkl")
            os.rename("ddos_model_new.pkl", "ddos_model.pkl")
            os.rename("scaler_new.pkl",     "scaler.pkl")
            print("[MODEL] Hot-swapped to new model ✓")
        except Exception as e:
            print(f"[MODEL] Hot-swap failed: {e}")

# ──────────────────────────────────────────────
#  FEATURE EXTRACTION
# ──────────────────────────────────────────────

def extract_features(pkt) -> dict | None:
    if IP not in pkt:
        return None

    ip  = pkt[IP]
    src = ip.src
    dst = ip.dst

    if src == VICTIM_IP:           return None
    if dst.endswith(".255"):       return None
    if dst.startswith("239."):     return None
    if dst.startswith("224."):     return None
    if src == "192.168.68.1":      return None

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
#  RULE-BASED IDENTIFICATION
# ──────────────────────────────────────────────

def identify_attack(features: dict) -> tuple[str | None, str | None]:
    if features["tcp.flags.syn"] == 1 and features["tcp.flags.ack"] == 0:
        return "SYN Flood", "Pure SYN — no handshake completion"
    if features["ip.proto"] == 17:
        return "UDP Flood", "High UDP traffic"
    if features["tcp.dstport"] in (80, 443, 8000, 8080):
        return "HTTP Flood", "Targeting HTTP port"
    return None, None

# ──────────────────────────────────────────────
#  SUBNET ENTROPY CHECK  (detects distributed /24 attacks)
# ──────────────────────────────────────────────

def check_subnet_attack(attackers: dict, threshold: int = 5) -> list[str]:
    """
    If many IPs from the same /24 subnet are attacking,
    flag the whole subnet (return list of attacker IPs from that subnet).
    """
    subnet_map: dict[str, list[str]] = defaultdict(list)
    for ip in attackers:
        subnet = ".".join(ip.split(".")[:3])
        subnet_map[subnet].append(ip)

    flagged = []
    for subnet, ips in subnet_map.items():
        if len(ips) >= threshold:
            print(f"[SUBNET] Distributed attack from /{subnet}.0/24 — {len(ips)} IPs")
            flagged.extend(ips)
    return flagged

# ──────────────────────────────────────────────
#  FIREWALL BLOCK
# ──────────────────────────────────────────────

def block_ip(ip: str):
    if ip in blocked_ips:
        return
    if ip in (VICTIM_IP, "127.0.0.1"):
        return

    print(f"[MITIGATION] Blocking {ip} …")

    if IS_LINUX:
        cmd = f"iptables -A INPUT -s {ip} -j DROP"
    else:
        cmd = (
            f'netsh advfirewall firewall add rule '
            f'name="Vajra_Block_{ip}" '
            f'dir=in action=block remoteip={ip} protocol=any'
        )

    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            blocked_ips.add(ip)
            print(f"[MITIGATION] ✓ {ip} blocked")
        else:
            print(f"[ERROR] Failed to block {ip}: {result.stderr.strip()}")
    except Exception as e:
        print(f"[ERROR] block_ip exception: {e}")

# ──────────────────────────────────────────────
#  TRAINING DATA LOG
# ──────────────────────────────────────────────

def log_training_data(features: dict, label: int):
    row          = features.copy()
    row["label"] = label
    csv_path     = "training_data_live.csv"
    df           = pd.DataFrame([row])
    df.to_csv(csv_path, mode="a", header=not os.path.exists(csv_path), index=False)

# ──────────────────────────────────────────────
#  LIVE DETECTION LOOP
# ──────────────────────────────────────────────

def live_mode():
    print(f"Starting real-time detection on interface: {INTERFACE}\n")
    print(f"Window: {WINDOW_TIME}s | Alert threshold: {ATTACK_THRESHOLD} | "
          f"Per-IP threshold: {PER_IP_THRESHOLD}\n")

    try:
        while True:
            # ── Capture one window ──────────────────
            packets = sniff(timeout=WINDOW_TIME, iface=INTERFACE, promisc=True)

            attack_count = 0
            normal_count = 0

            # per-IP counters for this window
            ip_attack_counts: dict[str, int] = defaultdict(int)
            ip_total_counts:  dict[str, int] = defaultdict(int)

            for pkt in packets:
                features = extract_features(pkt)
                if not features:
                    continue

                src = features["src"]
                if src in blocked_ips:
                    continue

                ip_total_counts[src] += 1
                ml_pred              = predict_ml(features)
                attack_type, reason  = identify_attack(features)
                is_attack            = bool(ml_pred == 1 or attack_type)

                if is_attack:
                    attack_count          += 1
                    ip_attack_counts[src] += 1
                    print(f"[ATTACK] {src}  type={attack_type}  reason={reason}  ml={ml_pred}")
                    log_training_data(features, 1)
                else:
                    normal_count += 1
                    log_training_data(features, 0)

            print(f"\n[WINDOW] total={len(packets)}  attack={attack_count}  normal={normal_count}")
            print(f"[WINDOW] unique attack sources: {len(ip_attack_counts)}")

            # ── Per-IP block (fine-grained) ─────────
            for ip, count in ip_attack_counts.items():
                if count >= PER_IP_THRESHOLD:
                    print(f"[RATE]  {ip} sent {count} attack pkts this window → BLOCKING")
                    block_ip(ip)

            # ── Subnet/distributed detection ────────
            if len(ip_attack_counts) >= 3:
                subnet_attackers = check_subnet_attack(ip_attack_counts)
                for ip in subnet_attackers:
                    block_ip(ip)

            # ── Global threshold ────────────────────
            if attack_count >= ATTACK_THRESHOLD:
                print(f"\n[ALERT] *** DDoS DETECTED ***  ({attack_count} attack pkts in window)\n")
                for ip in ip_attack_counts:
                    block_ip(ip)
            else:
                print("[INFO]  Traffic normal\n")

            print(f"[INFO]  Total blocked IPs so far: {len(blocked_ips)}\n")
            reload_model_if_new()

    except KeyboardInterrupt:
        print("\n[DETECTOR] Stopped safely.")
        print(f"[DETECTOR] Blocked IPs this session: {blocked_ips}")

# ──────────────────────────────────────────────
#  ENTRY POINT
# ──────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Vajra DDoS Detector (standalone)")
    parser.add_argument("--mode",      choices=["live"], required=True)
    parser.add_argument("--iface",     default=INTERFACE, help="Network interface")
    parser.add_argument("--victim",    default=VICTIM_IP, help="Protected IP")
    parser.add_argument("--window",    type=int, default=WINDOW_TIME)
    parser.add_argument("--threshold", type=int, default=ATTACK_THRESHOLD)
    args = parser.parse_args()

    INTERFACE        = args.iface
    VICTIM_IP        = args.victim
    WINDOW_TIME      = args.window
    ATTACK_THRESHOLD = args.threshold

    load_model()

    if args.mode == "live":
        live_mode()
