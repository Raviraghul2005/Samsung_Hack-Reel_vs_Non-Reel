import asyncio
import websockets
import threading
import queue
import time
import os
import sys
from collections import defaultdict
import numpy as np
import pandas as pd
import joblib
from scapy.all import sniff

# --- 1. CONFIGURATION & GLOBAL STATE ---

# Change this to your network interface name (find it with the steps from the previous errors)
NETWORK_INTERFACE = "Wi-Fi" 
ANALYSIS_INTERVAL_S = 2  # How often to analyze and predict (in seconds)
FLOW_TIMEOUT_S = 5       # How long to wait before considering a flow inactive

# Check for model files before starting
if not os.path.exists('traffic_classifier.joblib') or not os.path.exists('feature_columns.joblib'):
    print("[!] Error: Model files not found.", file=sys.stderr)
    print("[!] Please run 'train_model.py' first.", file=sys.stderr)
    sys.exit(1)

# Load the trained model and feature columns
try:
    MODEL = joblib.load('traffic_classifier.joblib')
    FEATURE_COLUMNS = joblib.load('feature_columns.joblib')
    print("[+] Machine learning model loaded successfully.")
except Exception as e:
    print(f"[!] Failed to load model files: {e}", file=sys.stderr)
    sys.exit(1)


# Thread-safe data structures
active_flows = defaultdict(list)
flows_lock = threading.Lock()
prediction_queue = queue.Queue()

# WebSocket client management
CONNECTED_CLIENTS = set()


# --- 2. TRAFFIC ANALYSIS THREAD ---

def analyzer_and_sniffer_thread():
    """
    This function runs in a background thread. It sniffs packets and periodically
    analyzes them to make predictions, which are then put into a queue.
    """
    
    def process_packet(packet):
        """Callback function for scapy's sniff(). Adds packet info to active_flows."""
        if 'IP' in packet and ('TCP' in packet or 'UDP' in packet):
            proto = 'TCP' if 'TCP' in packet else 'UDP'
            flow_key = tuple(sorted((
                (packet['IP'].src, packet[proto].sport),
                (packet['IP'].dst, packet[proto].dport)
            )))
            
            packet_time = float(packet.time)
            packet_size = len(packet)

            with flows_lock:
                active_flows[flow_key].append({'time': packet_time, 'size': packet_size})

    # Start sniffing in the background of this thread
    sniffer = threading.Thread(target=lambda: sniff(iface=NETWORK_INTERFACE, prn=process_packet, store=False), daemon=True)
    sniffer.start()
    print(f"[+] Sniffer started on interface '{NETWORK_INTERFACE}'.")

    # Main analysis loop for this thread
    while True:
        time.sleep(ANALYSIS_INTERVAL_S)

        with flows_lock:
            # Make a copy to work on, so we don't block packet capture for too long
            current_flows = {k: v for k, v in active_flows.items()}
            
            # Clean up old, inactive flows
            now = time.time()
            for key, packets in list(active_flows.items()):
                if now - packets[-1]['time'] > FLOW_TIMEOUT_S:
                    del active_flows[key]
        
        if not current_flows:
            prediction_queue.put("Idle")
            continue

        # --- Feature Engineering (similar to train_model.py) ---
        features_list = []
        for flow_packets in current_flows.values():
            if len(flow_packets) < 2:
                continue

            times = [p['time'] for p in flow_packets]
            sizes = [p['size'] for p in flow_packets]
            iats = np.diff(times)
            
            features = {
                'flow_duration': times[-1] - times[0], 'packet_count': len(flow_packets),
                'total_bytes': sum(sizes), 'avg_pkt_size': np.mean(sizes),
                'std_pkt_size': np.std(sizes), 'max_pkt_size': np.max(sizes),
                'min_pkt_size': np.min(sizes), 'avg_iat': np.mean(iats) if len(iats) > 0 else 0,
                'std_iat': np.std(iats) if len(iats) > 0 else 0,
                'max_iat': np.max(iats) if len(iats) > 0 else 0,
                'min_iat': np.min(iats) if len(iats) > 0 else 0,
            }
            features_list.append(features)
        
        if not features_list:
            prediction_queue.put("Idle")
            continue

        # --- Prediction ---
        live_df = pd.DataFrame(features_list, columns=FEATURE_COLUMNS).fillna(0)
        predictions = MODEL.predict(live_df)
        
        # Determine dominant activity
        reel_count = np.sum(predictions == 'Reel')
        non_reel_count = np.sum(predictions == 'Non-Reel')
        
        dominant_activity = "Reel" if reel_count > non_reel_count else "Non-Reel"
        print(f"Activity check: {dominant_activity} (Reels: {reel_count}, Browse: {non_reel_count})")
        
        # Put the result in the queue for the WebSocket server to broadcast
        prediction_queue.put(dominant_activity)

# --- 3. WEBSOCKET SERVER ---

async def handler(websocket):
    """Handles new WebSocket connections."""
    CONNECTED_CLIENTS.add(websocket)
    print(f"[+] Client connected. Total clients: {len(CONNECTED_CLIENTS)}")
    try:
        await websocket.wait_closed()
    finally:
        CONNECTED_CLIENTS.remove(websocket)
        print(f"[-] Client disconnected. Total clients: {len(CONNECTED_CLIENTS)}")

async def broadcast_loop():
    """Continuously checks the queue for new predictions and broadcasts them."""
    while True:
        try:
            # Get the latest prediction from the queue
            prediction = prediction_queue.get_nowait()
            # Broadcast to all connected clients
            websockets.broadcast(CONNECTED_CLIENTS, prediction)
        except queue.Empty:
            await asyncio.sleep(0.1) # Wait briefly if queue is empty

async def main():
    """Starts the backend services."""
    print("[*] Starting analysis thread...")
    analysis_thread = threading.Thread(target=analyzer_and_sniffer_thread, daemon=True)
    analysis_thread.start()

    print("[*] Starting WebSocket server on ws://localhost:8080...")
    server = await websockets.serve(handler, "localhost", 8080)
    
    # Run the broadcast loop concurrently
    await broadcast_loop()

# --- 4. SCRIPT EXECUTION ---
if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (OSError, RuntimeError) as e:
        print(f"\n[!] A critical error occurred: {e}", file=sys.stderr)
        print("[!] This might be a permissions issue. Try running with 'sudo'.", file=sys.stderr)
    except KeyboardInterrupt:
        print("\n[*] Server is shutting down.")