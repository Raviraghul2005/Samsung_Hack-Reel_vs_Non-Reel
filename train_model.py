import numpy as np
import pandas as pd
from scapy.all import rdpcap
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from collections import defaultdict
import joblib
import os

# --- FEATURE EXTRACTION ---
# --- FEATURE EXTRACTION ---
def extract_features_from_pcap(pcap_file, label):
    """Reads a pcap file, groups packets into flows, and extracts features for each flow."""
    if not os.path.exists(pcap_file):
        print(f"[!] Error: Pcap file not found at '{pcap_file}'. Please run capture_traffic.py first.")
        return None

    packets = rdpcap(pcap_file)
    flows = defaultdict(list)
    
    # Group packets into flows using a 5-tuple key
    for packet in packets:
        if 'IP' in packet and ('TCP' in packet or 'UDP' in packet):
            proto = 'TCP' if 'TCP' in packet else 'UDP'
            flow_key = tuple(sorted((
                (packet['IP'].src, packet[proto].sport),
                (packet['IP'].dst, packet[proto].dport)
            )))
            flows[flow_key].append(packet)

    features_list = []
    for flow_key, flow_packets in flows.items():
        if len(flow_packets) < 2:  # Ignore flows with less than 2 packets
            continue

        # Sort packets by time to calculate Inter-Arrival Times (IAT)
        flow_packets.sort(key=lambda p: p.time)
        
        # CORRECTED LINE: Convert Scapy's Decimal time to float for NumPy compatibility
        times = [float(p.time) for p in flow_packets]
        sizes = [len(p) for p in flow_packets]
        iats = np.diff(times)

        features = {
            'flow_duration': times[-1] - times[0],
            'packet_count': len(flow_packets),
            'total_bytes': sum(sizes),
            'avg_pkt_size': np.mean(sizes),
            'std_pkt_size': np.std(sizes),
            'max_pkt_size': np.max(sizes),
            'min_pkt_size': np.min(sizes),
            'avg_iat': np.mean(iats) if len(iats) > 0 else 0,
            'std_iat': np.std(iats) if len(iats) > 0 else 0,
            'max_iat': np.max(iats) if len(iats) > 0 else 0,
            'min_iat': np.min(iats) if len(iats) > 0 else 0,
            'label': label
        }
        features_list.append(features)
        
    return pd.DataFrame(features_list)

# --- MODEL TRAINING ---
def train_and_save_model():
    """Main function to load data, train the classifier, and save it."""
    print("[*] Starting model training process...")

    # Load and process data
    reels_df = extract_features_from_pcap('reels_traffic.pcap', 'Reel')
    non_reels_df = extract_features_from_pcap('non_reels_traffic.pcap', 'Non-Reel')

    if reels_df is None or non_reels_df is None:
        return

    # Combine datasets
    full_df = pd.concat([reels_df, non_reels_df], ignore_index=True)
    full_df = full_df.fillna(0) # Handle any potential NaN values
    
    if len(full_df) < 10:
        print("[!] Error: Not enough data to train. Please capture more traffic.")
        return

    print(f"[+] Combined data: {len(full_df)} flows ({len(reels_df)} Reel, {len(non_reels_df)} Non-Reel).")
    
    # Prepare data for Scikit-learn
    X = full_df.drop('label', axis=1)
    y = full_df['label']
    
    feature_columns = X.columns.tolist()

    # Split data (optional but good practice)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    # Initialize and train the RandomForestClassifier
    print("[*] Training RandomForestClassifier...")
    model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    model.fit(X_train, y_train)
    
    accuracy = model.score(X_test, y_test)
    print(f"[+] Model training complete. Accuracy on test data: {accuracy:.2f}")

    # Save the trained model and the feature columns
    joblib.dump(model, 'traffic_classifier.joblib')
    joblib.dump(feature_columns, 'feature_columns.joblib')
    print("[+] Model saved as 'traffic_classifier.joblib'")
    print("[+] Feature columns saved as 'feature_columns.joblib'")

if __name__ == "__main__":
    train_and_save_model()