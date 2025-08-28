import argparse
from scapy.all import sniff, wrpcap
import sys

# --- CONFIGURATION ---
# Find your network interface name.
# Windows: run `getmac /v` in cmd. Look for the name under "Connection Name" for your Wi-Fi/Ethernet.
# macOS/Linux: run `ifconfig` or `ip a` in the terminal. Look for names like "en0", "wlan0", etc.
DEFAULT_INTERFACE = "Wi-Fi" # <-- IMPORTANT: CHANGE THIS TO YOUR WI-FI/ETHERNET INTERFACE NAME

def capture(output_file, duration, interface):
    """Captures network traffic for a given duration and saves it to a file."""
    print(f"[*] Starting traffic capture on interface '{interface}' for {duration} seconds.")
    print(f"[*] Packets will be saved to '{output_file}'.")
    print("[*] Please begin the target activity now (e.g., watch Reels or browse the feed).")
    
    try:
        # Sniff packets from the specified interface
        packets = sniff(iface=interface, timeout=duration)
        
        # Write the captured packets to a .pcap file
        wrpcap(output_file, packets)
        print(f"\n[+] Capture complete. Saved {len(packets)} packets to '{output_file}'.")
        
    except Exception as e:
        print(f"[!] An error occurred: {e}", file=sys.stderr)
        print("[!] Make sure you are running this script with administrator/root privileges.", file=sys.stderr)
        print(f"[!] Also, verify that the interface name '{interface}' is correct.", file=sys.stderr)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Capture network traffic for model training.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "output", 
        help="The name of the output .pcap file (e.g., reels_traffic.pcap)."
    )
    parser.add_argument(
        "-d", "--duration", 
        type=int, 
        default=60, 
        help="Duration of the capture in seconds. Default is 60."
    )
    parser.add_argument(
        "-i", "--interface", 
        type=str, 
        default=DEFAULT_INTERFACE, 
        help=f"Network interface to sniff on. Default is '{DEFAULT_INTERFACE}'."
    )
    
    args = parser.parse_args()

    # --- How to Run ---
    # 1. To capture video traffic:
    #    python capture_traffic.py reels_traffic.pcap -d 120
    #
    # 2. To capture non-video (Browse) traffic:
    #    python capture_traffic.py non_reels_traffic.pcap -d 120
    
    capture(args.output, args.duration, args.interface)