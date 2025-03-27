from flask import Flask, render_template
from flask_socketio import SocketIO
import re
import threading
from scapy.all import *
from scapy.layers.http import HTTPRequest

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")  # Fix CORS issues

# Path to your Snort community rules file
rules_file = "snort3-community.rules"
attack_signatures = []

# Load attack signatures
with open(rules_file, 'r') as file:
    for line in file:
        line = line.strip()
        if line and not line.startswith('#'):
            # Extract all content matches
            matches = re.findall(r'content:"([^"]+)"', line)
            if matches:
                attack_signatures.extend([m.lower() for m in matches])
    print(f"Loaded {len(attack_signatures)} attack signatures")  # Debugging


def check_for_intrusion(packet):
    """Check for attack signatures in HTTP or Raw payloads"""
    payload = None

    if packet.haslayer(Raw):  # Extract raw data
        try:
            payload = packet[Raw].load.decode(errors='ignore').lower()
        except Exception:
            return False, None

    if payload:
        for signature in attack_signatures:
            if signature in payload:
                return True, signature
    return False, None


def packet_callback(packet):
    """Processes packets and checks for intrusions"""
    try:
        intrusion_detected, signature = check_for_intrusion(packet)
        if intrusion_detected:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = "TCP" if packet.haslayer(TCP) else "UDP"
            alert_msg = (f"Intrusion detected from {src_ip} to {dst_ip} "
                         f"using {protocol}! Signature: '{signature}'")

            print(f"[ALERT] {alert_msg}")
            socketio.emit('new_alert', {
                'message': alert_msg,
                'signature': signature,
                'source_ip': src_ip,
                'destination_ip': dst_ip,
                'protocol': protocol
            })
    except Exception as e:
        print(f"Packet processing error: {str(e)}")


@app.route('/')
def index():
    return render_template('index.html')


def start_sniffing():
    """Sniffs packets on all TCP/UDP ports"""
    sniff(filter="ip", prn=packet_callback, store=0, iface=None)


if __name__ == "__main__":
    print("Starting IDS and Web Dashboard...")

    # Start sniffing in a separate thread
    sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
    sniff_thread.start()

    # Start Flask server
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
