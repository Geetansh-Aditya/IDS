from flask import Flask, render_template
from flask_socketio import SocketIO
import re
import threading
from scapy.all import *
from scapy.layers.http import HTTPRequest

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")  # Fix CORS

# Path to your Snort community rules file
rules_file = "snort3-community.rules"
attack_signatures = []

# Load attack signatures with improved regex
with open(rules_file, 'r') as file:
    for line in file:
        line = line.strip()
        if line and not line.startswith('#'):
            # Find all content matches, ignoring modifiers
            matches = re.findall(r'content:"([^"]+)"', line)
            if matches:
                attack_signatures.extend([m.lower() for m in matches])
    print(f"Loaded {len(attack_signatures)} attack signatures")  # Debug


def check_for_intrusion(packet):
    """Improved intrusion detection with HTTP layer check"""
    if packet.haslayer(HTTPRequest) and packet.haslayer(Raw):
        try:
            payload = packet[Raw].load.decode(errors='ignore').lower()
        except Exception as e:
            return False, None

        for signature in attack_signatures:
            if signature in payload:
                return True, signature
    return False, None


def packet_callback(packet):
    """Enhanced packet processing with error handling"""
    try:
        if packet.haslayer(TCP) and packet[TCP].dport == 80:
            intrusion_detected, signature = check_for_intrusion(packet)
            if intrusion_detected:
                src_ip = packet[IP].src
                alert_msg = (f"Intrusion detected from {src_ip}! "
                             f"Signature: '{signature}'")
                print(f"[ALERT] {alert_msg}")
                socketio.emit('new_alert', {
                    'message': alert_msg,
                    'signature': signature,
                    'source_ip': src_ip
                })
    except Exception as e:
        print(f"Packet processing error: {str(e)}")


@app.route('/')
def index():
    return render_template('index.html')


def start_sniffing():
    """Improved sniffing with interface specification"""
    sniff(filter="tcp port 80", prn=packet_callback, store=0, iface=None)


if __name__ == "__main__":
    print("Starting IDS and Web Dashboard...")

    # Start sniffing in a separate thread
    sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
    sniff_thread.start()

    # Start Flask server
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)