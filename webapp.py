from flask import Flask, render_template
from flask_socketio import SocketIO
import re
import threading
from scapy.all import *

app = Flask(__name__)
socketio = SocketIO(app)

# Path to your Snort community rules file
rules_file = "snort3-community.rules"
attack_signatures = []

# Load attack signatures
with open(rules_file, 'r') as file:
    for line in file:
        if line.strip() and not line.strip().startswith('#'):
            matches = re.findall(r'content:"([^"]+)"', line)
            for match in matches:
                attack_signatures.append(match.lower())

def check_for_intrusion(packet):
    """Check if the packet payload matches any attack signatures."""
    if packet.haslayer(Raw):
        try:
            payload = packet[Raw].load.decode(errors='ignore').lower()
        except Exception:
            payload = ""
        for signature in attack_signatures:
            if signature in payload:
                return True, signature
    return False, None

def packet_callback(packet):
    """Process captured packets and detect intrusions."""
    intrusion_detected, signature = check_for_intrusion(packet)
    if intrusion_detected:
        alert_msg = f"Intrusion detected! Signature: '{signature}' in {packet.summary()}"
        print(f"[ALERT] {alert_msg}")
        socketio.emit('new_alert', {'message': alert_msg, 'signature': signature})

@app.route('/')
def index():
    """Render the web dashboard."""
    return render_template('index.html')

def start_sniffing():
    """Start packet sniffing on port 80."""
    sniff(filter="tcp port 80", prn=packet_callback, store=0)

if __name__ == "__main__":
    print("Starting IDS and Web Dashboard...")

    # Start sniffing in a separate thread
    sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
    sniff_thread.start()

    # Start Flask server
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
