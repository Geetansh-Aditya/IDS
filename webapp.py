from flask import Flask, render_template
from flask_socketio import SocketIO
import re
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
    intrusion_detected, signature = check_for_intrusion(packet)
    if intrusion_detected:
        alert_msg = f"Intrusion detected! Signature: '{signature}' in {packet.summary()}"
        print(f"[ALERT] {alert_msg}")
        socketio.emit('new_alert', {'message': alert_msg, 'signature': signature})

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == "__main__":
    print("Starting IDS and Web Dashboard...")
    sniff(prn=packet_callback, store=0)
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
