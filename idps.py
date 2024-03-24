from scapy.all import *
import re
import random
import threading
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import requests

# Sample botnet signatures (regular expressions)
botnet_signatures = [
    r'botnet\.com',
    r'malware\.exe',
    # Add more signatures as needed
]

class RealTimeAnalyzer(threading.Thread):
    def __init__(self, log_file):
        threading.Thread.__init__(self)
        self.log_file = log_file

    def run(self):
        sniff(prn=self.analyze_packet, store=0)

    def analyze_packet(self, packet):
        """Analyze network packets in real-time"""
        if detect_botnet_traffic(packet):
            self.log_detected_packet(packet)
            self.send_email_alert(packet)
            self.check_ip_reputation(packet)

    def log_detected_packet(self, packet):
        """Log detected botnet packet to file"""
        with open(self.log_file, 'a') as f:
            f.write("Detected Botnet Traffic:\n")
            f.write(str(packet) + "\n\n")  # Write packet details to log file

    def send_email_alert(self, packet):
        """Send email alert for detected botnet traffic"""
        # Email sending code remains unchanged

    def check_ip_reputation(self, packet):
        """Check IP reputation of the source IP address"""
        source_ip = packet[IP].src
        response = requests.get(f"https://ipinfo.io/{source_ip}/json")
        if response.status_code == 200:
            ip_data = response.json()
            print("IP Reputation Check for", source_ip)
            print("Country:", ip_data.get('country', 'N/A'))
            print("Hostname:", ip_data.get('hostname', 'N/A'))
            print("Organization:", ip_data.get('org', 'N/A'))
            print("ISP:", ip_data.get('isp', 'N/A'))
            print("Reputation:", ip_data.get('threat', {}).get('is_tor', 'N/A'))
        else:
            print("Error checking IP reputation")

def detect_botnet_traffic(packet):
    """Detect botnet traffic based on signatures"""
    payload = str(packet.payload) if packet.haslayer(Raw) else ""  # Extract packet payload as string
    for signature in botnet_signatures:
        if re.search(signature, payload):
            return True  # Return True if a signature is found in the payload
    return False  # Return False if no signatures are found

def generate_network_traffic(num_packets):
    """Generate random network traffic for testing"""
    traffic = []
    for _ in range(num_packets):
        # Generate random traffic with a 50% chance of containing a botnet signature
        if random.random() < 0.5:
            packet = "GET /botnet.com HTTP/1.1"
        else:
            packet = "POST /login HTTP/1.1"
        traffic.append(packet)  # Add the generated packet to the traffic list
    return traffic  # Return the list of generated traffic packets

# Test with 10 random network packets
test_traffic = generate_network_traffic(10)
print("Generated Network Traffic:")
for packet in test_traffic:
    print(packet)

# Start real-time analysis in a separate thread and log detected botnet traffic
log_file = "botnet_detection_log.txt"
analyzer_thread = RealTimeAnalyzer(log_file)
analyzer_thread.start()
