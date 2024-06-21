from scapy.all import *
import re
import random
import threading
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import matplotlib.pyplot as plt
import time
import logging
import json  # For configuration management

# Load configuration from a file
with open('config.json', 'r') as f:
    config = json.load(f)

# Set up logging
logging.basicConfig(filename='analyzer.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Sample whitelist of trusted IP addresses
whitelist = config["whitelist"]

class RealTimeAnalyzer(threading.Thread):
    def __init__(self, log_file, botnet_signatures):
        threading.Thread.__init__(self)
        self.log_file = log_file
        self.botnet_signatures = botnet_signatures
        self.traffic_profile = {}
        self.ip_reputation_service = set()
        self.siem_integration = SIEMIntegration()

    def run(self):
        updater_thread = threading.Thread(target=self.update_botnet_signatures_periodically)
        updater_thread.daemon = True
        updater_thread.start()

        sniff(prn=self.analyze_packet, store=0)

    def analyze_packet(self, packet):
        try:
            if detect_botnet_traffic(packet, self.botnet_signatures) and not in_whitelist(packet) and not is_malicious_ip(packet):
                self.log_detected_packet(packet)
                self.send_email_alert(packet)
                self.siem_integration.send_to_siem(packet)
            analyze_behavior(packet)
            update_traffic_profile(packet)
            visualize_traffic_profile()
        except Exception as e:
            logging.error(f"Error analyzing packet: {e}")

    def log_detected_packet(self, packet):
        try:
            with open(self.log_file, 'a') as f:
                f.write("Detected Botnet Traffic:\n")
                f.write(str(packet) + "\n\n")
            logging.info(f"Logged detected packet: {packet.summary()}")
        except Exception as e:
            logging.error(f"Error logging packet: {e}")

    def send_email_alert(self, packet):
        sender_email = config["email"]["sender"]
        receiver_email = config["email"]["receiver"]
        password = config["email"]["password"]

        message = MIMEMultipart()
        message['From'] = sender_email
        message['To'] = receiver_email
        message['Subject'] = "Botnet Traffic Detected"

        body = self.generate_alert_message(packet)
        message.attach(MIMEText(body, 'plain'))

        try:
            with smtplib.SMTP('smtp.gmail.com', 587) as server:
                server.starttls()
                server.login(sender_email, password)
                server.sendmail(sender_email, receiver_email, message.as_string())
            logging.info("Email alert sent successfully!")
        except Exception as e:
            logging.error(f"Error sending email alert: {e}")

    def generate_alert_message(self, packet):
        alert_message = "Botnet Traffic Detected!\n\n"
        alert_message += "Severity Level: High\n"
        alert_message += f"Packet Summary: {packet.summary()}\n"
        alert_message += "Recommended Action: Block the IP address\n"
        return alert_message

    def update_botnet_signatures_periodically(self):
        while True:
            time.sleep(86400)
            updated_signatures = update_botnet_signatures()
            if updated_signatures:
                self.botnet_signatures = updated_signatures
                logging.info("Botnet signatures updated successfully!")

class SIEMIntegration:
    def __init__(self):
        self.siem_address = config["siem"]["address"]
        self.siem_port = config["siem"]["port"]

    def send_to_siem(self, packet):
        logging.info(f"Sending packet data to SIEM: {packet.summary()}")

def detect_botnet_traffic(packet, botnet_signatures):
    payload = str(packet.payload) if packet.haslayer(Raw) else ""
    for signature in botnet_signatures:
        if re.search(signature, payload):
            return True
    return False

def in_whitelist(packet):
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    return src_ip in whitelist or dst_ip in whitelist

def analyze_traffic(packet):
    if random.random() < 0.1:
        logging.warning(f"Suspicious traffic detected: {packet.summary()}")

def update_botnet_signatures():
    updated_signatures = [
        r'new_signature1\.com',
        r'new_signature2\.exe',
    ]
    return updated_signatures

def analyze_behavior(packet):
    if random.random() < 0.05:
        logging.warning(f"Suspicious behavior detected: {packet.summary()}")

def update_traffic_profile(packet):
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    protocol = packet[IP].proto
    key = (src_ip, dst_ip, protocol)
    if key in analyzer_thread.traffic_profile:
        analyzer_thread.traffic_profile[key] += 1
    else:
        analyzer_thread.traffic_profile[key] = 1

def is_malicious_ip(packet):
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    return src_ip in analyzer_thread.ip_reputation_service or dst_ip in analyzer_thread.ip_reputation_service

def visualize_traffic_profile():
    traffic_data = analyzer_thread.traffic_profile
    if traffic_data:
        labels = [f'{src_ip} -> {dst_ip}' for (src_ip, dst_ip, _) in traffic_data.keys()]
        values = list(traffic_data.values())

        plt.figure(figsize=(10, 6))
        plt.bar(labels, values, color='skyblue')
        plt.xlabel('Traffic Flow')
        plt.ylabel('Packet Count')
        plt.title('Traffic Profile')
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        plt.show()

# Start real-time analysis in a separate thread and log detected botnet traffic
log_file = config["log_file"]
initial_signatures = config["initial_signatures"]
analyzer_thread = RealTimeAnalyzer(log_file, initial_signatures)
analyzer_thread.start()

# Sniff network traffic and analyze for suspicious patterns
sniff(prn=analyze_traffic, store=0)
