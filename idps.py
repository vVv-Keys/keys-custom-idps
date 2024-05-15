from scapy.all import *
import re
import random
import threading
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import matplotlib.pyplot as plt

# Sample whitelist of trusted IP addresses
whitelist = [
    '192.168.0.1',
    '10.0.0.1',
    # Add more trusted IP addresses as needed
]

class RealTimeAnalyzer(threading.Thread):
    def __init__(self, log_file, botnet_signatures):
        threading.Thread.__init__(self)
        self.log_file = log_file
        self.botnet_signatures = botnet_signatures
        self.traffic_profile = {}  # Initialize empty dictionary for traffic profiling
        self.ip_reputation_service = {}  # Initialize empty dictionary for IP reputation service

    def run(self):
        sniff(prn=self.analyze_packet, store=0)

    def analyze_packet(self, packet):
        """Analyze network packets in real-time"""
        if detect_botnet_traffic(packet, self.botnet_signatures) and not in_whitelist(packet) and not is_malicious_ip(packet):
            self.log_detected_packet(packet)
            self.send_email_alert(packet)
        analyze_behavior(packet)
        update_traffic_profile(packet)
        visualize_traffic_profile()

    def log_detected_packet(self, packet):
        """Log detected botnet packet to file"""
        with open(self.log_file, 'a') as f:
            f.write("Detected Botnet Traffic:\n")
            f.write(str(packet) + "\n\n")  # Write packet details to log file

    def send_email_alert(self, packet):
        """Send email alert for detected botnet traffic"""
        sender_email = "your_email@gmail.com"  # Sender's email address
        receiver_email = "recipient_email@gmail.com"  # Receiver's email address
        password = "your_password"  # Sender's email password

        message = MIMEMultipart()
        message['From'] = sender_email
        message['To'] = receiver_email
        message['Subject'] = "Botnet Traffic Detected"

        body = "Botnet Traffic Detected:\n\n" + str(packet)
        message.attach(MIMEText(body, 'plain'))

        try:
            server = smtplib.SMTP('smtp.gmail.com', 587)
            server.starttls()
            server.login(sender_email, password)
            text = message.as_string()
            server.sendmail(sender_email, receiver_email, text)
            server.quit()
            print("Email alert sent successfully!")
        except Exception as e:
            print("Error sending email alert:", e)

def detect_botnet_traffic(packet, botnet_signatures):
    """Detect botnet traffic based on signatures"""
    payload = str(packet.payload) if packet.haslayer(Raw) else ""  # Extract packet payload as string
    for signature in botnet_signatures:
        if re.search(signature, payload):
            return True  # Return True if a signature is found in the payload
    return False  # Return False if no signatures are found

def in_whitelist(packet):
    """Check if packet source or destination IP is in the whitelist"""
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    return src_ip in whitelist or dst_ip in whitelist

def analyze_traffic(packet):
    """Analyze network traffic for suspicious patterns"""
    # Basic machine learning - random analysis for demonstration
    if random.random() < 0.1:  # Randomly classify packets as suspicious
        print("Suspicious traffic detected:", packet.summary())

def update_botnet_signatures():
    """Update botnet signatures dynamically"""
    # Placeholder logic to fetch and update signatures from an external source or database
    updated_signatures = [
        r'new_signature1\.com',
        r'new_signature2\.exe',
        # Add more signatures
    ]
    return updated_signatures

def analyze_behavior(packet):
    """Analyze network behavior for suspicious patterns"""
    # Implement behavioral analysis logic here
    # For demonstration, let's randomly flag packets as suspicious
    if random.random() < 0.05:  # 5% chance of flagging a packet as suspicious
        print("Suspicious behavior detected:", packet.summary())

def update_traffic_profile(packet):
    """Update traffic profile with packet information"""
    # Update traffic profile with packet attributes (e.g., source IP, destination IP, protocol)
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    protocol = packet[IP].proto  # Assuming IPv4
    # Increment traffic count for the corresponding attributes in the traffic profile
    if (src_ip, dst_ip, protocol) in analyzer_thread.traffic_profile:
        analyzer_thread.traffic_profile[(src_ip, dst_ip, protocol)] += 1
    else:
        analyzer_thread.traffic_profile[(src_ip, dst_ip, protocol)] = 1

def is_malicious_ip(packet):
    """Check if the source or destination IP address is in the malicious IP reputation service"""
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    return src_ip in analyzer_thread.ip_reputation_service or dst_ip in analyzer_thread.ip_reputation_service

def visualize_traffic_profile():
    """Visualize traffic profile"""
    traffic_data = analyzer_thread.traffic_profile
    if traffic_data:
        labels = ['{} -> {}'.format(src_ip, dst_ip) for (src_ip, dst_ip, _) in traffic_data.keys()]
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
log_file = "botnet_detection_log.txt"
initial_signatures = [
    r'botnet\.com',
    r'malware\.exe',
    # Add more initial signatures as needed
]
analyzer_thread = RealTimeAnalyzer(log_file, initial_signatures)
analyzer_thread.start()

# Sniff network traffic and analyze for suspicious patterns
sniff(prn=analyze_traffic, store=0)
