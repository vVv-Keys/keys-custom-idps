from scapy.all import *
import re
import random
import threading

# Sample botnet signatures (regular expressions)
botnet_signatures = [
    r'botnet\.com',
    r'malware\.exe',
    # Add more signatures as needed
]

class RealTimeAnalyzer(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        sniff(prn=self.analyze_packet, store=0)

    def analyze_packet(self, packet):
        """Analyze network packets in real-time"""
        if detect_botnet_traffic(packet):
            print("Detected Botnet Traffic:")
            print(packet.show())  # Print details of the detected botnet packet

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

# Start real-time analysis in a separate thread
analyzer_thread = RealTimeAnalyzer()
analyzer_thread.start()
