from scapy.all import *
import re
import random

# Sample botnet signatures (regular expressions)
botnet_signatures = [
    r'botnet\.com',
    r'malware\.exe',
    # Add more signatures as needed
]

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

def test_botnet_detection(packet):
    """Test the botnet detection mechanism"""
    if detect_botnet_traffic(packet):
        print("Detected Botnet Traffic:")
        print(packet.show())  # Print the details of the detected botnet packet

# Test with 10 random network packets
test_traffic = generate_network_traffic(10)
print("Generated Network Traffic:")
for packet in test_traffic:
    print(packet)

# Sniff network traffic and test botnet detection for each packet
print("\nDetecting Botnet Traffic:")
sniff(prn=test_botnet_detection, store=0)
