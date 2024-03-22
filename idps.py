import re  # Import the regular expression module
import random  # Import the random module for generating random traffic

# Sample botnet signatures (regular expressions)
botnet_signatures = [
    r'botnet\.com',
    r'malware\.exe',
    # Add more signatures as needed
]

def detect_botnet_traffic(packet):
    """Detect botnet traffic based on signatures"""
    for signature in botnet_signatures:
        if re.search(signature, packet):
            return True  # Return True if a signature is found in the packet
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

def test_botnet_detection(num_packets):
    """Test the botnet detection mechanism"""
    traffic = generate_network_traffic(num_packets)  # Generate network traffic
    detected_packets = [packet for packet in traffic if detect_botnet_traffic(packet)]  # Detect botnet traffic
    print("Detected Botnet Traffic:")  # Print the detected botnet traffic
    for packet in detected_packets:
        print(packet)  # Print each detected botnet packet

# Test with 10 random network packets
test_botnet_detection(10)  # Call the test_botnet_detection function with 10 packets
