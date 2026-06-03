from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

# Packet handler function
def process_packet(packet):

    print("\n=== Packet Captured ===")

    # IP Layer
    if packet.haslayer(IP):

        print(f"Source IP: {packet[IP].src}")
        print(f"Destination IP: {packet[IP].dst}")
        print(f"Protocol: {packet[IP].proto}")

    # TCP Layer
    if packet.haslayer(TCP):

        print(f"Source Port: {packet[TCP].sport}")
        print(f"Destination Port: {packet[TCP].dport}")

    # UDP Layer
    if packet.haslayer(UDP):

        print(f"Source Port: {packet[UDP].sport}")
        print(f"Destination Port: {packet[UDP].dport}")

    # Packet Length
    print(f"Packet Length: {len(packet)}")


print("Starting Live Packet Capture...\n")

# Start sniffing
sniff(prn=process_packet, store=False)