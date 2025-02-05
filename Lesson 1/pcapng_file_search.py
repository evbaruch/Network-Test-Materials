from scapy.all import rdpcap, Ether, IP, TCP, UDP

# Function to process each packet in the pcapng file
def process_pcapng(file_path):
    # load the pcapng file
    packets = rdpcap(file_path)

    for packet in packets:
        # Extract MAC addresses
        src_mac = packet[Ether].src if Ether in packet else "N/A"
        dst_mac = packet[Ether].dst if Ether in packet else "N/A"

        # Extract IP addresses
        src_ip = packet[IP].src if IP in packet else "N/A"
        dst_ip = packet[IP].dst if IP in packet else "N/A"

        # Extract Ports (TCP/UDP)
        src_port = dst_port = "N/A"
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        # Print the captured data
        print(f"Source MAC: {src_mac}, Destination MAC: {dst_mac}")
        print(f"Source IP: {src_ip}, Destination IP: {dst_ip}")
        print(f"Source Port: {src_port}, Destination Port: {dst_port}")
        print("-" * 50)

# Replace 'file.pcapng' with your actual file path
process_pcapng('Lesson 1\wwb001-http.pcapng')

# Output
"""
Source MAC: d4:85:64:a7:bf:a3, Destination MAC: ac:5d:10:11:e2:b9
Source IP: 192.168.1.72, Destination IP: 98.136.187.13
Source Port: 6129, Destination Port: 80
--------------------------------------------------
Source MAC: ac:5d:10:11:e2:b9, Destination MAC: d4:85:64:a7:bf:a3
Source IP: 98.136.187.13, Destination IP: 192.168.1.72
Source Port: 80, Destination Port: 6131
--------------------------------------------------
Source MAC: d4:85:64:a7:bf:a3, Destination MAC: ac:5d:10:11:e2:b9
Source IP: 192.168.1.72, Destination IP: 98.136.187.13
Source Port: 6131, Destination Port: 80
--------------------------------------------------
"""