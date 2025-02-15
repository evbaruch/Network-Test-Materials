from scapy.all import IP, TCP, send, sr1

def three_way_handshake(target_ip, target_port):
    # Step 1: Send SYN packet
    syn_packet = IP(dst=target_ip) / TCP(dport=target_port, sport=12345, flags='S')
    print(f"[*] Sending SYN to {target_ip}:{target_port}")
    syn_ack_response = sr1(syn_packet, timeout=2, verbose=False)

    if syn_ack_response is None:
        print("[!] No response from target.")
        return False

    if syn_ack_response.haslayer(TCP) and syn_ack_response[TCP].flags == 0x12:  # SYN-ACK
        print("[*] Received SYN-ACK, sending ACK...")
        
        # Step 2: Send ACK to complete the handshake
        ack_packet = IP(dst=target_ip) / TCP(dport=target_port, sport=12345, flags='A', seq=syn_ack_response.ack, ack=syn_ack_response.seq + 1)
        send(ack_packet, verbose=False)
        
        print("[+] Handshake completed successfully!")
        return True
    else:
        print("[!] Unexpected response, handshake failed.")
        return False

if __name__ == "__main__":
    # target_ip = "192.168.1.1"  # Replace with actual target IP
    target_ip = "www.google.com"  # Replace with actual target IP
    target_port = 80           # Replace with actual target port

    three_way_handshake(target_ip, target_port)

# tcp.flags.syn == 1 and tcp.flags.ack == 0 → Captures the initial SYN packet sent by the client.
# tcp.flags.syn == 1 and tcp.flags.ack == 1 → Captures the SYN-ACK response from the server.
# tcp.flags.syn == 0 and tcp.flags.ack == 1 → Captures the final ACK packet sent by the client to complete the handshake.
# tcp.port == 12345 → Filters packets based on the source or destination port number (e.g., port 12345).
# tcp.flags.fin == 1 → Captures packets with the FIN (finish) flag set, indicating the sender is done sending data.