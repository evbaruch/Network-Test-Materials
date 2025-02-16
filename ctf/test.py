from scapy.all import IP, TCP, send, sr1, sniff, show_interfaces, dev_from_index, Raw
import time

def filter_syn_ack(packet):
    return packet.haslayer(TCP) and packet[TCP].flags == 0x12

if __name__ == "__main__":
    target_ip = "127.0.0.1"  # Replace with actual target IP
    target_port = 8200
    my_port = 5800

    # Step 1: Send SYN
    syn_packet = IP(dst=target_ip) / TCP(dport=target_port, sport=my_port, flags='S')
    print(f"[*] Sending SYN")
    send(syn_packet)

    # Step 2: Receive SYN-ACK
    server_syn_ack = sniff(count=1, lfilter=filter_syn_ack, iface=dev_from_index(1))[0]

    # Step 3: Send ACK
    ack_packet = IP(dst=target_ip) / TCP(dport=target_port, sport=my_port, flags='A', 
                                         seq=server_syn_ack.ack, ack=server_syn_ack.seq + 1)
    print("[*] Sending ACK")
    send(ack_packet, verbose=False)

    # Step 4: Wait 1 second before sending GET
    print("[*] Waiting 1 second...")
    time.sleep(1)

    # Step 5: Send HTTP GET Request
    http_request = "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
    get_packet = IP(dst=target_ip) / TCP(dport=target_port, sport=my_port, flags='PA',
                                         seq=server_syn_ack.ack, ack=server_syn_ack.seq + 1) / Raw(load=http_request)
    
    print("[*] Sending HTTP GET request")
    send(get_packet, verbose=False)
