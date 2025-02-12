from scapy.all import *
import sys
import socket

def nslookup(domain, query_type="A"):
    # DNS server to query (Google Public DNS)
    dns_server = "8.8.8.8"

    # Construct the DNS query
    dns_query = IP(dst=dns_server) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain, qtype=query_type))

    # Send the DNS query and receive the response
    response = sr1(dns_query, verbose=0, timeout=2)

    if response and response.haslayer(DNS):
        # Check if the DNS server responded with the requested information
        answers = response[DNS].an
        if answers:
            for i in range(response[DNS].ancount):
                print(f"{query_type} Record: {answers[i].rdata}")
        else:
            print("No DNS records found.")
    else:
        print("No response received from the DNS server.")

def main():
    # if len(sys.argv) < 3:
    #     print("Usage:")
    #     print("  nslookup type=A www.youtube.com")
    #     print("  nslookup type=PTR 142.251.37.78")
    #     return
    # query_type = sys.argv[1].split("=")[1]
    # domain = sys.argv[2]

    query_type = "A"
    domain = "www.google.com"

    # query_type = "PTR"
    # domain = "142.250.75.36"

    # Handle reverse lookup (PTR records)
    if query_type.upper() == "PTR":
        try:
            # Convert the IP address to a valid format
            domain = socket.inet_aton(domain)
            # Reverse the IP address and append the in-addr.arpa domain
            reversed_ip = ".".join(map(str, domain[::-1])) + ".in-addr.arpa"
            nslookup(reversed_ip, "PTR")
        except socket.error:
            print("Invalid IP address format for PTR lookup.")
    else:
        nslookup(domain, query_type.upper())

if __name__ == "__main__":
    main()
