from scapy.all import IP, UDP, DNS, DNSQR, sr1
import sys
import socket

def nslookup(domain, query_type="A"):
    """Perform a DNS lookup for a given domain and query type."""
    dns_server = "8.8.8.8"  # Google Public DNS

    if query_type == "PTR":
        domain = ".".join(reversed(domain.split("."))) + ".in-addr.arpa"

    dns_query = IP(dst=dns_server) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain, qtype=query_type))
    response = sr1(dns_query, verbose=0, timeout=2)

    results = []
    if response and response.haslayer(DNS) and response[DNS].ancount >= 0:
        answers = response[DNS].an
        for i in range(response[DNS].ancount):
            if query_type == "A" and answers[i].type == 1:  # A record (IPv4 address)
                results.append(answers[i].rdata)
            elif query_type == "PTR" and answers[i].type == 12:  # PTR record (reverse DNS)
                results.append(answers[i].rdata.decode())
    
    return results

def main():
    """Command-line interface for nslookup."""
    # if len(sys.argv) < 3:
    #     print("Usage:")
    #     print("  nslookup type=A www.youtube.com")
    #     print("  nslookup type=PTR 142.251.37.78")
    #     return
    # query_type = sys.argv[1].split("=")[1].upper()
    # domain = sys.argv[2]

    query_type = "PTR"
    domain = "129.159.130.77"

    # query_type = "A"
    # domain = "moodle.jct.ac.il"

    if query_type == "PTR":
        try:
            socket.inet_aton(domain)  # Validate IP address format
            results = nslookup(domain, "PTR")
        except socket.error:
            print("Invalid IP address format for PTR lookup.")
            return
    else:
        results = nslookup(domain, query_type)

    if results:
        for res in results:
            print(res)
    else:
        print("No DNS records found.")

if __name__ == "__main__":
    main()
