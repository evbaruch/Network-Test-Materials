import sys
from scapy.all import IP, UDP, DNS, DNSQR, sr1

# Function to get the DNS domain's Start of Authority (SOA) record
def get_dns_domain(domain):
    # DNS server to query (using dns.jct.ac.il instead of 8.8.8.8)
    dns_server = "8.8.8.8"  # Change the DNS server to the desired one

    # Build the DNS query for SOA (Start of Authority) record
    query = IP(dst=dns_server)/UDP(dport=53)/DNS(qd=DNSQR(qname=domain, qtype="SOA"))
    
    # Send the query and receive the response
    response = sr1(query, timeout=2, verbose=0)  # Set timeout to 2 seconds

    # Check if the response contains DNS and SOA records
    if response and DNS in response and response[DNS].ancount > 0:
        soa_record = response[DNS].an
        # Return the mname (Master Name Server) from the SOA record
        return soa_record.mname.decode()

    else:
        return {"Error": "No SOA record found for the domain"}

# Function to enumerate DNS records for subdomains
def dnsenum(dns_domain, sub_domain):
    # Query the subdomain DNS record
    query = IP(dst=dns_domain)/UDP(dport=53)/DNS(qd=DNSQR(qname=sub_domain))
    response = sr1(query, timeout=2, verbose=0)

    # Check if the response contains DNS and answers
    if response and DNS in response and response[DNS].ancount > 0:
        # Check for A record (IP address) in the response
        for answer in response[DNS].an:
            if answer.type == 1:  # Type 1 corresponds to an A record (IP address)
                ip_address = answer.rdata
                print(f"> {sub_domain} -> IP: {ip_address}")

# Main function to execute the DNS enumeration
if __name__ == "__main__":
    
    # Ensure the domain name is provided as a command-line argument
    if len(sys.argv) != 2:
        print("Usage: python script.py <domain>")
    #   sys.exit(1)
    
    domain = sys.argv[1]
    dns_domain = get_dns_domain(domain)

    file_path = 'dnsenum.txt'  # File containing subdomains to enumerate

    # Read the file containing subdomains
    with open(file_path, 'r') as file:
        lines = file.readlines()

    # Strip any extra whitespace from each line in the file
    list = [line.strip() for line in lines]

    # Enumerate each subdomain
    for item in list:
        sub_domain = item + '.' + domain
        dnsenum(dns_domain, sub_domain)
