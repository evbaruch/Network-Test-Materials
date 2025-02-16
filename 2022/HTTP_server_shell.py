# Ex 4.4 - HTTP Server Shell
# Author: Barak Gonen
# Purpose: Provide a basis for Ex. 4.4
# Note: The code is written in a simple way, without classes, log files or other utilities, for educational purpose
# Usage: Fill the missing functions and constants

# TO DO: import modules
import socket
import os
import urllib.parse
from scapy.all import IP, UDP, DNS, DNSQR, sr1


# TO DO: set constants
SERVER_IP  = '0.0.0.0'
PORT = 80
SOCKET_TIMEOUT = 0.5
FIXED_RESPONSE = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Type: text/html; charset=ISO-8859-1\r\n\r\nhello"

def nslookup(domain, query_type="A"):
    """Perform a DNS lookup for a given domain and query type."""
    dns_server = "8.8.8.8"  # Google Public DNS

    if query_type == "PTR":
        domain = ".".join(reversed(domain.split("."))) + ".in-addr.arpa"

    dns_query = IP(dst=dns_server) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain, qtype=query_type))
    response = sr1(dns_query, verbose=0, timeout=2)

    results = []
    if response and response.haslayer(DNS) and response[DNS].ancount > 0:
        answers = response[DNS].an
        for i in range(response[DNS].ancount):
            if query_type == "A" and answers[i].type == 1:  # A record (IPv4 address)
                results.append(answers[i].rdata)
            elif query_type == "PTR" and answers[i].type == 12:  # PTR record (reverse DNS)
                results.append(answers[i].rdata.decode())
    
    return results

def get_file_data(filename):
    """ Get data from file """
    try:
        with open(filename, 'rb') as f:
            return f.read()
    except FileNotFoundError:
        return None


def handle_client_request(resource, client_socket):
    """Process the client request and return a response."""
    if resource == "/":
        response_body = "Welcome to NSLookup Server"
        response = f"HTTP/1.1 200 OK\r\nContent-Length: {len(response_body)}\r\nContent-Type: text/plain\r\n\r\n{response_body}"
        client_socket.send(response.encode())
        return

    # Extract domain name from URL path
    parsed_path = urllib.parse.unquote(resource.lstrip("/"))  # Remove leading "/"
    
    if parsed_path.startswith("reverse/"):
        ip_address = parsed_path[len("reverse/"):]  # Extract IP after "reverse/"
        addresses = nslookup(ip_address, "PTR")
        if addresses:
            response_body = "\n".join(addresses)
        else:
            response_body = "No addresses found"
        
        response = f"HTTP/1.1 200 OK\r\nContent-Length: {len(response_body)}\r\nContent-Type: text/plain\r\n\r\n{response_body}"

    elif parsed_path:
        ip_addresses = nslookup(parsed_path)
        if ip_addresses:
            response_body = "\n".join(ip_addresses)
        else:
            response_body = "No IP found"
        
        response = f"HTTP/1.1 200 OK\r\nContent-Length: {len(response_body)}\r\nContent-Type: text/plain\r\n\r\n{response_body}"

    else:
        response = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"

    client_socket.send(response.encode())


def validate_HTTP_request(request):
    """
    Check if request is a valid HTTP request and returns TRUE / FALSE and the requested URL
    """
    try:
        lines = request.split("\r\n")
        request_line = lines[0]
        parts = request_line.split()
        if len(parts) == 3 and (parts[0] == "GET" or parts[0] == "POST") and parts[2].startswith("HTTP/"):
            return True, parts[1]
        else:
            return False, None
    except IndexError:
        return False, None


def handle_client(client_socket):
    """ Handles client requests: verifies client's requests are legal HTTP, calls function to handle the requests """
    print('Client connected')

    while True:
        # Receive raw data from client
        client_request = client_socket.recv(1024)
        # Decode the first part of the request as UTF-8 to handle headers (ignoring binary data in body)
        decoded_request = client_request.decode('utf-8', errors='ignore')

        valid_http, resource = validate_HTTP_request(decoded_request)
        if valid_http:
            print(f"Got HTTP request for resource: {resource}")
            handle_client_request(resource, client_socket)
            break
        else:
            print('Error: invalid HTTP request')
            response = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"
            client_socket.send(response.encode())
            break

    print('Closing connection')
    client_socket.close()

def handle_client(client_socket):
    """ Handles client requests: verifies client's requests are legal HTTP, calls function to handle the requests """
    print('Client connected')
    try:
        while True:
            # Receive raw data from client
            client_request = client_socket.recv(1024)
            # Decode the first part of the request as UTF-8 to handle headers (ignoring binary data in body)
            decoded_request = client_request.decode('utf-8', errors='ignore')

            valid_http, resource = validate_HTTP_request(decoded_request)
            if valid_http:
                print(f"Got HTTP request for resource: {resource}")
                handle_client_request(resource, client_socket)
                break
            else:
                print('Error: invalid HTTP request')
                response = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"
                client_socket.send(response.encode())
                break
    except socket.timeout:
        print("Connection timed out")
    finally:
        print('Closing connection')
        client_socket.close()


def main():
    # Open a socket and loop forever while waiting for clients
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_IP, PORT))
    server_socket.listen()
    print("Listening for connections on port {}".format(PORT))

    while True:
        client_socket, client_address = server_socket.accept()
        print('New connection received')
        client_socket.settimeout(SOCKET_TIMEOUT)
        handle_client(client_socket)


if __name__ == "__main__":
    # Call the main handler function
    main()