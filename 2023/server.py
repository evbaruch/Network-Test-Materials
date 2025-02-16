import socket
import select
import protocol
from scapy.all import IP, UDP, DNS, DNSQR, sr1

SERVER_PORT = 8888
SERVER_IP = "0.0.0.0"


def socket_name(clients_names, current_socket):
    socket_name = ""
    for name, sock in clients_names.items():
        if sock == current_socket:
            socket_name = name
            break

    return socket_name

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

def handle_client_request(current_socket, clients_names, data, blocked_users):
    tokens = data.split(" ", 2)  # Split the message into parts
    command = tokens[0]

    if command == "NAME":
        name = tokens[1]
        if name in clients_names:
            return "Error: Name already exists", current_socket
        elif name == "BROADCAST":
            return "Error: This name cannot be used", current_socket
        elif current_socket in clients_names.values():
            return "Error: This socket already has a name", current_socket
        
        clients_names[name] = current_socket
        blocked_users[name] = []
        return f"Hello {name}", current_socket

    sender_name = socket_name(clients_names, current_socket)

    if sender_name == "":
        return "User not registered yet, register by NAME <name>", current_socket
    

    if command == "GET_NAMES":
        names_list = ", ".join(clients_names.keys())
        return f"{names_list}", current_socket

    elif command == "MSG":
        if len(tokens) < 3:
            return "Error: Message format incorrect", current_socket
        dest_name, message = tokens[1], tokens[2]

        if dest_name == "BROADCAST":
            return f"{sender_name} Broadcast: {message}", "BROADCAST"  # Broadcast to all
        elif dest_name == sender_name:
            return "You can't send to yourself", current_socket
        elif dest_name in clients_names:
            if dest_name not in blocked_users[sender_name]:
                return f"{sender_name} sent: {message}", clients_names[dest_name]  # Direct message
            else:
                return f"User {dest_name} blocked you.", current_socket
        else:
            return "Error: Name not found", current_socket

    elif command == "BLOCK":
        blocked_name = tokens[1]
        
        # Check if the blocked name exists
        if blocked_name not in clients_names:
            return "Error: Name not found", current_socket   

        # Add the user to the block list
        if sender_name not in blocked_users[blocked_name]:
            blocked_users[blocked_name].append(sender_name)
            return f"User {blocked_name} blocked", current_socket
        else:
            return f"User {blocked_name} is already blocked", current_socket


    else:
        return "Error: Unknown command", current_socket



def handle_client_request_NSLOOKUP(current_socket, clients_names, data, blocked_users):
    tokens = data.split(" ", 2)  # Split the message into parts
    command = tokens[0]

    if command == "NAME":
        name = tokens[1]
        if name in clients_names:
            return "Error: Name already exists", current_socket
        elif name == "BROADCAST":
            return "Error: This name cannot be used", current_socket
        elif current_socket in clients_names.values():
            return "Error: This socket already has a name", current_socket

        clients_names[name] = current_socket
        blocked_users[name] = []
        return f"Hello {name}", current_socket

    sender_name = socket_name(clients_names, current_socket)

    if sender_name == "":
        return "User not registered yet, register by NAME <name>", current_socket

    if command == "GET_NAMES":
        names_list = ", ".join(clients_names.keys())
        return f"{names_list}", current_socket

    elif command == "MSG":
        if len(tokens) < 3:
            return "Error: Message format incorrect", current_socket
        dest_name, message = tokens[1], tokens[2]

        if dest_name == "BROADCAST":
            return f"{sender_name} Broadcast: {message}", "BROADCAST"  # Broadcast to all
        elif dest_name == sender_name:
            return "You can't send to yourself", current_socket
        elif dest_name in clients_names:
            if dest_name not in blocked_users[sender_name]:
                return f"{sender_name} sent: {message}", clients_names[dest_name]  # Direct message
            else:
                return f"User {dest_name} blocked you.", current_socket
        else:
            return "Error: Name not found", current_socket

    elif command == "BLOCK":
        blocked_name = tokens[1]

        if blocked_name not in clients_names:
            return "Error: Name not found", current_socket

        if sender_name not in blocked_users[blocked_name]:
            blocked_users[blocked_name].append(sender_name)
            return f"User {blocked_name} blocked", current_socket
        else:
            return f"User {blocked_name} is already blocked", current_socket

    elif command == "NSLOOKUP":
        if len(tokens) < 2:
            return "Error: No hostname provided", current_socket
        
        lookup_target = tokens[1]

        if lookup_target in clients_names:
            client_ip = clients_names[lookup_target].getpeername()[0]
            if current_socket == clients_names[lookup_target]:  
                return "127.0.0.1", current_socket  # If same client
            return client_ip, current_socket
        else:
            try:
                ip_list = socket.gethostbyname_ex(lookup_target)[2]  # Get all IPv4 addresses
                if ip_list:
                    return "\n".join(ip_list), current_socket
                else:
                    return "Error: No IPv4 addresses found", current_socket
            except socket.gaierror:
                return "Error: Could not resolve hostname", current_socket

    else:
        return "Error: Unknown command", current_socket



def print_client_sockets(client_sockets):
    for c in client_sockets:
        print("\t", c.getpeername())

def get_broadcast_recipients(clients_names, sender_socket, blocked_users):
    recipients = []

    sender_name = socket_name(clients_names, sender_socket)
    blocked_list = blocked_users.get(sender_name, [])
    # Build the recipients list
    for name, sock in clients_names.items():
        if sock != sender_socket and name not in blocked_list:
            recipients.append(sock)

    return recipients


def main():
    print("Setting up server")
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_IP, SERVER_PORT))
    print("Listening for clients")
    server_socket.listen()
    client_sockets = []
    messages_to_send = []
    clients_names = {}
    blocked_users = {}
    while True:
        read_list = client_sockets + [server_socket]
        ready_to_read, ready_to_write, in_error = select.select(read_list, client_sockets, [])
        for current_socket in ready_to_read:
            if current_socket is server_socket:
                client_socket, client_address = server_socket.accept()
                print("Client joined!\n", client_address)
                client_sockets.append(client_socket)
                print_client_sockets(client_sockets)
            else:
                print("Data from client\n")
                data = protocol.get_message(current_socket)
                if data == "":
                    print("Connection closed\n")
                    sender_name = None
                    for entry in clients_names.keys():
                        if clients_names[entry] == current_socket:
                            sender_name = entry
                            break
                    if sender_name:  
                        clients_names.pop(sender_name)
                    client_sockets.remove(current_socket)
                    current_socket.close()
                else:
                    print(data)
                    (response, dest_socket) = handle_client_request(current_socket, clients_names, data, blocked_users)

                    if dest_socket == "BROADCAST":
                        # Use the helper function to get broadcast recipients
                        recipients = get_broadcast_recipients(clients_names, current_socket, blocked_users)
                        messages_to_send.extend((sock, response) for sock in recipients)
                    else:
                        # Add the response to the specific client
                        messages_to_send.append((dest_socket, response))


        # write to everyone (note: only ones which are free to read...)
        for message in messages_to_send:
            current_socket, data = message
            if current_socket in ready_to_write:
                response = protocol.create_msg(data)
                current_socket.send(response)
                messages_to_send.remove(message)


if __name__ == '__main__':
    main()