import socket

server_ip = "127.0.0.1"
server_port = 8200

# Create a TCP socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    s.connect((server_ip, server_port))
    print("Connected to server!")

    # Try sending "Hello"
    message = "Hello"
    s.sendall(message.encode())

    # Receive response
    response = s.recv(1024)
    print("Response from server:", response.decode())

except Exception as e:
    print("Connection failed:", e)
finally:
    s.close()
