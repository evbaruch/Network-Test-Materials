import socket          # Importing the socket module for network communication.
import protocol        # Importing a custom protocol module for message formatting and parsing.

# Creating a TCP/IP socket for the server.
serverSocket = socket.socket()

# Binding the server to all available network interfaces (0.0.0.0) on port 8805.
serverSocket.bind(('0.0.0.0', 8805))

print('Listening...')  # Informing that the server is ready to accept connections.
serverSocket.listen()  # Putting the server in listening mode to accept incoming client connections.

# Accepting a client connection (this call is blocking until a client connects).
# Returns a new socket (clientSocket) for the specific connection and the client's address.
(clientSocket, clientAddress) = serverSocket.accept()
print('Connection established with', clientAddress)  # Logging the client's address.

# Receiving and decoding the message sent by the client using the custom protocol.
data = protocol.get_message(clientSocket)

# Displaying the received message on the server console.
print(data)

# Closing the client socket after communication is complete.
clientSocket.close()
print('Connection closed.')  # Confirmation message for the closed connection.
