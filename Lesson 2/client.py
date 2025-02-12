import socket          # Importing the socket module for network communication.
import protocol        # Importing the custom protocol for message formatting.

# Creating a TCP/IP socket for the client.
mySocket = socket.socket()

# Connecting the client to the server running on localhost (same machine) at port 8805.
mySocket.connect(('localhost', 8805))

# Creating a formatted message ("Hello, server!") with a length prefix using the protocol.
message = protocol.create_message('Hello, server!')

# Sending the encoded message to the server over the established socket connection.
mySocket.send(message)

# Closing the client socket after the message has been sent.
mySocket.close()
print('Message sent.')  # Confirmation message for the sent message.