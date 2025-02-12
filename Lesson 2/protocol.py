import socket  # Although imported, not strictly needed unless used elsewhere in the module.

LEN_SIZE = 2   # Defining the length of the header that will store the message size (2 bytes).

# Function to create a formatted message with a length prefix.
def create_message(message):
    message_length = len(message)               # Calculating the length of the message.
    len_field = str(message_length).zfill(LEN_SIZE)  # Formatting the length to be exactly LEN_SIZE digits (padded with zeros if necessary).
    return (len_field + message).encode()       # Combining the length field and message, then encoding to bytes.

# Function to receive and decode a message from a socket.
def get_message(socket):
    len_field = int(socket.recv(LEN_SIZE).decode())  # Receiving and decoding the length field (first 2 bytes).
    return socket.recv(int(len_field)).decode()      # Receiving the actual message based on the decoded length, then decoding it to a string.
