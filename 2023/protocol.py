import struct

def get_message(current_socket):
    try:
        # First, receive the length of the message
        length_data = current_socket.recv(4)  # Receive the 4-byte length prefix
        if not length_data:
            return ""  # Client closed the connection

        # Unpack the length and read the actual message
        message_length = struct.unpack("!I", length_data)[0]  # Big-endian integer
        data = current_socket.recv(message_length)
        if not data:
            return ""  # Client closed the connection
        return data.decode()
    except Exception as e:
        print(f"Error receiving message: {e}")
        return ""


def create_msg(msg):
    try:
        # Encode the message and calculate its length
        encoded_msg = msg.encode()
        message_length = len(encoded_msg)

        # Pack the length as a 4-byte integer and prepend it to the message
        length_prefix = struct.pack("!I", message_length)  # Big-endian integer
        return length_prefix + encoded_msg  # Combine the length and the message
    except Exception as e:
        print(f"Error creating message: {e}")
        return b""
