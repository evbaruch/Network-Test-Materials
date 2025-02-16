import socket
import select
import msvcrt
import protocol
# NAME <name> will set name. Server will reply error if duplicate
# GET_NAMES will get all names
# MSG <NAME> <message> will send message to client name or to broadcast
# BLOCK <name> will block a user from sending messages to the client who sent the block command
# EXIT will close client
# NSLOOKUP <hostname> will return the IP address of the specified hostname


my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
my_socket.connect(("127.0.0.1", 8888))
print("Enter commands\n")
msg = ""
user_input = ""

print_s = f'''
    NAME <name> will set name. Server will reply error if duplicate
    GET_NAMES will get all names
    MSG <NAME> <message> will send message to client name or to broadcast
    BLOCK <name> will block a user from sending messages to the client who sent the block command
    EXIT will close client
    NSLOOKUP <hostname> will return the IP address of the specified hostname
'''
print(print_s)

while msg != "EXIT":

    rlist, wlist, xlist = select.select([my_socket], [], [], 0.2)

    # Handle incoming messages from the server
    if rlist:
        server_msg = protocol.get_message(my_socket)
        if server_msg == "":
            print("\nThe server has been shut down")
            break
        print(f"\rServer: {server_msg}")  # Print the server message
        print(f"{user_input}", end="", flush=True)  # Reprint the current input line

    # Handle keyboard input from the user
    if msvcrt.kbhit():
        char = msvcrt.getwche()  # Read a single character
        if char == '\r':  # If Enter is pressed
            print()  # Move to the next line
            if user_input.strip():
                my_socket.send(protocol.create_msg(user_input.strip()))  # Send input to the server
                if user_input.strip() == "EXIT":
                    break
            user_input = ""  # Clear the input buffer
        elif char == '\b':  # If Backspace is pressed
            if user_input:  # Ensure there's something to delete
                user_input = user_input[:-1]  # Remove the last character
                print(f"\r{user_input} ", end="", flush=True)  # Overwrite the line with the updated input
                print(f"\r{user_input}", end="", flush=True)
        else:
            user_input += char  # Add the character to the input



my_socket.close()

