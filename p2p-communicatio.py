import socket
import threading
from cryptography.fernet import Fernet
import os

# Generate a key for encryption and decryption
key = Fernet.generate_key()
cipher = Fernet(key)

# Set the host and port
HOST = '0.0.0.0'  # Listen on all interfaces
PORT = 9999

# Function to handle incoming messages
def handle_incoming_messages(peer_socket):
    while True:
        try:
            # Receive the type of message
            data = peer_socket.recvfrom(1024)
            message_type, addr = data[0].decode('utf-8').split('|', 1)
            if message_type == 'text':
                encrypted_message = peer_socket.recvfrom(1024)[0]
                message = cipher.decrypt(encrypted_message).decode('utf-8')
                print(f"Received message from {addr}: {message}")
            elif message_type == 'image':
                image_data = b''
                while True:
                    packet = peer_socket.recvfrom(1024)[0]
                    if not packet:
                        break
                    image_data += packet
                # Decrypt and save the image
                image_data = cipher.decrypt(image_data)
                with open('received_image.png', 'wb') as img_file:
                    img_file.write(image_data)
                print(f"Received image from {addr}: saved as 'received_image.png'")
        except Exception as e:
            print("Error receiving message:", e)
            break

# Function to send messages to a specific peer
def send_messages(peer_socket):
    while True:
        recipient = input("Enter recipient address (IP:PORT) or 'exit' to quit: ")
        if recipient.lower() == 'exit':
            break
        message_type = input("Send 'text' or 'image': ").lower()
        if message_type == 'text':
            message = input("Enter your message: ")
            encrypted_message = cipher.encrypt(message.encode('utf-8'))
            peer_socket.sendto(f"text|{recipient}".encode('utf-8'), (recipient.split(':')[0], int(recipient.split(':')[1])))
            peer_socket.sendto(encrypted_message, (recipient.split(':')[0], int(recipient.split(':')[1])))
        elif message_type == 'image':
            image_path = input("Enter the path to the image: ")
            if os.path.exists(image_path):
                with open(image_path, 'rb') as img_file:
                    image_data = img_file.read()
                encrypted_image = cipher.encrypt(image_data)
                peer_socket.sendto(f"image|{recipient}".encode('utf-8'), (recipient.split(':')[0], int(recipient.split(':')[1])))
                peer_socket.sendto(encrypted_image, (recipient.split(':')[0], int(recipient.split(':')[1])))
                print("Image sent!")
            else:
                print("Image file does not exist.")

# Create a UDP socket
peer_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
peer_socket.bind((HOST, PORT))

print(f"Peer listening on {HOST}:{PORT}")

# Start the thread to handle incoming messages
thread = threading.Thread(target=handle_incoming_messages, args=(peer_socket,))
thread.start()

# Start sending messages
send_messages(peer_socket)

# Clean up
peer_socket.close()
