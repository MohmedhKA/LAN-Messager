import socket
import threading
import os

HOST = '0.0.0.0'
PORT = 12345
clients = {}
lock = threading.Lock()
FILE_STORAGE_DIR = "server_files"

# Ensure the storage directory exists
if not os.path.exists(FILE_STORAGE_DIR):
    os.makedirs(FILE_STORAGE_DIR)

def handle_client(client_socket, address):
    try:
        # Receive username
        username = client_socket.recv(1024).decode()
        with lock:
            clients[client_socket] = username
        print(f"[NEW CONNECTION] {username} ({address}) connected.")

        while True:
            # Receive the header (TEXT or FILE)
            header = client_socket.recv(4).decode()
            if not header:
                break

            if header == "TEXT":
                message = client_socket.recv(1024).decode()
                print(f"[{username}] {message}")
                broadcast(f"{username}: {message}", client_socket)

            elif header == "FILE":
                # Receive file metadata
                metadata = client_socket.recv(110).decode()
                filename = metadata[:100].strip()
                filesize = int(metadata[100:].strip())
                filepath = os.path.join(FILE_STORAGE_DIR, filename)

                try:
                    # Receive and save the file
                    with open(filepath, "wb") as f:
                        received = 0
                        while received < filesize:
                            data = client_socket.recv(1024)
                            if not data:
                                break
                            received += len(data)
                            f.write(data)
                            print(f"Received {len(data)} bytes")
                    print(f"[FILE RECEIVED] {username} uploaded {filename} ({filesize} bytes).")
                    broadcast(f"{username} uploaded a file: {filename}", client_socket)
                except Exception as e:
                    print(f"[ERROR] Failed to save the file: {e}")

    except Exception as e:
        print(f"[ERROR] Connection issue: {e}")
    finally:
        with lock:
            if client_socket in clients:
                print(f"[DISCONNECTED] {clients[client_socket]} ({address}) left the chat.")
                del clients[client_socket]
        client_socket.close()

def broadcast(message, sender_socket):
    with lock:
        for client in clients:
            if client != sender_socket:
                try:
                    client.send("TEXT".encode())
                    client.send(message.encode())
                except:
                    client.close()
                    del clients[client]

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()
    print(f"[LISTENING] Server is running on {HOST}:{PORT}")

    while True:
        client_socket, address = server.accept()
        thread = threading.Thread(target=handle_client, args=(client_socket, address))
        thread.start()

if __name__ == "__main__":
    start_server()
