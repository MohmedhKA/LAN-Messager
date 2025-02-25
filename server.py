import socket
import threading
import os
import time
import json
from datetime import datetime
import sqlite3


HOST = '0.0.0.0'
PORT = 12345
clients = {}
lock = threading.Lock()
FILE_STORAGE_DIR = "server_files"
FILE_LIFETIME = 28800  # 8 hours (adjust as needed)

# Directory for user metadata (credentials)
#USERS_DIR = "users"

# Ensure necessary directories exist
if not os.path.exists(FILE_STORAGE_DIR):
    os.makedirs(FILE_STORAGE_DIR)

def init_db():
    conn = sqlite3.connect("chat.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            message TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

def send_history(client_socket):
    try:
        conn = sqlite3.connect("chat.db")
        cursor = conn.cursor()
        cursor.execute("""
            SELECT username, message, timestamp
            FROM messages
            WHERE timestamp >= datetime('now','-8 hours')
            ORDER BY timestamp ASC
        """)
        rows = cursor.fetchall()
        conn.close()
        
        # Convert the rows to a list of dictionaries
        historical_messages = [
            {"username": row[0], "message": row[1], "timestamp": row[2]}
            for row in rows
        ]
        historical_json = json.dumps(historical_messages)
        
        # Send the HIST header and then the JSON payload
        client_socket.send("HIST".encode())
        client_socket.send(historical_json.encode())
    except Exception as e:
        print(f"[ERROR] Failed to send historical messages: {e}")


def delete_old_files():
    while True:
        time.sleep(60)  # Check every minute
        now = datetime.now()
        with lock:
            for file in os.listdir(FILE_STORAGE_DIR):
                file_path = os.path.join(FILE_STORAGE_DIR, file)
                if os.path.isfile(file_path):
                    file_mtime = datetime.fromtimestamp(os.path.getmtime(file_path))
                    if (now - file_mtime).total_seconds() > FILE_LIFETIME:
                        os.remove(file_path)
                        print(f"[AUTO DELETE] Deleted file: {file}")

def handle_client(client_socket, address):
    try:
        # --- Authentication ---
        header = client_socket.recv(4).decode()
        if header != "AUTH":
            client_socket.close()
            return
        creds_json = client_socket.recv(1024).decode()
        try:
            creds = json.loads(creds_json)
        except Exception as e:
            print(f"[ERROR] Invalid JSON from {address}: {e}")
            client_socket.close()
            return
        username = creds.get("username")
        password = creds.get("password")
        
        # Load the users.json file from the root folder
        try:
            with open("users.json", "r") as f:
                users_data = json.load(f)
        except Exception as e:
            print(f"[ERROR] Failed to load users.json: {e}")
            client_socket.send("FAIL".encode())
            client_socket.close()
            return
        
        # Check credentials
        authenticated = False
        for user_dict in users_data:
            if username in user_dict and user_dict[username] == password:
                authenticated = True
                break
        
        if not authenticated:
            client_socket.send("FAIL".encode())
            client_socket.close()
            print(f"[AUTH FAIL] Incorrect credentials for {username}.")
            return
        
        client_socket.send("OKAY".encode())
        
        # **NEW:** Send historical messages after successful login
        send_history(client_socket)
        
        with lock:
            clients[client_socket] = username
        print(f"[NEW CONNECTION] {username} ({address}) connected.")

        # --- Main loop: handling messages ---
        while True:
            header = client_socket.recv(4).decode()
            if not header:
                break

            print(f"[DEBUG] Received header: {header}")

            if header == "TEXT":
                message = client_socket.recv(1024).decode()
                print(f"[{username}] {message}")
                
                # Insert the message into the database
                try:
                    conn = sqlite3.connect("chat.db")
                    cursor = conn.cursor()
                    cursor.execute("INSERT INTO messages (username, message) VALUES (?, ?)", (username, message))
                    conn.commit()
                    conn.close()
                except Exception as e:
                    print(f"[ERROR] Failed to insert message into DB: {e}")
                
                broadcast(f"{username}:{message}", client_socket)

            elif header == "FILE":
                metadata = client_socket.recv(110).decode()
                filename = metadata[:100].strip()
                filesize = int(metadata[100:].strip())
                filepath = os.path.join(FILE_STORAGE_DIR, filename)

                try:
                    with open(filepath, "wb") as f:
                        received = 0
                        while received < filesize:
                            data = client_socket.recv(1024)
                            if not data:
                                break
                            received += len(data)
                            f.write(data)
                    print(f"[FILE RECEIVED] {username} uploaded {filename} ({filesize} bytes).")
                    broadcast(f"{username} uploaded a file: {filename}", client_socket)
                except Exception as e:
                    print(f"[ERROR] Failed to save the file: {e}")

            elif header == "GETF":
                requested_file = client_socket.recv(100).decode().strip()
                file_path = os.path.join(FILE_STORAGE_DIR, requested_file)

                # Send a header so the client can properly detect the file transfer
                client_socket.send("GETF".encode())

                if os.path.isfile(file_path):
                    filesize = os.path.getsize(file_path)
                    client_socket.send(f"{filesize:<10}".encode())
                    with open(file_path, "rb") as f:
                        while data := f.read(1024):
                            client_socket.send(data)
                    print(f"[FILE SENT] Sent {requested_file} to {username}")
                else:
                    client_socket.send(f"{0:<10}".encode())
                    print(f"[FILE REQUEST FAILED] {username} requested {requested_file} (Not Found)")

            elif header == "LIST":
                print("[DEBUG] Received LIST command from client")
                files = os.listdir(FILE_STORAGE_DIR)
                file_list = "\n".join(files)
                print(f"[DEBUG] File list: {file_list}")
                # Send header then file list
                client_socket.send("LIST".encode())
                client_socket.send(file_list.encode('utf-8'))
                print("[DEBUG] Sent file list to client")

            elif header == "PRIV":
                # Receive the combined recipient and message data
                data = client_socket.recv(1024).decode()
                if "<:>" in data:
                    recipient, msg = data.split("<:>", 1)
                    send_private_message(recipient, f"{username}:{msg}")
                else:
                    print("[ERROR] Invalid private message format")

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
        for client in list(clients.keys()):
            if client != sender_socket:
                try:
                    client.send("TEXT".encode())
                    client.send(message.encode())
                except Exception as e:
                    print(f"[ERROR] Broadcasting error: {e}")
                    client.close()
                    del clients[client]

def send_private_message(recipient, message):
    with lock:
        for client_socket, username in list(clients.items()):
            if username == recipient:
                try:
                    client_socket.send("PRIV".encode())
                    client_socket.send(message.encode())
                    print(f"[PRIVATE] Sent private message to {recipient}")
                    return
                except Exception as e:
                    print(f"[ERROR] Private message error: {e}")
                    client_socket.close()
                    del clients[client_socket]
        print(f"[ERROR] User {recipient} not found")

def start_server():
    threading.Thread(target=delete_old_files, daemon=True).start()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()
    print(f"[LISTENING] Server is running on {HOST}:{PORT}")

    while True:
        client_socket, address = server.accept()
        thread = threading.Thread(target=handle_client, args=(client_socket, address))
        thread.start()

if __name__ == "__main__":
    init_db()
    start_server()
