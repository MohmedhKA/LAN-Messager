import tkinter as tk
from tkinter import simpledialog, messagebox, filedialog
import socket
import threading
import os
import json

SERVER_IP = "192.168.6.39"  # Replace with your server's IP
PORT = 12345

#dark mode
is_dark_mode = False

file_list_text_area = None
requested_filename = None


def apply_theme(root, text_area, entry_widget, buttons):
    global is_dark_mode
    if is_dark_mode:
        root.configure(bg="#2e2e2e")
        text_area.configure(bg="#3c3f41", fg="#ffffff", insertbackground="#ffffff")
        entry_widget.configure(bg="#3c3f41", fg="#ffffff")
        for btn in buttons:
            btn.configure(bg="#5c5c5c", fg="#ffffff")
    else:
        root.configure(bg="#e0e0e0")
        text_area.configure(bg="white", fg="#000000", insertbackground="#000000")
        entry_widget.configure(bg="white", fg="#000000")
        for btn in buttons:
            btn.configure(bg="grey", fg="#000000")

def toggle_dark_mode(root, text_area, entry_widget, dark_button, extra_buttons):
    global is_dark_mode
    is_dark_mode = not is_dark_mode
    apply_theme(root, text_area, entry_widget, [dark_button] + extra_buttons)
    if is_dark_mode:
        dark_button.config(text="Dark Mode: ON")
    else:
        dark_button.config(text="Dark Mode: OFF")

def receive_messages(client_socket, text_area):
    text_area.tag_config("public", foreground="green")
    text_area.tag_config("private", foreground="red")
    text_area.tag_config("you", foreground="blue")
    while True:
        try:
            header = client_socket.recv(4).decode()
            if header == "HIST":
                hist_json = client_socket.recv(4096).decode()
                messages = json.loads(hist_json)
                text_area.config(state=tk.NORMAL)
                for m in messages:
                    text_area.insert(tk.END, f"{m['timestamp']} - {m['username']}: {m['message']}\n", "public")
                text_area.config(state=tk.DISABLED)
            elif header == "TEXT":
                message = client_socket.recv(1024).decode()
                if ":" in message:
                    username, msg = message.split(":", 1)
                else:
                    username, msg = "unknown", message
                text_area.config(state=tk.NORMAL)
                text_area.insert(tk.END, f"Public from {username} => {msg}\n", "public")
                text_area.config(state=tk.DISABLED)
            elif header == "LIST":
                file_list = client_socket.recv(4096).decode('utf-8')
                global file_list_text_area
                if file_list_text_area:
                    file_list_text_area.config(state=tk.NORMAL)
                    file_list_text_area.delete("1.0", tk.END)
                    file_list_text_area.insert(tk.END, file_list)
                    file_list_text_area.config(state=tk.DISABLED)
            elif header == "PRIV":
                message = client_socket.recv(1024).decode()
                if ":" in message:
                    sender, msg = message.split(":", 1)
                else:
                    sender, msg = "unknown", message
                text_area.config(state=tk.NORMAL)
                text_area.insert(tk.END, f"Private from {sender}: {msg}\n", "private")
                text_area.config(state=tk.DISABLED)
            elif header == "GETF":
                filesize_str = client_socket.recv(10).decode()
                filesize = int(filesize_str.strip())
                if filesize == 0:
                    text_area.config(state=tk.NORMAL)
                    text_area.insert(tk.END, "Requested file not found.\n", "public")
                    text_area.config(state=tk.DISABLED)
                else:
                    global requested_filename
                    if not requested_filename:
                        requested_filename = "received_file"
                    if not os.path.exists("Received"):
                        os.makedirs("Received")
                    save_path = os.path.join("Received", requested_filename)
                    with open(save_path, "wb") as f:
                        remaining = filesize
                        while remaining > 0:
                            chunk = client_socket.recv(min(1024, remaining))
                            if not chunk:
                                break
                            f.write(chunk)
                            remaining -= len(chunk)
                    text_area.config(state=tk.NORMAL)
                    text_area.insert(tk.END, f"File received and saved as {save_path}\n", "public")
                    text_area.config(state=tk.DISABLED)

        except Exception as e:
            print(f"[ERROR] Connection lost: {e}")
            break


def send_message(client_socket, message_entry, text_area, username):
    message = message_entry.get()
    if message:
        client_socket.send("TEXT".encode())
        client_socket.send(f"{username}:{message}".encode())
        text_area.config(state=tk.NORMAL)
        text_area.insert(tk.END, f"[You]: {message}\n", "you")
        text_area.config(state=tk.DISABLED)
        message_entry.delete(0, tk.END)

def send_file(client_socket):
    filepath = filedialog.askopenfilename()
    if filepath and os.path.isfile(filepath):
        filename = os.path.basename(filepath)
        filesize = os.path.getsize(filepath)
        client_socket.send("FILE".encode())
        metadata = f"{filename:<100}{filesize:<10}".encode()
        client_socket.send(metadata)
        with open(filepath, "rb") as f:
            while data := f.read(1024):
                client_socket.send(data)
        messagebox.showinfo("File Transfer", f"File {filename} sent successfully.")

def request_file(client_socket):
    global requested_filename
    requested_file = simpledialog.askstring("Receive File", "Enter the name of the file to receive:")
    if requested_file:
        requested_filename = requested_file 
        client_socket.send("GETF".encode())
        client_socket.send(f"{requested_file:<100}".encode())

def private_message(client_socket, username):
    recipient = simpledialog.askstring("Private Message", "Enter the recipient's username:")
    if recipient:
        message = simpledialog.askstring("Private Message", "Enter your message:")
        if message:
            client_socket.send("PRIV".encode())
            full_message = f"{recipient}<:>{message}"
            client_socket.send(full_message.encode())

def create_ui(client_socket, username):
    root = tk.Tk()
    root.title("Chat Client")
    root.geometry("900x600")
    
    root.columnconfigure(0, weight=1)
    root.rowconfigure(1, weight=1)

    header_frame = tk.Frame(root)
    header_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=5)
    header_frame.columnconfigure(0, weight=1)
    
    private_button = tk.Button(header_frame, text="Private", command=lambda: private_message(client_socket, username))
    private_button.grid(row=0, column=1, sticky="e")
    
    chat_frame = tk.Frame(root, bg="white", bd=2, relief="groove")
    chat_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=5)

    chat_frame.columnconfigure(0, weight=1)
    chat_frame.rowconfigure(0, weight=1)
    
    text_area = tk.Text(chat_frame, state='disabled', bg="white", relief="flat")
    text_area.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
    
    scrollbar = tk.Scrollbar(chat_frame, command=text_area.yview)
    scrollbar.grid(row=0, column=1, sticky="ns")
    text_area['yscrollcommand'] = scrollbar.set

    entry_frame = tk.Frame(root)
    entry_frame.grid(row=2, column=0, sticky="ew", padx=10, pady=10)
    entry_frame.columnconfigure(0, weight=1)
    
    message_entry = tk.Entry(entry_frame, width=60, bd=2, relief="flat")
    message_entry.grid(row=0, column=0, padx=(0, 5), sticky="ew")
    message_entry.bind("<Return>", lambda event: send_message(client_socket, message_entry, text_area, username))
    
    send_button = tk.Button(entry_frame, text="Send", command=lambda: send_message(client_socket, message_entry, text_area, username))
    send_button.grid(row=0, column=1, padx=5)
    
    file_button = tk.Button(entry_frame, text="File", command=lambda: file_options(client_socket))
    file_button.grid(row=0, column=2, padx=5)
    
    dark_button = tk.Button(entry_frame, text="Dark Mode: OFF", command=lambda: toggle_dark_mode(root, text_area, message_entry, dark_button, [send_button, file_button, private_button]))
    dark_button.grid(row=0, column=3, padx=5)
    
    apply_theme(root, text_area, message_entry, [send_button, file_button, dark_button, private_button])
    
    threading.Thread(target=receive_messages, args=(client_socket, text_area), daemon=True).start()
    
    root.mainloop()

def file_options(client_socket):
    global file_list_text_area 
    file_window = tk.Toplevel()
    file_window.title("File Options")

    file_list_frame = tk.Frame(file_window)
    file_list_frame.pack(pady=5)

    file_list_text_area = tk.Text(file_list_frame, state='disabled', height=10, width=50)
    file_list_text_area.pack()

    client_socket.send("LIST".encode())

    def send_file_and_close():
        send_file(client_socket)
        file_window.destroy()

    def request_file_and_close():
        request_file(client_socket)
        file_window.destroy()

    send_file_button = tk.Button(file_window, text="Send File", command=send_file_and_close)
    send_file_button.pack(pady=5)

    receive_file_button = tk.Button(file_window, text="Receive File", command=request_file_and_close)
    receive_file_button.pack(pady=5)

def do_authentication():
    auth_window = tk.Tk()
    auth_window.title("Login")
    auth_window.geometry("300x150")
    auth_window.resizable(False, False)
    
    tk.Label(auth_window, text="Username:").grid(row=0, column=0, padx=10, pady=10, sticky="w")
    username_entry = tk.Entry(auth_window)
    username_entry.grid(row=0, column=1, padx=10, pady=10)
    
    tk.Label(auth_window, text="Password:").grid(row=1, column=0, padx=10, pady=10, sticky="w")
    password_entry = tk.Entry(auth_window, show="*")
    password_entry.grid(row=1, column=1, padx=10, pady=10)
    
    credentials = {}

    def submit(event=None):
        credentials['username'] = username_entry.get().strip()
        credentials['password'] = password_entry.get().strip()
        auth_window.destroy()

    auth_window.bind('<Return>', submit)
    
    tk.Button(auth_window, text="Login", command=submit).grid(row=2, column=0, columnspan=2, pady=10)
    
    auth_window.mainloop()
    
    return credentials.get('username'), credentials.get('password')

def main():
    username, password = do_authentication()
    if not username or not password:
        return

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((SERVER_IP, PORT))
    client_socket.send("AUTH".encode())
    creds = json.dumps({"username": username, "password": password})
    client_socket.send(creds.encode())
    auth_response = client_socket.recv(4).decode()
    if auth_response != "OKAY":
        messagebox.showerror("Authentication Failed", "Invalid username or password.")
        client_socket.close()
        return

    create_ui(client_socket, username)

if __name__ == "__main__":
    main()
