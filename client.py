import tkinter as tk
from tkinter import simpledialog, messagebox, filedialog
from tkinter import ttk
import socket
import threading
import os
import json
import time

SERVER_IP = "192.168.6.39"  # Replace with your server's IP
PORT = 12345

# Global flags and variables
is_dark_mode = False
file_list_text_area = None
requested_filename = None
user_listbox_global = None  # used to update the user list in the left panel
current_username_global = None  # store the current user

def recvall(sock, n):
    """Helper function to receive exactly n bytes from the socket."""
    data = b""
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None  # Connection closed
        data += packet
    return data


#############################
# THEME FUNCTIONS
#############################

def apply_theme(root, text_area, entry_widget, buttons):
    global is_dark_mode
    if is_dark_mode:
        # Dark theme colors
        root.configure(bg="#2e2e2e")
        text_area.configure(bg="#3c3f41", fg="#ffffff", insertbackground="#ffffff")
        entry_widget.configure(bg="#3c3f41", fg="#ffffff")
        for btn in buttons:
            btn.configure(bg="#5c5c5c", fg="#ffffff")
    else:
        # Light theme colors
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

#############################
# MESSAGE SENDING FUNCTIONS
#############################

def send_public_message(client_socket, entry, text_widget, username):
    message = entry.get()
    if message:
        try:
            client_socket.send("TEXT".encode())
            client_socket.send(f"{username}:{message}".encode())
        except Exception as e:
            print(e)
        text_widget.config(state="normal")
        text_widget.insert(tk.END, f"[You]: {message}\n")
        text_widget.config(state="disabled")
        entry.delete(0, tk.END)

def send_private_message(client_socket, recipient, entry, text_widget, username):
    message = entry.get()
    if message:
        try:
            client_socket.send("PRIV".encode())
            # Protocol: send recipient and message separated by "<:>"
            client_socket.send(f"{recipient}<:>{message}".encode())
        except Exception as e:
            print(e)
        text_widget.config(state="normal")
        text_widget.insert(tk.END, f"[You]: {message}\n")
        text_widget.config(state="disabled")
        entry.delete(0, tk.END)

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

def file_options(client_socket):
    global file_list_text_area
    file_window = tk.Toplevel()
    file_window.title("File Options")
    file_list_frame = tk.Frame(file_window)
    file_list_frame.pack(pady=5)
    file_list_text_area = tk.Text(file_list_frame, state='disabled', height=10, width=50)
    file_list_text_area.pack()
    # Request file list from server (LIST command)
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

#############################
# USER LIST FUNCTIONS
#############################

def request_user_list(client_socket):
    # Request the user list (the server should respond with header "USRS" and a JSON payload)
    try:
        client_socket.send("USRS".encode())
    except Exception as e:
        print(e)

#############################
# MESSAGE RECEIVING FUNCTION
#############################

def receive_messages(client_socket, chat_tabs, open_private_tab):
    # Preconfigure our tags, etc.
    while True:
        try:
            header_bytes = recvall(client_socket, 4)
            if not header_bytes:
                break  # Connection closed
            header = header_bytes.decode()

            if header == "HIST":
                # For simplicity we assume the JSON payload fits in 4096 bytes.
                hist_json_bytes = recvall(client_socket, 4096)
                if not hist_json_bytes:
                    break
                hist_json = hist_json_bytes.decode()
                messages = json.loads(hist_json)
                public_text = chat_tabs["public"]["text"]
                public_text.config(state="normal")
                for m in messages:
                    public_text.insert(tk.END, f"{m['timestamp']} - {m['username']}: {m['message']}\n")
                public_text.config(state="disabled")
            elif header == "TEXT":
                message_bytes = recvall(client_socket, 1024)
                if not message_bytes:
                    break
                message = message_bytes.decode()
                if ":" in message:
                    sender, msg = message.split(":", 1)
                else:
                    sender, msg = "unknown", message
                public_text = chat_tabs["public"]["text"]
                public_text.config(state="normal")
                public_text.insert(tk.END, f"Public from {sender} => {msg}\n")
                public_text.config(state="disabled")
            elif header == "PRIV":
                message_bytes = recvall(client_socket, 1024)
                if not message_bytes:
                    break
                message = message_bytes.decode()
                # Expect message in format "sender<:>message"
                if "<:>" in message:
                    sender, msg = message.split("<:>", 1)
                else:
                    if ":" in message:
                        sender, msg = message.split(":", 1)
                    else:
                        sender, msg = "unknown", message
                def update_private():
                    if sender not in chat_tabs:
                        open_private_tab(sender)
                    private_text = chat_tabs[sender]["text"]
                    private_text.config(state="normal")
                    private_text.insert(tk.END, f"{sender}: {msg}\n")
                    private_text.config(state="disabled")
                tk._default_root.after(0, update_private)
            elif header == "USRS":
                # Read the user list JSON (again assuming 4096 bytes is enough)
                user_list_bytes = recvall(client_socket, 4096)
                if not user_list_bytes:
                    break
                user_list_json = user_list_bytes.decode()
                users = json.loads(user_list_json)
                def update_user_list():
                    global user_listbox_global, current_username_global
                    if user_listbox_global:
                        user_listbox_global.delete(0, tk.END)
                        for user in users:
                            if user["username"] == current_username_global:
                                continue  # skip yourself
                            status = "online" if user["online"] else "offline"
                            user_listbox_global.insert(tk.END, f"{user['username']}({status})")
                tk._default_root.after(0, update_user_list)
            elif header == "GETF":
                filesize_bytes = recvall(client_socket, 10)
                if not filesize_bytes:
                    break
                filesize_str = filesize_bytes.decode()
                filesize = int(filesize_str.strip())
                if filesize == 0:
                    public_text = chat_tabs["public"]["text"]
                    public_text.config(state="normal")
                    public_text.insert(tk.END, "Requested file not found.\n")
                    public_text.config(state="disabled")
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
                            chunk = recvall(client_socket, min(1024, remaining))
                            if not chunk:
                                break
                            f.write(chunk)
                            remaining -= len(chunk)
                    public_text = chat_tabs["public"]["text"]
                    public_text.config(state="normal")
                    public_text.insert(tk.END, f"File received and saved as {save_path}\n")
                    public_text.config(state="disabled")
            elif header == "LIST":
                file_list_bytes = recvall(client_socket, 4096)
                if not file_list_bytes:
                    break
                file_list = file_list_bytes.decode('utf-8')
                global file_list_text_area
                if file_list_text_area:
                    file_list_text_area.config(state="normal")
                    file_list_text_area.delete("1.0", tk.END)
                    file_list_text_area.insert(tk.END, file_list)
                    file_list_text_area.config(state="disabled")
        except Exception as e:
            print(f"[ERROR] Connection lost: {e}")
            break


#############################
# AUTHENTICATION WINDOW
#############################

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

#############################
# MAIN CHAT UI
#############################

def create_ui(client_socket, username):
    global current_username_global
    current_username_global = username

    root = tk.Tk()
    root.title("Chat Client")
    root.geometry("1200x700")
    # Two-column grid: left for user list, right for chat tabs.
    root.columnconfigure(0, weight=0)
    root.columnconfigure(1, weight=1)
    root.rowconfigure(0, weight=1)

    # LEFT PANEL: USER LIST
    left_frame = tk.Frame(root, width=200, bd=2, relief="sunken")
    left_frame.grid(row=0, column=0, sticky="ns")
    left_frame.grid_propagate(False)
    tk.Label(left_frame, text="Users").pack(pady=5)
    user_listbox = tk.Listbox(left_frame)
    user_listbox.pack(fill="both", expand=True, padx=5, pady=5)
    global user_listbox_global
    user_listbox_global = user_listbox
    refresh_button = tk.Button(left_frame, text="Refresh", command=lambda: request_user_list(client_socket))
    refresh_button.pack(pady=5)

    # RIGHT PANEL: CHAT TABS
    right_frame = tk.Frame(root, bd=2, relief="sunken")
    right_frame.grid(row=0, column=1, sticky="nsew")
    right_frame.columnconfigure(0, weight=1)
    right_frame.rowconfigure(0, weight=1)
    notebook = ttk.Notebook(right_frame)
    notebook.grid(row=0, column=0, sticky="nsew")

    # Dictionary to hold tab widgets; keys: "public" for public chat or a username for private chats.
    chat_tabs = {}

    # PUBLIC CHAT TAB (always present)
    public_tab = tk.Frame(notebook)
    notebook.add(public_tab, text="Public Chat")
    public_text = tk.Text(public_tab, state="disabled", wrap="word")
    public_text.pack(fill="both", expand=True, padx=5, pady=5)

    # Create a control frame for message entry and buttons.
    controls_frame = tk.Frame(public_tab)
    controls_frame.pack(fill="x", padx=5, pady=5)

    public_entry = tk.Entry(controls_frame)
    public_entry.pack(side="left", fill="x", expand=True)

    send_button = tk.Button(controls_frame, text="Send",
                            command=lambda: send_public_message(client_socket, public_entry, public_text, username))
    send_button.pack(side="left", padx=5)

    file_button = tk.Button(controls_frame, text="File",
                            command=lambda: file_options(client_socket))
    file_button.pack(side="left", padx=5)


    # FUNCTION TO OPEN A PRIVATE CHAT TAB
    def open_private_tab(recipient):
        if recipient in chat_tabs:
            notebook.select(chat_tabs[recipient]["frame"])
        else:
            new_tab = tk.Frame(notebook)
            notebook.add(new_tab, text=recipient)
            private_text = tk.Text(new_tab, state="disabled", wrap="word")
            private_text.pack(fill="both", expand=True, padx=5, pady=5)
            private_entry = tk.Entry(new_tab)
            private_entry.pack(fill="x", padx=5, pady=5)
            private_entry.bind("<Return>", lambda e: send_private_message(client_socket, recipient, private_entry, private_text, username))
            chat_tabs[recipient] = {"frame": new_tab, "text": private_text, "entry": private_entry, "type": "private"}
            notebook.select(new_tab)

    # When a user in the left list is double-clicked, open a private tab.
    def on_user_select(event):
        selection = user_listbox.curselection()
        if selection:
            index = selection[0]
            user_item = user_listbox.get(index)
            # user_item is in the form "username(online)" or "username(offline)"
            if "(" in user_item:
                recipient = user_item.split("(")[0].strip()
            else:
                recipient = user_item.strip()
            if recipient != username:
                open_private_tab(recipient)
    user_listbox.bind("<Double-Button-1>", on_user_select)

    # Add a dark mode toggle button (for the public chat, but you can extend this)
    dark_button = tk.Button(right_frame, text="Dark Mode: OFF", 
                             command=lambda: toggle_dark_mode(root, public_text, public_entry, dark_button, []))
    dark_button.grid(row=1, column=0, sticky="e", padx=5, pady=5)
    apply_theme(root, public_text, public_entry, [dark_button])
    
    # Start the receiving thread.
    threading.Thread(target=receive_messages, args=(client_socket, chat_tabs, open_private_tab), daemon=True).start()
    
    # Start a background thread to periodically refresh the user list.
    def periodic_update():
        while True:
            request_user_list(client_socket)
            time.sleep(10)
    threading.Thread(target=periodic_update, daemon=True).start()
    
    root.mainloop()

#############################
# MAIN FUNCTION
#############################

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
