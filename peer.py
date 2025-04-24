import socket
import threading
import os
import shutil
from datetime import datetime, timedelta
import time
import hashlib

# Authentication constants
USERS_FILE = 'users.txt'
DEBUG_FILE = 'users_hashed_debug.txt'
SHARE_FOLDER = 'shared'
REND_SERVER_IP = 'localhost'
REND_SERVER_PORT = 5000
SESSION_DURATION = timedelta(minutes=5)

# Create shared folder if it doesn't exist
if not os.path.exists(SHARE_FOLDER):
    os.makedirs(SHARE_FOLDER)

# Session management
login_time = None
session_active = threading.Event()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def save_user(username, hashed_password):
    with open(USERS_FILE, 'a') as f:
        f.write(f"{username},{hashed_password}\n")
    with open(DEBUG_FILE, 'a') as debug:
        debug.write(f"{username} => {hashed_password}\n")

def user_exists(username):
    if not os.path.exists(USERS_FILE):
        return False
    with open(USERS_FILE, 'r') as f:
        for line in f:
            saved_user, _ = line.strip().split(',', 1)
            if username == saved_user:
                return True
    return False

def signup():
    username = input("Choose a username: ").strip()
    password = input("Choose a password: ").strip()

    if user_exists(username):
        print("[-] Username already exists.")
        return False

    hashed = hash_password(password)
    save_user(username, hashed)
    print("[+] Signup successful.")
    return True

def login():
    print("\nPlease log in to continue:")
    username = input("Enter username: ").strip()
    password = input("Enter password: ").strip()

    hashed_input = hash_password(password)

    if not os.path.exists(USERS_FILE):
        print("[-] No users registered yet.")
        return False

    with open(USERS_FILE, 'r') as f:
        for line in f:
            saved_user, saved_hash = line.strip().split(',', 1)
            if username == saved_user and hashed_input == saved_hash:
                print("[+] Login successful.")
                return True

    print("[-] Invalid username or password.")
    return False

def session_monitor():
    global login_time
    while True:
        if session_active.is_set() and login_time:
            if datetime.now() - login_time > SESSION_DURATION:
                print("\n[!] Session expired. Please log in again to relogin please press 1.")
                session_active.clear()
                login_time = None
        time.sleep(5)

def handle_client(conn, addr):
    filename = conn.recv(1024).decode()
    filepath = os.path.join(SHARE_FOLDER, filename)
    if os.path.exists(filepath):
        with open(filepath, 'rb') as f:
            data = f.read()
            conn.sendall(data)
        print(f"[+] Sent file '{filename}' to {addr}")
    else:
        conn.send(b'ERROR: File not found')
    conn.close()

def file_server(port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('', port))
    server.listen(5)
    print(f"[+] File server started on port {port}")
    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_client, args=(conn, addr)).start()

def list_files():
    files = os.listdir(SHARE_FOLDER)
    if not files:
        print("No files shared.")
    else:
        for f in files:
            print(f)

def upload_file():
    file_path = input("Enter the full path of the file you want to share: ").strip()
    if os.path.isfile(file_path):
        dest_path = os.path.join(SHARE_FOLDER, os.path.basename(file_path))
        shutil.copy(file_path, dest_path)
        print(f"[+] File '{os.path.basename(file_path)}' copied to shared folder.")
    else:
        print("[-] File not found. Please check the path.")

def connect_to_server(port):
    peer_info = f"{socket.gethostbyname(socket.gethostname())}:{port}"
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((REND_SERVER_IP, REND_SERVER_PORT))
        s.send(peer_info.encode())
        data = s.recv(4096).decode()
        peers = eval(data) if data else []
        print("Connected Peers:")
        for p in peers:
            print(f"- {p}")
        return peers
    except Exception as e:
        print(f"[-] Could not connect to rendezvous server: {e}")
        return []
    finally:
        s.close()

def download_file():
    peer = input("Enter peer IP:PORT to download from: ")
    filename = input("Enter the filename to download: ")
    try:
        ip, port = peer.split(':')
        port = int(port)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, port))
        s.send(filename.encode())
        data = s.recv(1024 * 1024)
        if data.startswith(b'ERROR'):
            print(data.decode())
        else:
            with open(os.path.join(SHARE_FOLDER, f"from_{ip}_{filename}"), 'wb') as f:
                f.write(data)
            print(f"[+] File '{filename}' downloaded from {peer}")
    except Exception as e:
        print(f"[-] Failed to download: {e}")
    finally:
        if 's' in locals():
            s.close()

def require_active_session():
    global login_time
    while not session_active.is_set():
        if login():
            login_time = datetime.now()
            session_active.set()
        else:
            print("[-] Login failed. Please try again.")

def main():
    print("Welcome to CipherShare\n")

    threading.Thread(target=session_monitor, daemon=True).start()

    # Initial login
    while True:
        print("\n1. Login")
        print("2. Sign Up")
        print("3. Exit")
        choice = input("Choose an option: ")

        if choice == '1':
            if login():
                global login_time
                login_time = datetime.now()
                session_active.set()
                break
        elif choice == '2':
            signup()
        elif choice == '3':
            return
        else:
            print("Invalid choice.")

    port = int(input("Enter your peer port (e.g. 6000, 6001): "))
    threading.Thread(target=file_server, args=(port,), daemon=True).start()

    while True:
        print("\nOptions:")
        print("1. List local shared files")
        print("2. Upload a file to share")
        print("3. Connect to rendezvous server")
        print("4. Download file from peer")
        print("5. Exit")

        choice = input("Select option: ")

        if choice in {'1', '2', '3', '4'}:
            require_active_session()

        if choice == '1':
            list_files()
        elif choice == '2':
            upload_file()
        elif choice == '3':
            connect_to_server(port)
        elif choice == '4':
            download_file()
        elif choice == '5':
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()