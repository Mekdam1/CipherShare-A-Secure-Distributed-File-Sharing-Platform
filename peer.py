import socket
import threading
import os
import shutil
import hashlib
import time
from datetime import datetime, timedelta
from auth import login, signup, verify_credentials
from cryptography.fernet import Fernet, InvalidToken

# Settings
REND_SERVER_IP = 'localhost'
REND_SERVER_PORT = 5000
SHARE_FOLDER = 'shared'
KEY_FILE = 'symmetric.key'
HASHES_FILE = 'file_hashes.txt'
SESSION_TIMEOUT = timedelta(minutes=5)

# Session management
session_active = threading.Event()
login_time = None

# Ensure shared folder exists
if not os.path.exists(SHARE_FOLDER):
    os.makedirs(SHARE_FOLDER)

# Generate symmetric key if not exists
if not os.path.exists(KEY_FILE):
    key = Fernet.generate_key()
    with open(KEY_FILE, 'wb') as f:
        f.write(key)

# Load symmetric key
with open(KEY_FILE, 'rb') as f:
    symmetric_key = f.read()
fernet = Fernet(symmetric_key)

def hash_data(data):
    return hashlib.sha256(data).hexdigest()

def save_file_hash(filename, hash_value):
    with open(HASHES_FILE, 'a') as f:
        f.write(f"{filename},{hash_value}\n")

def get_file_hash(filename):
    if not os.path.exists(HASHES_FILE):
        return None
    with open(HASHES_FILE, 'r') as f:
        for line in f:
            name, file_hash = line.strip().split(',', 1)
            if name == filename:
                return file_hash
    return None

def handle_client(conn, addr):
    filename = conn.recv(1024).decode()
    filepath = os.path.join(SHARE_FOLDER, filename)
    if os.path.exists(filepath):
        with open(filepath, 'rb') as f:
            encrypted_data = f.read()
        conn.sendall(encrypted_data)
        print(f"[+] Sent encrypted file '{filename}' to {addr}")
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
        with open(file_path, 'rb') as f:
            original_data = f.read()
        encrypted_data = fernet.encrypt(original_data)
        hash_value = hash_data(original_data)

        dest_filename = os.path.basename(file_path)
        dest_path = os.path.join(SHARE_FOLDER, dest_filename)

        with open(dest_path, 'wb') as f:
            f.write(encrypted_data)

        save_file_hash(dest_filename, hash_value)
        print(f"[+] File '{dest_filename}' encrypted and copied to shared folder.")
        print(f"[✓] Hash saved for integrity verification.")
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
        encrypted_data = s.recv(1024 * 1024)
        if encrypted_data.startswith(b'ERROR'):
            print(encrypted_data.decode())
        else:
            try:
                decrypted_data = fernet.decrypt(encrypted_data)
                print("[✓] Decryption successful.")
            except InvalidToken:
                print("[-] Decryption failed. The file may be corrupted or the key is wrong.")
                return

            downloaded_path = os.path.join(SHARE_FOLDER, f"from_{ip}_{filename}")
            with open(downloaded_path, 'wb') as f:
                f.write(decrypted_data)

            received_hash = hash_data(decrypted_data)
            original_hash = get_file_hash(filename)
            if original_hash:
                if received_hash == original_hash:
                    print("[✓] File integrity verified successfully.")
                else:
                    print("[✗] WARNING: File hash mismatch! File may be corrupted.")
            else:
                print("[!] No original hash available for comparison.")

            print(f"[+] File '{filename}' downloaded and saved as '{downloaded_path}'")
    except Exception as e:
        print(f"[-] Failed to download: {e}")
    finally:
        s.close()

def require_active_session():
    global login_time
    while not session_active.is_set():
        print("\n[!] Your session has expired. Please press 1 to re-login.")
        while True:
            choice = input("Press 1 to re-login: ")
            if choice == '1':
                break
            else:
                print("Invalid input. Please press 1 to re-login.")

        username = input("Enter your username: ").strip()
        password = input("Enter your password: ").strip()

        if verify_credentials(username, password):
            print("[+] Re-login successful.")
            login_time = datetime.now()
            session_active.set()
        else:
            print("[-] Login failed. Please try again.")

def session_watcher():
    global login_time
    while True:
        time.sleep(5)
        if login_time and datetime.now() - login_time > SESSION_TIMEOUT:
            session_active.clear()
            require_active_session()

def main():
    global login_time
    print("Welcome to CipherShare\n")
    while True:
        print("1. Login")
        print("2. Sign Up")
        print("3. Exit")
        choice = input("Choose an option: ")

        if choice == '1':
            if login():
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
    threading.Thread(target=session_watcher, daemon=True).start()

    while True:
        print("\nOptions:")
        print("1. List local shared files")
        print("2. Upload a file to share (encrypted)")
        print("3. Connect to rendezvous server")
        print("4. Download file from peer (with decryption & hash check)")
        print("5. Exit")

        choice = input("Select option: ")

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
