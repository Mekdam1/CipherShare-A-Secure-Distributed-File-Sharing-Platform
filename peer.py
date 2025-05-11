import socket
import threading
import os
import hashlib
import time
import json
from datetime import datetime, timedelta
from cryptography.fernet import InvalidToken
from auth import login, signup, get_derived_fernet, verify_password

# Settings
REND_SERVER_IP = 'localhost'
REND_SERVER_PORT = 5000
SHARE_FOLDER = 'shared'
PRIVATE_FOLDER = 'private_shares'
HASHES_FILE = 'file_hashes.txt'
USER_SHARES_FILE = 'user_shares.json'
SESSION_TIMEOUT = timedelta(minutes=5)
BROADCAST_PORT = 5001
BROADCAST_INTERVAL = 30
DISCOVERY_TIMEOUT = 60
BUFFER_SIZE = 1024 * 1024  # 1MB chunks

# Session management
session_active = threading.Event()
login_time = None
fernet = None
current_user = None

# Peer and file discovery
peer_files = {}  # {peer_ip: {'last_seen': timestamp, 'files': [file1, file2]}}
peer_lock = threading.Lock()

# Ensure shared folders exist
if not os.path.exists(SHARE_FOLDER):
    os.makedirs(SHARE_FOLDER)
if not os.path.exists(PRIVATE_FOLDER):
    os.makedirs(PRIVATE_FOLDER)

def hash_data(data):
    return hashlib.sha256(data).hexdigest()

def save_file_hash(filename, hash_value, is_private=False):
    with open(HASHES_FILE, 'a') as f:
        f.write(f"{filename},{hash_value},{int(is_private)}\n")

def get_file_hash(filename, is_private=False):
    if not os.path.exists(HASHES_FILE):
        return None
    with open(HASHES_FILE, 'r') as f:
        for line in f:
            parts = line.strip().split(',')
            if len(parts) >= 2 and parts[0] == filename:
                if len(parts) == 3 and parts[2] == str(int(is_private)):
                    return parts[1]
                elif len(parts) == 2 and not is_private:
                    return parts[1]
    return None

def load_user_shares():
    if os.path.exists(USER_SHARES_FILE):
        with open(USER_SHARES_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_user_shares(shares):
    with open(USER_SHARES_FILE, 'w') as f:
        json.dump(shares, f, indent=2)

def add_file_share(owner, recipient, filename, is_private=False):
    shares = load_user_shares()
    if owner not in shares:
        shares[owner] = {}
    if recipient not in shares[owner]:
        shares[owner][recipient] = []
    if filename not in shares[owner][recipient]:
        shares[owner][recipient].append(filename)
    save_user_shares(shares)

def get_shared_files(username):
    shares = load_user_shares()
    shared_files = []
    for owner in shares:
        if username in shares[owner]:
            shared_files.extend([(owner, f) for f in shares[owner][username]])
    return shared_files

def is_file_shared_with_user(filename, username):
    """Check if a file is shared with the specified user"""
    shares = load_user_shares()
    # Check if file is public
    if any(filename in shares.get(owner, {}).get("public", []) for owner in shares):
        return True
    # Check if file is specifically shared with this user
    if any(filename in shares.get(owner, {}).get(username, []) for owner in shares):
        return True
    return False

def handle_client(conn, addr):
    try:
        data = conn.recv(1024).decode()
        if not data:
            return
            
        if ',' in data:
            # Request from another peer for a shared file
            username, filename = data.split(',', 1)
            
            # Check both public and private folders
            public_path = os.path.join(SHARE_FOLDER, filename)
            private_path = os.path.join(PRIVATE_FOLDER, filename)
            
            filepath = None
            if os.path.exists(public_path) and (username == "public" or is_file_shared_with_user(filename, username)):
                filepath = public_path
            elif os.path.exists(private_path) and is_file_shared_with_user(filename, username):
                filepath = private_path
            
            if filepath:
                # Send file size first
                file_size = os.path.getsize(filepath)
                conn.sendall(str(file_size).encode())
                
                # Wait for ACK
                ack = conn.recv(3)
                if ack != b'ACK':
                    raise ConnectionError("No ACK received")
                
                # Send file in chunks
                with open(filepath, 'rb') as f:
                    while True:
                        chunk = f.read(BUFFER_SIZE)
                        if not chunk:
                            break
                        conn.sendall(chunk)
                print(f"[+] Sent encrypted file '{filename}' to {username}@{addr[0]}")
            else:
                conn.sendall(b'ERROR: File not shared with you or does not exist')
        else:
            # Request for a public file
            filename = data
            filepath = os.path.join(SHARE_FOLDER, filename)
            if os.path.exists(filepath):
                # Send file size first
                file_size = os.path.getsize(filepath)
                conn.sendall(str(file_size).encode())
                
                # Wait for ACK
                ack = conn.recv(3)
                if ack != b'ACK':
                    raise ConnectionError("No ACK received")
                
                # Send file in chunks
                with open(filepath, 'rb') as f:
                    while True:
                        chunk = f.read(BUFFER_SIZE)
                        if not chunk:
                            break
                        conn.sendall(chunk)
                print(f"[+] Sent encrypted file '{filename}' to {addr[0]}")
            else:
                conn.sendall(b'ERROR: File not found')
    except Exception as e:
        print(f"Error handling client {addr[0]}: {e}")
    finally:
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

def broadcast_server():
    """Listen for broadcast messages from other peers"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('', BROADCAST_PORT))
    
    while True:
        try:
            data, addr = sock.recvfrom(1024)
            message = json.loads(data.decode())
            if 'files' in message and 'peer' in message:
                with peer_lock:
                    peer_files[message['peer']] = {
                        'last_seen': time.time(),
                        'files': message['files']
                    }
                    # Remove stale peers
                    stale_peers = [p for p in peer_files 
                                 if time.time() - peer_files[p]['last_seen'] > DISCOVERY_TIMEOUT]
                    for p in stale_peers:
                        del peer_files[p]
        except (json.JSONDecodeError, UnicodeDecodeError, Exception) as e:
            continue

def broadcast_files():
    """Periodically broadcast our file list to the network"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    
    while True:
        try:
            # Only broadcast public files
            files = os.listdir(SHARE_FOLDER)
            message = {
                'peer': f"{socket.gethostbyname(socket.gethostname())}:{port}",
                'files': files
            }
            sock.sendto(json.dumps(message).encode(), ('<broadcast>', BROADCAST_PORT))
            time.sleep(BROADCAST_INTERVAL)
        except Exception as e:
            print(f"Broadcast error: {e}")
            time.sleep(5)

def list_files():
    public_files = os.listdir(SHARE_FOLDER)
    private_files = os.listdir(PRIVATE_FOLDER)
    shared_files = get_shared_files(current_user)
    
    if not public_files and not private_files and not shared_files and not peer_files:
        print("No files available.")
        return
    
    if public_files:
        print("\nYour Public Shared Files:")
        for f in public_files:
            print(f" - {f}")
    
    if private_files:
        print("\nYour Private Shared Files:")
        for f in private_files:
            print(f" - {f}")
    
    if shared_files:
        print("\nFiles Shared With You:")
        for owner, filename in shared_files:
            print(f" - {filename} (shared by {owner})")
    
    if peer_files:
        print("\nPublic Files Available in Network:")
        for peer in peer_files:
            if time.time() - peer_files[peer]['last_seen'] <= DISCOVERY_TIMEOUT:
                print(f"\nFrom {peer}:")
                for f in peer_files[peer]['files']:
                    print(f" - {f}")

def upload_file():
    global fernet, current_user
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

        save_file_hash(dest_filename, hash_value, is_private=False)
        print(f"[+] File '{dest_filename}' encrypted and copied to public shared folder.")
        print(f"[✓] Hash saved for integrity verification.")
        
        # Automatically share with public
        add_file_share(current_user if current_user else "public", "public", dest_filename)
    else:
        print("[-] File not found. Please check the path.")

def share_with_user():
    global current_user, fernet
    
    if not current_user:
        print("[-] You need to be logged in to share files with specific users.")
        return
    
    # Get recipient username
    recipient = input("Enter username to share with: ").strip()
    if not recipient:
        print("[-] Username cannot be empty")
        return
    
    # Get file to share
    file_path = input("Enter the full path of the file to share: ").strip()
    if not os.path.isfile(file_path):
        print("[-] File not found. Please check the path.")
        return
    
    # Encrypt and save the file with recipient's username in filename
    with open(file_path, 'rb') as f:
        original_data = f.read()
    
    encrypted_data = fernet.encrypt(original_data)
    hash_value = hash_data(original_data)
    
    # Create a special filename format: sender_recipient_originalfilename
    original_filename = os.path.basename(file_path)
    shared_filename = f"{current_user}_to_{recipient}_{original_filename}"
    shared_path = os.path.join(PRIVATE_FOLDER, shared_filename)
    
    # Save the encrypted file in private shares folder
    with open(shared_path, 'wb') as f:
        f.write(encrypted_data)
    
    # Save hash for integrity verification (mark as private)
    save_file_hash(shared_filename, hash_value, is_private=True)
    
    # Add to shared files database
    add_file_share(current_user, recipient, shared_filename)
    
    print(f"[+] File '{original_filename}' encrypted and privately shared with user '{recipient}'")
    print(f"[+] Private shared filename: {shared_filename}")

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

def search_files():
    """Search for files across the network"""
    search_term = input("Enter search term (leave empty to list all): ").strip().lower()
    
    print("\nSearch Results:")
    found = False
    
    # Local public files
    local_public_files = os.listdir(SHARE_FOLDER)
    for f in local_public_files:
        if not search_term or search_term in f.lower():
            print(f" - {f} (local public)")
            found = True
    
    # Local private files
    local_private_files = os.listdir(PRIVATE_FOLDER)
    for f in local_private_files:
        if not search_term or search_term in f.lower():
            print(f" - {f} (local private)")
            found = True
    
    # Shared files
    shared_files = get_shared_files(current_user)
    for owner, filename in shared_files:
        if not search_term or search_term in filename.lower():
            print(f" - {filename} (shared by {owner})")
            found = True
    
    # Network files (only public)
    for peer in peer_files:
        if time.time() - peer_files[peer]['last_seen'] <= DISCOVERY_TIMEOUT:
            for f in peer_files[peer]['files']:
                if not search_term or search_term in f.lower():
                    print(f" - {f} (on {peer})")
                    found = True
    
    if not found:
        print("No matching files found.")

def download_file():
    global fernet, current_user
    print("\nAvailable files in network:")
    search_files()
    
    peer = input("\nEnter peer IP:PORT to download from (or leave empty to cancel): ").strip()
    if not peer:
        return
    
    filename = input("Enter the filename to download: ").strip()
    
    try:
        ip, port = peer.split(':')
        port = int(port)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((ip, port))
        
        # Send request
        if current_user:
            s.send(f"{current_user},{filename}".encode())
        else:
            s.send(f"public,{filename}".encode())
            
        # Get response (file size or error)
        response = s.recv(1024).decode()
        
        if response.startswith('ERROR'):
            print(response)
            return
        
        # Get file size
        try:
            file_size = int(response)
        except ValueError:
            print("[-] Invalid file size received")
            return
            
        # Send ACK
        s.send(b'ACK')
        
        # Receive file data
        received_data = bytearray()
        remaining = file_size
        
        while remaining > 0:
            chunk = s.recv(min(BUFFER_SIZE, remaining))
            if not chunk:
                break
            received_data.extend(chunk)
            remaining -= len(chunk)
            print(f"\rDownloading... {((file_size - remaining)/file_size)*100:.1f}%", end='')
        
        print()  # New line after progress
        
        if len(received_data) != file_size:
            print("[-] File transfer incomplete")
            return
            
        # Decrypt the data
        try:
            if not received_data:
                raise ValueError("No data received")
                
            decrypted_data = fernet.decrypt(bytes(received_data))
            print("[✓] Decryption successful.")
        except InvalidToken as e:
            print(f"[-] Decryption failed: {e}")
            return
        except Exception as e:
            print(f"[-] Decryption error: {e}")
            return

        # Save the file
        # For files shared specifically with this user, remove the sender_recipient_ prefix
        if filename.startswith(current_user + "_to_") or "_to_" + current_user in filename:
            # Extract original filename
            parts = filename.split('_')
            if len(parts) >= 4:  # sender_to_recipient_originalname
                original_filename = '_'.join(parts[3:])
            else:
                original_filename = filename
        else:
            original_filename = filename
            
        # Save to appropriate folder based on file type
        if filename in os.listdir(SHARE_FOLDER) or not is_file_shared_with_user(filename, current_user):
            downloaded_path = os.path.join(SHARE_FOLDER, original_filename)
        else:
            downloaded_path = os.path.join(PRIVATE_FOLDER, original_filename)
        
        with open(downloaded_path, 'wb') as f:
            f.write(decrypted_data)

        # Verify integrity
        is_private = filename in os.listdir(PRIVATE_FOLDER) if os.path.exists(PRIVATE_FOLDER) else False
        received_hash = hash_data(decrypted_data)
        original_hash = get_file_hash(filename, is_private=is_private)
        
        if original_hash:
            if received_hash == original_hash:
                print("[✓] File integrity verified successfully.")
            else:
                print("[✗] WARNING: File hash mismatch! File may be corrupted.")
        else:
            print("[!] No original hash available for comparison.")

        print(f"[+] File saved as '{original_filename}'")
        
    except socket.timeout:
        print("[-] Connection timed out")
    except ConnectionRefusedError:
        print("[-] Connection refused by peer")
    except Exception as e:
        print(f"[-] Download failed: {e}")
    finally:
        s.close()

def require_active_session():
    global login_time, fernet, current_user
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

        if verify_password(username, password):
            print("[+] Re-login successful.")
            login_time = datetime.now()
            fernet = get_derived_fernet(password)
            current_user = username
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
    global login_time, fernet, current_user, port
    
    print("Welcome to CipherShare\n")
    while True:
        print("1. Login")
        print("2. Sign Up")
        print("3. Exit")
        choice = input("Choose an option: ")

        if choice == '1':
            username = input("Username: ").strip()
            password = input("Password: ").strip()
            if verify_password(username, password):
                login_time = datetime.now()
                session_active.set()
                current_user = username
                fernet = get_derived_fernet(password)
                break
            else:
                print("[-] Invalid credentials.")
        elif choice == '2':
            signup()
        elif choice == '3':
            return
        else:
            print("Invalid choice.")

    port = int(input("Enter your peer port (e.g. 6000, 6001): "))
    
    # Start all background services
    threading.Thread(target=file_server, args=(port,), daemon=True).start()
    threading.Thread(target=session_watcher, daemon=True).start()
    threading.Thread(target=broadcast_server, daemon=True).start()
    threading.Thread(target=broadcast_files, daemon=True).start()

    while True:
        print("\nOptions:")
        print("1. List/Search available files")
        print("2. Upload a file to share (encrypted)")
        print("3. Connect to rendezvous server")
        print("4. Download file from peer")
        print("5. Share a file with specific user")
        print("6. Exit")

        choice = input("Select option: ")

        if choice == '1':
            search_files()
        elif choice == '2':
            upload_file()
        elif choice == '3':
            connect_to_server(port)
        elif choice == '4':
            download_file()
        elif choice == '5':
            share_with_user()
        elif choice == '6':
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()