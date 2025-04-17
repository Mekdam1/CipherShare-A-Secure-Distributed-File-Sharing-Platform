import socket
import threading
import os
import shutil

# Settings
REND_SERVER_IP = 'localhost'
REND_SERVER_PORT = 5000
SHARE_FOLDER = 'shared'

if not os.path.exists(SHARE_FOLDER):
    os.makedirs(SHARE_FOLDER)

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
    s.connect((REND_SERVER_IP, REND_SERVER_PORT))
    s.send(peer_info.encode())
    data = s.recv(4096).decode()
    peers = data.split(';') if data else []
    print("Connected Peers:", peers)
    s.close()
    return peers

def download_file():
    peer = input("Enter peer IP:PORT to download from: ")
    filename = input("Enter the filename to download: ")
    ip, port = peer.split(':')
    port = int(port)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
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
        s.close()

def main():
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
