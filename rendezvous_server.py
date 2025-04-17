# rendezvous_server.py
import socket
import threading

HOST = '0.0.0.0'
PORT = 5000
peers = set()

def handle_client(conn, addr):
    try:
        peer_info = conn.recv(1024).decode()
        print(f"[REGISTERED] {peer_info}")
        peers.add(peer_info)
        conn.sendall(str(list(peers)).encode())
    except:
        pass
    finally:
        conn.close()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()
    print(f"[RENDEZVOUS SERVER] Running on {HOST}:{PORT}")
    
    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_client, args=(conn, addr)).start()

if __name__ == "__main__":
    start_server()
