import socket
import threading
import struct
from datetime import datetime
from typing import List

from encryption_utils import encrypt_message, decrypt_message

clients_lock = threading.Lock()
clients: List[socket.socket] = []
LOG_FILE = "chat_server.log"


def recv_exact(sock: socket.socket, n: int) -> bytes | None:
    """Receive exactly n bytes from the socket or return None on disconnect."""
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def log_message(addr, message: str) -> None:
    timestamp = datetime.now().isoformat(timespec="seconds")
    line = f"{timestamp} [{addr[0]}:{addr[1]}] {message}\n"
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line)


def broadcast(sender_sock: socket.socket, plaintext: bytes) -> None:
    """Send plaintext to all other clients (encrypted separately per client)."""
    with clients_lock:
        for c in list(clients):
            if c is sender_sock:
                continue
            try:
                payload = encrypt_message(plaintext)
                header = struct.pack("!I", len(payload))
                c.sendall(header + payload)
            except OSError:
                clients.remove(c)
                c.close()


def handle_client(conn: socket.socket, addr) -> None:
    print(f"Client connected: {addr[0]}:{addr[1]}")
    with clients_lock:
        clients.append(conn)

    try:
        while True:
            header = recv_exact(conn, 4)
            if not header:
                break
            (length,) = struct.unpack("!I", header)
            data = recv_exact(conn, length)
            if not data:
                break

            try:
                plaintext = decrypt_message(data)
            except Exception:
                print(f"Failed to decrypt message from {addr}")
                continue

            text = plaintext.decode("utf-8", errors="replace")
            print(f"[{addr[0]}:{addr[1]}] {text}")
            log_message(addr, text)

            broadcast(conn, plaintext)
    finally:
        print(f"Client disconnected: {addr[0]}:{addr[1]}")
        with clients_lock:
            if conn in clients:
                clients.remove(conn)
        conn.close()


def main() -> None:
    host = "0.0.0.0"
    port = 5000

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen()
    print(f"Encrypted chat server listening on {host}:{port}")

    try:
        while True:
            conn, addr = srv.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print("\nShutting down server.")
    finally:
        srv.close()


if __name__ == "__main__":
    main()