import socket
import struct
import threading

from encryption_utils import encrypt_message, decrypt_message


def recv_exact(sock: socket.socket, n: int) -> bytes | None:
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def receive_loop(sock: socket.socket) -> None:
    """Receive and decrypt messages from server."""
    while True:
        header = recv_exact(sock, 4)
        if not header:
            print("Disconnected from server.")
            break
        (length,) = struct.unpack("!I", header)
        data = recv_exact(sock, length)
        if not data:
            print("Disconnected from server.")
            break

        try:
            plaintext = decrypt_message(data)
            text = plaintext.decode("utf-8", errors="replace")
            print(f"\n[chat] {text}")
            print("> ", end="", flush=True)
        except Exception:
            print("\n[error] Failed to decrypt incoming message.")
            print("> ", end="", flush=True)


def send_loop(sock: socket.socket) -> None:
    """Read user input, encrypt, and send to server."""
    try:
        while True:
            msg = input("> ").strip()
            if not msg:
                continue
            if msg.lower() in {"quit", "exit"}:
                break

            plaintext = msg.encode("utf-8")
            payload = encrypt_message(plaintext)
            header = struct.pack("!I", len(payload))
            sock.sendall(header + payload)
    except (EOFError, KeyboardInterrupt):
        pass


def main() -> None:
    host = input("Server IP (default 127.0.0.1): ").strip() or "127.0.0.1"
    port_str = input("Server port (default 5000): ").strip() or "5000"
    port = int(port_str)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    print(f"Connected to {host}:{port}. Type 'exit' to quit.")

    t = threading.Thread(target=receive_loop, args=(s,), daemon=True)
    t.start()

    send_loop(s)
    s.close()


if __name__ == "__main__":
    main()