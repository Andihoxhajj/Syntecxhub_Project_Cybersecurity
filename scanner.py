import socket
import threading
from datetime import datetime

# Lock for clean printing
print_lock = threading.Lock()

open_ports = []

def scan_port(host, port, timeout=1):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((host, port))
        s.close()

        with print_lock:
            if result == 0:
                print(f"[OPEN] Port {port}")
                open_ports.append(port)
            else:
                print(f"[CLOSED] Port {port}")

    except socket.error as e:
        with print_lock:
            print(f"[ERROR] Port {port}: {e}")

def start_scan(host, start_port, end_port):
    print(f"\nScanning {host} from port {start_port} to {end_port}")
    print("Started at:", datetime.now())

    threads = []

    for port in range(start_port, end_port + 1):
        t = threading.Thread(target=scan_port, args=(host, port))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    save_results(host)

def save_results(host):
    filename = f"scan_{host}.txt"
    with open(filename, "w") as f:
        f.write(f"Open ports for {host}:\n")
        for port in open_ports:
            f.write(f"{port}\n")

    print(f"\nResults saved to {filename}")

if __name__ == "__main__":
    host = input("Enter host (example: scanme.nmap.org): ")

    try:
        start = int(input("Start port: "))
        end = int(input("End port: "))

        if start < 1 or end > 65535 or start > end:
            print("Invalid port range. Use 1–65535 and start <= end.")
        else:
            start_scan(host, start, end)

    except ValueError:
        print("Please enter valid numbers for ports.")
