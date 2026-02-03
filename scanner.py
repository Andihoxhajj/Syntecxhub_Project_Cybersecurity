import socket
import threading
from datetime import datetime
import errno

# Locks for clean printing and thread-safe result writing
print_lock = threading.Lock()
results_lock = threading.Lock()

# port -> status ("OPEN", "CLOSED", "TIMEOUT", "ERROR: ...")
scan_results = {}


def scan_port(host, port, timeout=1):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((host, port))
        s.close()

        # Distinguish between closed and timeout if possible
        if result == 0:
            status = "OPEN"
        elif result == errno.ETIMEDOUT:
            status = "TIMEOUT"
        else:
            status = "CLOSED"

        with results_lock:
            scan_results[port] = status

        with print_lock:
            print(f"[{status}] Port {port}")

    except socket.timeout:
        with results_lock:
            scan_results[port] = "TIMEOUT"
        with print_lock:
            print(f"[TIMEOUT] Port {port}")
    except socket.error as e:
        with results_lock:
            scan_results[port] = f"ERROR: {e}"
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

    save_results(host, start_port, end_port)


def save_results(host, start_port, end_port):
    filename = f"scan_{host}.txt"
    with open(filename, "w") as f:
        f.write(
            f"Scan results for {host} (ports {start_port}-{end_port}) at {datetime.now()}:\n"
        )
        for port in range(start_port, end_port + 1):
            status = scan_results.get(port, "NOT_SCANNED")
            f.write(f"Port {port}: {status}\n")

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
