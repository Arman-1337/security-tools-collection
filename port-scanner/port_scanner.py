#!/usr/bin/env python3
"""
Port Scanner Tool
Scans a target host for open ports within a specified range.
"""

import socket
import sys
from datetime import datetime
import threading
from queue import Queue

# Thread-safe queue for port scanning
print_lock = threading.Lock()
queue = Queue()

def scan_port(host, port):
    """Scan a single port on the target host."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False

def get_service_name(port):
    """Get common service name for a port number."""
    common_ports = {
        20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet",
        25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
        143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
        3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 
        8080: "HTTP-Proxy", 8443: "HTTPS-Alt"
    }
    return common_ports.get(port, "Unknown")

def threader(host):
    """Thread worker function to scan ports from queue."""
    while True:
        port = queue.get()
        if scan_port(host, port):
            with print_lock:
                service = get_service_name(port)
                print(f"[+] Port {port:5d} OPEN    - {service}")
        queue.task_done()

def port_scanner(host, start_port=1, end_port=1024, threads=100):
    """Main port scanning function with multi-threading."""
    print("=" * 60)
    print(f"Port Scanner - Security Tools Collection")
    print("=" * 60)
    print(f"Target Host: {host}")
    print(f"Port Range: {start_port} - {end_port}")
    print(f"Threads: {threads}")
    print(f"Scan Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    
    # Resolve hostname to IP
    try:
        target_ip = socket.gethostbyname(host)
        print(f"Resolved IP: {target_ip}")
        print("-" * 60)
    except socket.gaierror:
        print(f"Error: Unable to resolve hostname '{host}'")
        return
    
    # Create threads
    for _ in range(threads):
        t = threading.Thread(target=threader, args=(host,))
        t.daemon = True
        t.start()
    
    # Add ports to queue
    start_time = datetime.now()
    for port in range(start_port, end_port + 1):
        queue.put(port)
    
    # Wait for all threads to complete
    queue.join()
    
    # Calculate scan time
    end_time = datetime.now()
    scan_duration = (end_time - start_time).total_seconds()
    
    print("-" * 60)
    print(f"Scan Completed: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Duration: {scan_duration:.2f} seconds")
    print("=" * 60)

def main():
    """Main function to handle user input and run scanner."""
    print("\n" + "=" * 60)
    print("PORT SCANNER TOOL")
    print("=" * 60 + "\n")
    
    target = input("Enter target IP/hostname (e.g., scanme.nmap.org): ").strip()
        
    if not target:
        print("Error: No target specified")
        sys.exit(1)
    
    # Get port range
    try:
        start_input = input("Enter start port (default 1): ").strip()
        start_port = int(start_input) if start_input else 1
        
        end_input = input("Enter end port (default 1024): ").strip()
        end_port = int(end_input) if end_input else 1024
        
        if start_port < 1 or end_port > 65535 or start_port > end_port:
            print("Error: Invalid port range (1-65535)")
            sys.exit(1)
            
    except ValueError:
        print("Error: Ports must be numbers")
        sys.exit(1)
    
    # Run scanner
    try:
        port_scanner(target, start_port, end_port)
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()