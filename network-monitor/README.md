# Network Monitor

Real-time network traffic monitoring and packet analysis tool.

## Features

- 📊 Real-time packet capture and analysis
- 🔍 Protocol detection (TCP, UDP, ICMP, etc.)
- 📈 Traffic statistics and visualization
- 🌐 IP address tracking
- 🔌 Port monitoring
- 📉 Packets per second calculation
- 🎯 Top talkers identification

## Usage

### Packet Capture Mode (Requires Admin/Root)

**Windows:**
```bash
# Run Command Prompt as Administrator, then:
python network_monitor.py
```

**Linux/Mac:**
```bash
sudo python3 network_monitor.py
```

### Connection Monitoring Mode (No Admin Required)

The tool will automatically fall back to connection monitoring if raw sockets aren't available.

### Example
```bash
python network_monitor.py

Enter monitoring duration in seconds: 30
Enter packet limit: 100
```

## Output Example
```
==============================================================
NETWORK MONITOR - Security Tools Collection
==============================================================
Monitoring Duration: 30 seconds
Packet Limit: 100

Press Ctrl+C to stop monitoring early
==============================================================

🔍 Monitoring network traffic...

[Packet #1] 15:30:45
  Protocol: TCP
  Source IP: 192.168.1.100
  Dest IP: 142.250.185.46
  TTL: 64
  Source Port: 54321
  Dest Port: 443

[Packet #2] 15:30:46
  Protocol: UDP
  Source IP: 192.168.1.100
  Dest IP: 8.8.8.8
  TTL: 64
  Source Port: 12345
  Dest Port: 53

==============================================================
NETWORK MONITORING STATISTICS
==============================================================
Duration: 30.15 seconds
Total Packets: 87
Packets/Second: 2.89
Total Bytes: 125,432

--------------------------------------------------------------
PROTOCOL DISTRIBUTION:
--------------------------------------------------------------
  TCP       :    65 packets ( 74.7%)
  UDP       :    18 packets ( 20.7%)
  ICMP      :     4 packets (  4.6%)

--------------------------------------------------------------
TOP 10 SOURCE IPs:
--------------------------------------------------------------
  192.168.1.100  :    87 packets (100.0%)

--------------------------------------------------------------
TOP 10 DESTINATION PORTS:
--------------------------------------------------------------
  Port   443:    45 packets ( 51.7%)
  Port    80:    15 packets ( 17.2%)
  Port    53:    10 packets ( 11.5%)
==============================================================
```

## How It Works

1. **Packet Capture**: Uses raw sockets to capture network packets
2. **Protocol Analysis**: Parses IP, TCP, and UDP headers
3. **Statistics Collection**: Tracks protocols, IPs, and ports
4. **Real-time Display**: Shows packet information as it's captured
5. **Summary Report**: Displays comprehensive statistics at the end

## Requirements

- Python 3.6+
- Administrator/Root privileges (for packet capture mode)
- `psutil` for connection monitoring mode (optional)

Install psutil:
```bash
pip install psutil
```

## Monitoring Modes

### 1. Packet Capture Mode
- Requires admin/root privileges
- Captures all network packets
- Provides detailed packet analysis
- Best for deep network analysis

### 2. Connection Monitoring Mode
- No special privileges required
- Monitors active connections
- Good for basic network monitoring
- Works on all systems

## Common Use Cases

- 🔒 Security monitoring
- 🐛 Network troubleshooting
- 📊 Traffic analysis
- 🎯 Bandwidth monitoring
- 🔍 Intrusion detection
- 📈 Performance analysis

## Disclaimer

⚠️ **For educational and authorized network monitoring only.**  
Always obtain proper authorization before monitoring network traffic.  
Unauthorized network monitoring may be illegal in your jurisdiction.

## Troubleshooting

**"Permission Denied" Error:**
- Windows: Run Command Prompt as Administrator
- Linux/Mac: Use `sudo`

**"Module not found" Error:**
```bash
pip install psutil
```

## Author

Arman Bin Tahir - Cybersecurity Engineer
