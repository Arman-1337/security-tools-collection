#!/usr/bin/env python3
"""
Network Monitor Tool
Real-time network traffic monitoring and analysis.
"""

import socket
import struct
import time
import sys
from datetime import datetime
from collections import defaultdict

class NetworkMonitor:
    """Monitor network traffic and analyze packets."""
    
    def __init__(self):
        """Initialize network monitor."""
        self.packet_count = 0
        self.protocol_stats = defaultdict(int)
        self.ip_stats = defaultdict(int)
        self.port_stats = defaultdict(int)
        self.start_time = None
        self.bytes_received = 0
        
    def get_protocol_name(self, protocol_num):
        """Get protocol name from protocol number."""
        protocols = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP',
            41: 'IPv6',
            47: 'GRE',
            50: 'ESP',
            51: 'AH',
            89: 'OSPF'
        }
        return protocols.get(protocol_num, f'Unknown ({protocol_num})')
    
    def parse_ip_header(self, data):
        """Parse IP header from raw data."""
        try:
            # Unpack first 20 bytes (IP header)
            ip_header = struct.unpack('!BBHHHBBH4s4s', data[:20])
            
            version_ihl = ip_header[0]
            version = version_ihl >> 4
            ihl = version_ihl & 0xF
            
            iph_length = ihl * 4
            ttl = ip_header[5]
            protocol = ip_header[6]
            s_addr = socket.inet_ntoa(ip_header[8])
            d_addr = socket.inet_ntoa(ip_header[9])
            
            return {
                'version': version,
                'header_length': iph_length,
                'ttl': ttl,
                'protocol': protocol,
                'source_ip': s_addr,
                'dest_ip': d_addr,
                'data': data[iph_length:]
            }
        except Exception as e:
            return None
    
    def parse_tcp_header(self, data):
        """Parse TCP header from data."""
        try:
            tcp_header = struct.unpack('!HHLLBBHHH', data[:20])
            
            source_port = tcp_header[0]
            dest_port = tcp_header[1]
            sequence = tcp_header[2]
            acknowledgement = tcp_header[3]
            
            return {
                'source_port': source_port,
                'dest_port': dest_port,
                'sequence': sequence,
                'acknowledgement': acknowledgement
            }
        except:
            return None
    
    def parse_udp_header(self, data):
        """Parse UDP header from data."""
        try:
            udp_header = struct.unpack('!HHHH', data[:8])
            
            source_port = udp_header[0]
            dest_port = udp_header[1]
            length = udp_header[2]
            
            return {
                'source_port': source_port,
                'dest_port': dest_port,
                'length': length
            }
        except:
            return None
    
    def display_packet(self, packet_info):
        """Display packet information."""
        self.packet_count += 1
        
        protocol_name = self.get_protocol_name(packet_info['protocol'])
        self.protocol_stats[protocol_name] += 1
        self.ip_stats[packet_info['source_ip']] += 1
        
        print(f"\n[Packet #{self.packet_count}] {datetime.now().strftime('%H:%M:%S')}")
        print(f"  Protocol: {protocol_name}")
        print(f"  Source IP: {packet_info['source_ip']}")
        print(f"  Dest IP: {packet_info['dest_ip']}")
        print(f"  TTL: {packet_info['ttl']}")
        
        # Parse transport layer
        if packet_info['protocol'] == 6:  # TCP
            tcp_info = self.parse_tcp_header(packet_info['data'])
            if tcp_info:
                print(f"  Source Port: {tcp_info['source_port']}")
                print(f"  Dest Port: {tcp_info['dest_port']}")
                self.port_stats[tcp_info['dest_port']] += 1
                
        elif packet_info['protocol'] == 17:  # UDP
            udp_info = self.parse_udp_header(packet_info['data'])
            if udp_info:
                print(f"  Source Port: {udp_info['source_port']}")
                print(f"  Dest Port: {udp_info['dest_port']}")
                self.port_stats[udp_info['dest_port']] += 1
    
    def display_statistics(self):
        """Display monitoring statistics."""
        if self.start_time:
            duration = time.time() - self.start_time
            pps = self.packet_count / duration if duration > 0 else 0
            
            print("\n" + "=" * 60)
            print("NETWORK MONITORING STATISTICS")
            print("=" * 60)
            print(f"Duration: {duration:.2f} seconds")
            print(f"Total Packets: {self.packet_count}")
            print(f"Packets/Second: {pps:.2f}")
            print(f"Total Bytes: {self.bytes_received:,}")
            
            print("\n" + "-" * 60)
            print("PROTOCOL DISTRIBUTION:")
            print("-" * 60)
            for protocol, count in sorted(self.protocol_stats.items(), 
                                         key=lambda x: x[1], reverse=True):
                percentage = (count / self.packet_count * 100) if self.packet_count > 0 else 0
                print(f"  {protocol:10s}: {count:5d} packets ({percentage:5.1f}%)")
            
            print("\n" + "-" * 60)
            print("TOP 10 SOURCE IPs:")
            print("-" * 60)
            for ip, count in sorted(self.ip_stats.items(), 
                                   key=lambda x: x[1], reverse=True)[:10]:
                percentage = (count / self.packet_count * 100) if self.packet_count > 0 else 0
                print(f"  {ip:15s}: {count:5d} packets ({percentage:5.1f}%)")
            
            if self.port_stats:
                print("\n" + "-" * 60)
                print("TOP 10 DESTINATION PORTS:")
                print("-" * 60)
                for port, count in sorted(self.port_stats.items(), 
                                         key=lambda x: x[1], reverse=True)[:10]:
                    percentage = (count / self.packet_count * 100) if self.packet_count > 0 else 0
                    print(f"  Port {port:5d}: {count:5d} packets ({percentage:5.1f}%)")
            
            print("=" * 60)
    
    def start_monitoring(self, duration=30, packet_limit=100):
        """
        Start monitoring network traffic.
        
        Args:
            duration: Maximum monitoring time in seconds
            packet_limit: Maximum number of packets to capture
        """
        print("\n" + "=" * 60)
        print("NETWORK MONITOR - Security Tools Collection")
        print("=" * 60)
        print(f"Monitoring Duration: {duration} seconds")
        print(f"Packet Limit: {packet_limit}")
        print("\nPress Ctrl+C to stop monitoring early")
        print("=" * 60)
        
        try:
            # Create raw socket
            # Note: Requires admin/root privileges on most systems
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            except PermissionError:
                print("\n❌ ERROR: This tool requires administrator/root privileges!")
                print("\nOn Windows: Run Command Prompt as Administrator")
                print("On Linux/Mac: Run with sudo")
                return
            except OSError:
                print("\n⚠️  Unable to create raw socket.")
                print("Switching to connection monitoring mode...\n")
                self.monitor_connections(duration)
                return
            
            self.start_time = time.time()
            end_time = self.start_time + duration
            
            print("\n🔍 Monitoring network traffic...\n")
            
            while time.time() < end_time and self.packet_count < packet_limit:
                try:
                    # Receive packet
                    packet, addr = s.recvfrom(65565)
                    self.bytes_received += len(packet)
                    
                    # Parse IP header
                    packet_info = self.parse_ip_header(packet)
                    
                    if packet_info:
                        self.display_packet(packet_info)
                    
                except socket.timeout:
                    continue
                except KeyboardInterrupt:
                    print("\n\n⚠️  Monitoring stopped by user")
                    break
            
            s.close()
            
        except Exception as e:
            print(f"\n❌ Error: {str(e)}")
        
        finally:
            self.display_statistics()
    
    def monitor_connections(self, duration=30):
        """Alternative monitoring for systems without raw socket support."""
        print("=" * 60)
        print("CONNECTION MONITORING MODE")
        print("=" * 60)
        print("\nMonitoring active network connections...")
        print(f"Duration: {duration} seconds\n")
        
        import psutil
        
        self.start_time = time.time()
        end_time = self.start_time + duration
        
        connections_seen = set()
        
        try:
            while time.time() < end_time:
                try:
                    # Get network connections
                    connections = psutil.net_connections(kind='inet')
                    
                    for conn in connections:
                        if conn.status == 'ESTABLISHED':
                            conn_id = (conn.laddr, conn.raddr, conn.status)
                            
                            if conn_id not in connections_seen:
                                connections_seen.add(conn_id)
                                self.packet_count += 1
                                
                                print(f"[{self.packet_count}] New Connection:")
                                print(f"  Local: {conn.laddr.ip}:{conn.laddr.port}")
                                if conn.raddr:
                                    print(f"  Remote: {conn.raddr.ip}:{conn.raddr.port}")
                                    self.ip_stats[conn.raddr.ip] += 1
                                print(f"  Status: {conn.status}\n")
                    
                    time.sleep(1)
                    
                except KeyboardInterrupt:
                    print("\n⚠️  Monitoring stopped by user")
                    break
                    
        except ImportError:
            print("\n❌ psutil module not installed")
            print("Install with: pip install psutil")
        
        print("\n" + "=" * 60)
        print(f"Total Connections Monitored: {self.packet_count}")
        print("=" * 60)

def main():
    """Main function to run network monitor."""
    print("\n" + "=" * 60)
    print("NETWORK MONITOR TOOL")
    print("=" * 60)
    print("\n⚠️  NOTE: Packet capture requires administrator privileges")
    print("         Connection monitoring works without elevated access\n")
    
    try:
        duration = input("Enter monitoring duration in seconds (default 30): ").strip()
        duration = int(duration) if duration else 30
        
        packet_limit = input("Enter packet limit (default 100): ").strip()
        packet_limit = int(packet_limit) if packet_limit else 100
        
        if duration < 1 or duration > 300:
            print("Error: Duration must be between 1-300 seconds")
            sys.exit(1)
            
    except ValueError:
        print("Error: Please enter valid numbers")
        sys.exit(1)
    
    monitor = NetworkMonitor()
    
    try:
        monitor.start_monitoring(duration, packet_limit)
    except KeyboardInterrupt:
        print("\n\n⚠️  Monitoring interrupted by user")
        monitor.display_statistics()
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()