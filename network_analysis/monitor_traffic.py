"""
Network Traffic Monitor for eLMS Django Application
Monitors HTTP/HTTPS traffic for security analysis

Requirements:
    pip install scapy pandas
    
Note: May require administrator privileges for packet capture
"""
import os
import sys
from datetime import datetime
from collections import Counter, defaultdict
import json

try:
    from scapy.all import sniff, TCP, IP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("⚠️  Scapy not installed. Install with: pip install scapy")

class NetworkTrafficMonitor:
    def __init__(self, interface=None, port=8000):
        """
        Initialize network traffic monitor
        
        Args:
            interface: Network interface to monitor (None = all interfaces)
            port: Port to monitor (default: 8000 for Django dev server)
        """
        self.interface = interface
        self.port = port
        self.packets_captured = []
        self.statistics = {
            'total_packets': 0,
            'http_requests': 0,
            'suspicious_patterns': 0,
            'ips': Counter(),
            'methods': Counter(),
            'urls': Counter(),
        }
        
        # Suspicious patterns to detect
        self.attack_patterns = {
            'sql_injection': [
                b'UNION', b'SELECT', b'INSERT', b'DROP', b'DELETE',
                b'--', b';', b'OR 1=1', b"' OR '1'='1"
            ],
            'xss': [
                b'<script', b'javascript:', b'onerror=', b'onload=',
                b'<iframe', b'<img'
            ],
            'path_traversal': [
                b'../', b'..\\', b'%2e%2e', b'%252e'
            ],
            'command_injection': [
                b';', b'|', b'&', b'`', b'$(', b'${'
            ]
        }
    
    def packet_callback(self, packet):
        """Callback function for each captured packet"""
        self.statistics['total_packets'] += 1
        
        # Check if packet has IP and TCP layers
        if packet.haslayer(IP) and packet.haslayer(TCP):
            ip_layer = packet[IP]
            tcp_layer = packet[TCP]
            
            # Filter by port
            if tcp_layer.dport == self.port or tcp_layer.sport == self.port:
                # Track source IP
                self.statistics['ips'][ip_layer.src] += 1
                
                # Check if packet has payload (HTTP data)
                if packet.haslayer(Raw):
                    payload = packet[Raw].load
                    
                    # Try to parse HTTP request
                    try:
                        payload_str = payload.decode('utf-8', errors='ignore')
                        
                        # Check if it's an HTTP request
                        if payload_str.startswith(('GET', 'POST', 'PUT', 'DELETE', 'PATCH')):
                            self.statistics['http_requests'] += 1
                            self.analyze_http_request(payload_str, ip_layer.src)
                    
                    except Exception as e:
                        pass
                    
                    # Check for attack patterns
                    self.detect_attacks(payload, ip_layer.src)
                
                # Store packet info
                self.packets_captured.append({
                    'timestamp': datetime.now().isoformat(),
                    'src_ip': ip_layer.src,
                    'dst_ip': ip_layer.dst,
                    'src_port': tcp_layer.sport,
                    'dst_port': tcp_layer.dport,
                    'size': len(packet)
                })
    
    def analyze_http_request(self, payload, src_ip):
        """Analyze HTTP request"""
        lines = payload.split('\r\n')
        if lines:
            # Parse request line (e.g., "GET /path HTTP/1.1")
            request_line = lines[0].split()
            if len(request_line) >= 2:
                method = request_line[0]
                url = request_line[1]
                
                self.statistics['methods'][method] += 1
                self.statistics['urls'][url] += 1
                
                print(f"[{datetime.now().strftime('%H:%M:%S')}] {method} {url} from {src_ip}")
    
    def detect_attacks(self, payload, src_ip):
        """Detect attack patterns in payload"""
        payload_lower = payload.lower()
        
        for attack_type, patterns in self.attack_patterns.items():
            for pattern in patterns:
                if pattern.lower() in payload_lower:
                    self.statistics['suspicious_patterns'] += 1
                    self.alert_attack(attack_type, pattern.decode('utf-8', errors='ignore'), src_ip)
                    break
    
    def alert_attack(self, attack_type, pattern, src_ip):
        """Alert on detected attack"""
        alert_msg = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║ 🚨 SECURITY ALERT: {attack_type.upper()} DETECTED                                    
╠══════════════════════════════════════════════════════════════════════════════╣
║ Time:     {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
║ Source IP: {src_ip}
║ Pattern:   {pattern}
║ Type:      {attack_type}
╚══════════════════════════════════════════════════════════════════════════════╝
"""
        print(alert_msg)
        
        # Log to file
        with open('logs/security_alerts.log', 'a') as f:
            f.write(alert_msg + '\n')
    
    def start_monitoring(self, duration=None, packet_count=None):
        """Start monitoring network traffic"""
        if not SCAPY_AVAILABLE:
            print("❌ Cannot start monitoring: Scapy not installed")
            print("Install with: pip install scapy")
            return
        
        print("=" * 80)
        print("  NETWORK TRAFFIC MONITOR - eLMS Django Application")
        print("=" * 80)
        print(f"Monitoring Port: {self.port}")
        print(f"Interface: {self.interface or 'All interfaces'}")
        if duration:
            print(f"Duration: {duration} seconds")
        if packet_count:
            print(f"Packet Count: {packet_count}")
        print("\n⚠️  Note: This may require administrator privileges")
        print("Press Ctrl+C to stop monitoring\n")
        print("=" * 80)
        
        try:
            # Start packet capture
            filter_str = f"tcp port {self.port}"
            
            sniff(
                iface=self.interface,
                filter=filter_str,
                prn=self.packet_callback,
                timeout=duration,
                count=packet_count,
                store=False
            )
        
        except PermissionError:
            print("\n❌ Permission denied!")
            print("Please run this script as administrator:")
            print("  Right-click PowerShell → Run as Administrator")
            print("  Then run: python network_analysis/monitor_traffic.py")
        
        except KeyboardInterrupt:
            print("\n\n⏹️  Monitoring stopped by user")
        
        except Exception as e:
            print(f"\n❌ Error: {e}")
        
        finally:
            self.print_statistics()
            self.save_report()
    
    def print_statistics(self):
        """Print monitoring statistics"""
        print("\n" + "=" * 80)
        print("  MONITORING STATISTICS")
        print("=" * 80)
        print(f"Total Packets Captured: {self.statistics['total_packets']}")
        print(f"HTTP Requests: {self.statistics['http_requests']}")
        print(f"Suspicious Patterns: {self.statistics['suspicious_patterns']}")
        
        if self.statistics['ips']:
            print("\nTop Source IPs:")
            for ip, count in self.statistics['ips'].most_common(10):
                print(f"  {ip}: {count} packets")
        
        if self.statistics['methods']:
            print("\nHTTP Methods:")
            for method, count in self.statistics['methods'].most_common():
                print(f"  {method}: {count} requests")
        
        if self.statistics['urls']:
            print("\nTop URLs:")
            for url, count in self.statistics['urls'].most_common(10):
                print(f"  {url}: {count} requests")
        
        print("=" * 80)
    
    def save_report(self):
        """Save monitoring report to file"""
        report_file = f"network_analysis/traffic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        report_data = {
            'timestamp': datetime.now().isoformat(),
            'statistics': {
                'total_packets': self.statistics['total_packets'],
                'http_requests': self.statistics['http_requests'],
                'suspicious_patterns': self.statistics['suspicious_patterns'],
                'top_ips': dict(self.statistics['ips'].most_common(10)),
                'methods': dict(self.statistics['methods']),
                'top_urls': dict(self.statistics['urls'].most_common(10)),
            },
            'packets': self.packets_captured[-100:]  # Last 100 packets
        }
        
        with open(report_file, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        print(f"\n✅ Report saved to: {report_file}")

def main():
    """Main function"""
    print("\n🔍 Network Traffic Monitor for eLMS")
    print("=" * 80)
    
    # Configuration
    port = 8000  # Django development server port
    duration = None  # Monitor indefinitely (use Ctrl+C to stop)
    
    # Create monitor
    monitor = NetworkTrafficMonitor(port=port)
    
    # Start monitoring
    monitor.start_monitoring(duration=duration)

if __name__ == '__main__':
    main()
