"""
Simple Intrusion Detection System for Django eLMS
Monitors logs and detects suspicious activities in real-time

This is a learning-focused IDS that demonstrates core concepts
"""
import os
import re
import time
from datetime import datetime, timedelta
from collections import defaultdict
from pathlib import Path
import json

class DjangoIDS:
    def __init__(self, log_dir='logs'):
        """
        Initialize Django IDS
        
        Args:
            log_dir: Directory containing Django logs
        """
        self.log_dir = Path(log_dir)
        self.security_log = self.log_dir / 'security.log'
        self.django_log = self.log_dir / 'django.log'
        self.access_log = self.log_dir / 'access.log'
        
        # Create logs directory if it doesn't exist
        self.log_dir.mkdir(exist_ok=True)
        
        # Create log files if they don't exist
        for log_file in [self.security_log, self.django_log, self.access_log]:
            log_file.touch(exist_ok=True)
        
        # Tracking dictionaries
        self.failed_logins = defaultdict(list)
        self.request_counts = defaultdict(list)
        self.blocked_ips = set()
        self.alerts = []
        
        # Attack patterns (regex)
        self.patterns = {
            'sql_injection': re.compile(
                r'(\bunion\s+select\b|\binsert\s+into\b|\bdrop\s+table\b|\bdelete\s+from\b|\bupdate\s+\w+\s+set\b|--\s)',
                re.IGNORECASE
            ),
            'xss': re.compile(
                r'(<script|javascript:|onerror=|onload=|<iframe|<img)',
                re.IGNORECASE
            ),
            'path_traversal': re.compile(
                r'(\.\./|\.\.\\|%2e%2e|%252e)',
                re.IGNORECASE
            ),
            'command_injection': re.compile(
                r'(;|\||&|`|\$\(|\${)',
                re.IGNORECASE
            ),
        }
        
        # Thresholds
        self.MAX_FAILED_LOGINS = 5
        self.FAILED_LOGIN_WINDOW = 600  # 10 minutes
        self.MAX_REQUESTS_PER_MINUTE = 60
        self.BLOCK_DURATION = 3600  # 1 hour
        
        print("=" * 80)
        print("  DJANGO IDS - Intrusion Detection System")
        print("=" * 80)
        print(f"Security Log: {self.security_log}")
        print(f"Django Log: {self.django_log}")
        print(f"Access Log: {self.access_log}")
        print("\nMonitoring Configuration:")
        print(f"  Max Failed Logins: {self.MAX_FAILED_LOGINS} in {self.FAILED_LOGIN_WINDOW}s")
        print(f"  Max Requests/Min: {self.MAX_REQUESTS_PER_MINUTE}")
        print(f"  Block Duration: {self.BLOCK_DURATION}s")
        print("=" * 80 + "\n")
    
    def extract_ip(self, line):
        """Extract IP address from log line"""
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        match = re.search(ip_pattern, line)
        return match.group(0) if match else None
    
    def analyze_log_line(self, line, log_type='django'):
        """Analyze a single log line for threats"""
        
        # Ignore traceback lines to prevent false positives
        # Traceback lines often contain file paths with quotes that trigger SQL injection detection
        if 'File "' in line and ', line ' in line:
            return
        if 'Traceback (most recent call last):' in line:
            return
            
        # Extract IP address
        ip = self.extract_ip(line)
        
        # Ignore lines without IP address for security alerts (reduces false positives from system logs)
        if not ip and log_type != 'django':
            return

        # Ignore Django URL resolver errors which contain regex patterns
        if 'pattern(s) tried:' in line or 'Not Found:' in line:
            return
            
        # Check for failed login attempts
        if 'Failed login' in line or 'Invalid password' in line or 'Authentication failure' in line:
            if ip:
                self.failed_logins[ip].append(datetime.now())
                self.check_brute_force(ip)
        
        # Check for attack patterns
        for attack_type, pattern in self.patterns.items():
            if pattern.search(line):
                self.alert_attack(attack_type, line, ip)
        
        # Track request rate
        if ip and log_type == 'access':
            self.request_counts[ip].append(datetime.now())
            self.check_request_rate(ip)
    
    def check_brute_force(self, ip):
        """Check for brute force attacks"""
        # Get failed logins in the time window
        cutoff_time = datetime.now() - timedelta(seconds=self.FAILED_LOGIN_WINDOW)
        recent_failures = [
            t for t in self.failed_logins[ip]
            if t > cutoff_time
        ]
        
        # Update the list
        self.failed_logins[ip] = recent_failures
        
        # Alert if threshold exceeded
        if len(recent_failures) >= self.MAX_FAILED_LOGINS:
            self.alert_brute_force(ip, len(recent_failures))
            self.block_ip(ip)
    
    def check_request_rate(self, ip):
        """Check for excessive request rate (potential DoS)"""
        # Get requests in last minute
        cutoff_time = datetime.now() - timedelta(seconds=60)
        recent_requests = [
            t for t in self.request_counts[ip]
            if t > cutoff_time
        ]
        
        # Update the list
        self.request_counts[ip] = recent_requests
        
        # Alert if threshold exceeded
        if len(recent_requests) > self.MAX_REQUESTS_PER_MINUTE:
            self.alert_dos(ip, len(recent_requests))
            self.block_ip(ip)
    
    def block_ip(self, ip):
        """Block an IP address"""
        if ip not in self.blocked_ips:
            self.blocked_ips.add(ip)
            print(f"\n🚫 BLOCKED IP: {ip}")
            print(f"   Block Duration: {self.BLOCK_DURATION}s")
            
            # Log the block
            with open(self.log_dir / 'blocked_ips.log', 'a') as f:
                f.write(f"{datetime.now().isoformat()} - Blocked IP: {ip}\n")
    
    def alert_attack(self, attack_type, log_line, ip):
        """Alert on detected attack"""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'type': attack_type,
            'severity': 'HIGH',
            'source_ip': ip,
            'log_line': log_line.strip()
        }
        
        self.alerts.append(alert)
        
        alert_msg = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║ 🚨 SECURITY ALERT: {attack_type.upper()}
╠══════════════════════════════════════════════════════════════════════════════╣
║ Time:      {alert['timestamp']}
║ Severity:  {alert['severity']}
║ Source IP: {ip or 'Unknown'}
║ Type:      {attack_type}
╠══════════════════════════════════════════════════════════════════════════════╣
║ Log Entry:
║ {log_line[:76]}
╚══════════════════════════════════════════════════════════════════════════════╝
"""
        print(alert_msg)
        
        # Save alert
        self.save_alert(alert)
    
    def alert_brute_force(self, ip, attempts):
        """Alert on brute force attack"""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'type': 'brute_force',
            'severity': 'CRITICAL',
            'source_ip': ip,
            'attempts': attempts
        }
        
        self.alerts.append(alert)
        
        alert_msg = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║ 🚨 CRITICAL ALERT: BRUTE FORCE ATTACK DETECTED
╠══════════════════════════════════════════════════════════════════════════════╣
║ Time:           {alert['timestamp']}
║ Severity:       CRITICAL
║ Source IP:      {ip}
║ Failed Attempts: {attempts}
║ Action:         IP BLOCKED
╚══════════════════════════════════════════════════════════════════════════════╝
"""
        print(alert_msg)
        
        # Save alert
        self.save_alert(alert)
    
    def alert_dos(self, ip, request_count):
        """Alert on potential DoS attack"""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'type': 'dos_attack',
            'severity': 'HIGH',
            'source_ip': ip,
            'request_count': request_count
        }
        
        self.alerts.append(alert)
        
        alert_msg = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║ 🚨 SECURITY ALERT: POTENTIAL DOS ATTACK
╠══════════════════════════════════════════════════════════════════════════════╣
║ Time:          {alert['timestamp']}
║ Severity:      HIGH
║ Source IP:     {ip}
║ Requests/Min:  {request_count}
║ Threshold:     {self.MAX_REQUESTS_PER_MINUTE}
║ Action:        IP BLOCKED
╚══════════════════════════════════════════════════════════════════════════════╝
"""
        print(alert_msg)
        
        # Save alert
        self.save_alert(alert)
    
    def save_alert(self, alert):
        """Save alert to file"""
        alerts_file = self.log_dir / 'ids_alerts.json'
        
        # Load existing alerts
        if alerts_file.exists():
            with open(alerts_file, 'r') as f:
                try:
                    all_alerts = json.load(f)
                except:
                    all_alerts = []
        else:
            all_alerts = []
        
        # Add new alert
        all_alerts.append(alert)
        
        # Save
        with open(alerts_file, 'w') as f:
            json.dump(all_alerts, f, indent=2)
    
    def monitor_logs(self, tail=True):
        """Monitor log files for suspicious activity"""
        print("🔍 Starting log monitoring...")
        print("Press Ctrl+C to stop\n")
        
        # File positions
        positions = {
            'security': 0,
            'django': 0,
            'access': 0
        }
        
        # If tail is True, seek to end of files
        if tail:
            if self.security_log.exists():
                positions['security'] = self.security_log.stat().st_size
            if self.django_log.exists():
                positions['django'] = self.django_log.stat().st_size
            if self.access_log.exists():
                positions['access'] = self.access_log.stat().st_size
        
        try:
            while True:
                # Monitor security log
                if self.security_log.exists():
                    with open(self.security_log, 'r') as f:
                        f.seek(positions['security'])
                        for line in f:
                            self.analyze_log_line(line, 'security')
                        positions['security'] = f.tell()
                
                # Monitor django log
                if self.django_log.exists():
                    with open(self.django_log, 'r') as f:
                        f.seek(positions['django'])
                        for line in f:
                            self.analyze_log_line(line, 'django')
                        positions['django'] = f.tell()
                
                # Monitor access log
                if self.access_log.exists():
                    with open(self.access_log, 'r') as f:
                        f.seek(positions['access'])
                        for line in f:
                            self.analyze_log_line(line, 'access')
                        positions['access'] = f.tell()
                
                # Sleep briefly
                time.sleep(1)
        
        except KeyboardInterrupt:
            print("\n\n⏹️  Monitoring stopped by user")
            self.print_summary()
        
        except Exception as e:
            print(f"\n❌ Error: {e}")
    
    def print_summary(self):
        """Print monitoring summary"""
        print("\n" + "=" * 80)
        print("  IDS MONITORING SUMMARY")
        print("=" * 80)
        print(f"Total Alerts: {len(self.alerts)}")
        print(f"Blocked IPs: {len(self.blocked_ips)}")
        
        if self.blocked_ips:
            print("\nBlocked IP Addresses:")
            for ip in self.blocked_ips:
                print(f"  🚫 {ip}")
        
        if self.alerts:
            print("\nAlert Summary:")
            alert_types = defaultdict(int)
            for alert in self.alerts:
                alert_types[alert['type']] += 1
            
            for alert_type, count in alert_types.items():
                print(f"  {alert_type}: {count}")
        
        print("=" * 80)
        print(f"\n✅ Alerts saved to: {self.log_dir / 'ids_alerts.json'}")
        print(f"✅ Blocked IPs logged to: {self.log_dir / 'blocked_ips.log'}")

def main():
    """Main function"""
    ids = DjangoIDS(log_dir='logs')
    ids.monitor_logs(tail=True)

if __name__ == '__main__':
    main()
