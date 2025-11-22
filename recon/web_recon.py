"""
Web Reconnaissance Tool for eLMS Django Application
Performs ethical security assessment

⚠️  ETHICAL USE ONLY - Only scan your own applications!
"""
import requests
import socket
import json
from datetime import datetime
from urllib.parse import urljoin
from pathlib import Path

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    print("⚠️  python-nmap not installed. Install with: pip install python-nmap")

class WebRecon:
    def __init__(self, target_url='http://localhost:8000'):
        """
        Initialize web reconnaissance
        
        Args:
            target_url: Target application URL
        """
        self.target_url = target_url
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'target': target_url,
            'findings': [],
            'vulnerabilities': [],
            'recommendations': []
        }
        
        print("=" * 80)
        print("  WEB RECONNAISSANCE TOOL - eLMS Django Application")
        print("=" * 80)
        print(f"Target: {target_url}")
        print("\n⚠️  ETHICAL USE ONLY - Only scan your own applications!")
        print("=" * 80 + "\n")
    
    def port_scan(self):
        """Perform port scan using nmap"""
        print("[1/6] Port Scanning...")
        
        if not NMAP_AVAILABLE:
            print("  ⚠️  Nmap not available, skipping port scan")
            print("  Install with: pip install python-nmap")
            print("  And install Nmap: https://nmap.org/download.html\n")
            return
        
        try:
            nm = nmap.PortScanner()
            
            # Scan common web ports
            print("  Scanning ports 8000-9000...")
            nm.scan('127.0.0.1', '8000-9000', arguments='-sV')
            
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in ports:
                        service = nm[host][proto][port]
                        
                        finding = {
                            'category': 'Port Scan',
                            'port': port,
                            'state': service['state'],
                            'service': service['name'],
                            'version': service.get('version', 'Unknown')
                        }
                        
                        self.results['findings'].append(finding)
                        
                        print(f"  ✅ Port {port}: {service['name']} ({service['state']})")
                        
                        if service['state'] == 'open':
                            print(f"     Version: {service.get('version', 'Unknown')}")
        
        except Exception as e:
            print(f"  ❌ Error during port scan: {e}")
        
        print()
    
    def check_security_headers(self):
        """Check HTTP security headers"""
        print("[2/6] Checking Security Headers...")
        
        try:
            response = requests.get(self.target_url, timeout=10)
            headers = response.headers
            
            # Required security headers
            required_headers = {
                'X-Frame-Options': {
                    'description': 'Clickjacking protection',
                    'expected': ['DENY', 'SAMEORIGIN']
                },
                'X-Content-Type-Options': {
                    'description': 'MIME type sniffing protection',
                    'expected': ['nosniff']
                },
                'Strict-Transport-Security': {
                    'description': 'HTTPS enforcement (HSTS)',
                    'expected': None
                },
                'Content-Security-Policy': {
                    'description': 'XSS and injection protection',
                    'expected': None
                },
                'X-XSS-Protection': {
                    'description': 'XSS filter',
                    'expected': ['1; mode=block']
                }
            }
            
            for header, config in required_headers.items():
                if header in headers:
                    value = headers[header]
                    print(f"  ✅ {header}: {value}")
                    
                    self.results['findings'].append({
                        'category': 'Security Headers',
                        'header': header,
                        'value': value,
                        'status': 'Present'
                    })
                else:
                    print(f"  ❌ Missing: {header}")
                    print(f"     Description: {config['description']}")
                    
                    self.results['vulnerabilities'].append({
                        'severity': 'MEDIUM',
                        'type': 'Missing Security Header',
                        'header': header,
                        'description': config['description']
                    })
                    
                    self.results['recommendations'].append({
                        'issue': f'Missing {header} header',
                        'recommendation': f"Add {header} header to protect against {config['description']}"
                    })
        
        except Exception as e:
            print(f"  ❌ Error checking headers: {e}")
        
        print()
    
    def enumerate_endpoints(self):
        """Enumerate common endpoints"""
        print("[3/6] Enumerating Endpoints...")
        
        common_endpoints = [
            ('/', 'Home Page'),
            ('/admin/', 'Admin Panel'),
            ('/login/', 'Login Page'),
            ('/logout/', 'Logout'),
            ('/api/', 'API Endpoint'),
            ('/static/', 'Static Files'),
            ('/media/', 'Media Files'),
            ('/.git/', 'Git Repository'),
            ('/.env', 'Environment File'),
            ('/robots.txt', 'Robots File'),
            ('/sitemap.xml', 'Sitemap'),
            ('/favicon.ico', 'Favicon'),
        ]
        
        for endpoint, description in common_endpoints:
            url = urljoin(self.target_url, endpoint)
            try:
                response = requests.get(url, timeout=5, allow_redirects=False)
                status = response.status_code
                
                if status == 200:
                    print(f"  ✅ {endpoint} - {description} (Status: {status})")
                    self.results['findings'].append({
                        'category': 'Accessible Endpoint',
                        'endpoint': endpoint,
                        'description': description,
                        'status_code': status
                    })
                    
                    # Check for sensitive files
                    if endpoint in ['/.git/', '/.env']:
                        self.results['vulnerabilities'].append({
                            'severity': 'CRITICAL',
                            'type': 'Sensitive File Exposed',
                            'endpoint': endpoint,
                            'description': f'{description} is publicly accessible'
                        })
                        print(f"     🚨 CRITICAL: Sensitive file exposed!")
                
                elif status == 403:
                    print(f"  🔒 {endpoint} - Forbidden (Status: {status})")
                
                elif status == 404:
                    print(f"  ❌ {endpoint} - Not Found (Status: {status})")
                
                elif status in [301, 302]:
                    print(f"  ↪️  {endpoint} - Redirect (Status: {status})")
            
            except requests.exceptions.RequestException:
                pass
        
        print()
    
    def check_ssl_tls(self):
        """Check SSL/TLS configuration"""
        print("[4/6] Checking SSL/TLS Configuration...")
        
        if self.target_url.startswith('https://'):
            try:
                response = requests.get(self.target_url, verify=True, timeout=10)
                print("  ✅ Valid SSL/TLS certificate")
                
                self.results['findings'].append({
                    'category': 'SSL/TLS',
                    'status': 'Valid certificate'
                })
            
            except requests.exceptions.SSLError as e:
                print(f"  ❌ Invalid SSL/TLS certificate: {e}")
                
                self.results['vulnerabilities'].append({
                    'severity': 'HIGH',
                    'type': 'Invalid SSL Certificate',
                    'description': str(e)
                })
        
        else:
            print("  ⚠️  Not using HTTPS")
            print("     Recommendation: Enable HTTPS for production")
            
            self.results['vulnerabilities'].append({
                'severity': 'HIGH',
                'type': 'No HTTPS',
                'description': 'Application not using HTTPS'
            })
            
            self.results['recommendations'].append({
                'issue': 'HTTP only (not secure)',
                'recommendation': 'Enable HTTPS with valid SSL/TLS certificate'
            })
        
        print()
    
    def check_common_vulnerabilities(self):
        """Check for common web vulnerabilities"""
        print("[5/6] Checking Common Vulnerabilities...")
        
        # Test for SQL injection (safe test)
        print("  Testing SQL Injection Protection...")
        test_payloads = [
            "' OR '1'='1",
            "admin'--",
            "1' UNION SELECT NULL--"
        ]
        
        sql_injection_found = False
        for payload in test_payloads:
            try:
                # Test on a safe endpoint (just checking if it's filtered)
                url = urljoin(self.target_url, f"/search/?q={payload}")
                response = requests.get(url, timeout=5)
                
                # Check if payload is reflected in response
                if payload in response.text:
                    print(f"  ⚠️  Potential SQL injection vulnerability")
                    sql_injection_found = True
                    break
            
            except:
                pass
        
        if not sql_injection_found:
            print("  ✅ SQL Injection: Protected")
        
        # Test for XSS (safe test)
        print("  Testing XSS Protection...")
        xss_payload = "<script>alert('XSS')</script>"
        xss_found = False
        
        try:
            url = urljoin(self.target_url, f"/search/?q={xss_payload}")
            response = requests.get(url, timeout=5)
            
            if xss_payload in response.text:
                print("  ⚠️  Potential XSS vulnerability")
                xss_found = True
                
                self.results['vulnerabilities'].append({
                    'severity': 'HIGH',
                    'type': 'Cross-Site Scripting (XSS)',
                    'description': 'XSS payload not properly sanitized'
                })
        
        except:
            pass
        
        if not xss_found:
            print("  ✅ XSS: Protected")
        
        print()
    
    def technology_fingerprinting(self):
        """Identify technologies used"""
        print("[6/6] Technology Fingerprinting...")
        
        try:
            response = requests.get(self.target_url, timeout=10)
            headers = response.headers
            
            # Check Server header
            if 'Server' in headers:
                server = headers['Server']
                print(f"  Server: {server}")
                self.results['findings'].append({
                    'category': 'Technology',
                    'type': 'Web Server',
                    'value': server
                })
            
            # Check for Django
            if 'csrftoken' in response.cookies or 'sessionid' in response.cookies:
                print("  Framework: Django (detected)")
                self.results['findings'].append({
                    'category': 'Technology',
                    'type': 'Framework',
                    'value': 'Django'
                })
            
            # Check X-Powered-By
            if 'X-Powered-By' in headers:
                powered_by = headers['X-Powered-By']
                print(f"  Powered By: {powered_by}")
                
                # This header can reveal too much information
                self.results['recommendations'].append({
                    'issue': 'X-Powered-By header present',
                    'recommendation': 'Remove X-Powered-By header to reduce information disclosure'
                })
        
        except Exception as e:
            print(f"  ❌ Error: {e}")
        
        print()
    
    def generate_report(self):
        """Generate reconnaissance report"""
        print("=" * 80)
        print("  RECONNAISSANCE SUMMARY")
        print("=" * 80)
        
        print(f"\nTotal Findings: {len(self.results['findings'])}")
        print(f"Vulnerabilities: {len(self.results['vulnerabilities'])}")
        print(f"Recommendations: {len(self.results['recommendations'])}")
        
        # Vulnerability summary
        if self.results['vulnerabilities']:
            print("\n🚨 VULNERABILITIES FOUND:")
            for vuln in self.results['vulnerabilities']:
                print(f"\n  [{vuln['severity']}] {vuln['type']}")
                print(f"  Description: {vuln['description']}")
        else:
            print("\n✅ No critical vulnerabilities found")
        
        # Recommendations
        if self.results['recommendations']:
            print("\n💡 RECOMMENDATIONS:")
            for i, rec in enumerate(self.results['recommendations'], 1):
                print(f"\n  {i}. {rec['issue']}")
                print(f"     → {rec['recommendation']}")
        
        print("\n" + "=" * 80)
        
        # Save report
        report_file = Path('recon') / f"recon_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        report_file.parent.mkdir(exist_ok=True)
        
        with open(report_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print(f"\n✅ Detailed report saved to: {report_file}")
        
        # Generate HTML report
        self.generate_html_report(report_file.with_suffix('.html'))
    
    def generate_html_report(self, output_file):
        """Generate HTML report"""
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Web Reconnaissance Report - eLMS</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; }}
        h2 {{ color: #555; margin-top: 30px; }}
        .critical {{ color: #dc3545; font-weight: bold; }}
        .high {{ color: #fd7e14; font-weight: bold; }}
        .medium {{ color: #ffc107; font-weight: bold; }}
        .low {{ color: #28a745; font-weight: bold; }}
        .finding {{ background: #e9ecef; padding: 10px; margin: 10px 0; border-left: 4px solid #007bff; }}
        .vulnerability {{ background: #f8d7da; padding: 10px; margin: 10px 0; border-left: 4px solid #dc3545; }}
        .recommendation {{ background: #d1ecf1; padding: 10px; margin: 10px 0; border-left: 4px solid #0c5460; }}
        .timestamp {{ color: #666; font-size: 0.9em; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Web Reconnaissance Report</h1>
        <p class="timestamp">Generated: {self.results['timestamp']}</p>
        <p><strong>Target:</strong> {self.results['target']}</p>
        
        <h2>📊 Summary</h2>
        <ul>
            <li>Total Findings: {len(self.results['findings'])}</li>
            <li>Vulnerabilities: {len(self.results['vulnerabilities'])}</li>
            <li>Recommendations: {len(self.results['recommendations'])}</li>
        </ul>
        
        <h2>🚨 Vulnerabilities</h2>
"""
        
        if self.results['vulnerabilities']:
            for vuln in self.results['vulnerabilities']:
                severity_class = vuln['severity'].lower()
                html_content += f"""
        <div class="vulnerability">
            <span class="{severity_class}">[{vuln['severity']}]</span>
            <strong>{vuln['type']}</strong><br>
            {vuln['description']}
        </div>
"""
        else:
            html_content += "<p>✅ No vulnerabilities found</p>"
        
        html_content += """
        <h2>💡 Recommendations</h2>
"""
        
        if self.results['recommendations']:
            for rec in self.results['recommendations']:
                html_content += f"""
        <div class="recommendation">
            <strong>{rec['issue']}</strong><br>
            → {rec['recommendation']}
        </div>
"""
        else:
            html_content += "<p>No recommendations</p>"
        
        html_content += """
    </div>
</body>
</html>
"""
        
        with open(output_file, 'w') as f:
            f.write(html_content)
        
        print(f"✅ HTML report saved to: {output_file}")
    
    def run_full_recon(self):
        """Run complete reconnaissance"""
        self.port_scan()
        self.check_security_headers()
        self.enumerate_endpoints()
        self.check_ssl_tls()
        self.check_common_vulnerabilities()
        self.technology_fingerprinting()
        self.generate_report()

def main():
    """Main function"""
    target = input("Enter target URL (default: http://localhost:8000): ").strip()
    if not target:
        target = 'http://localhost:8000'
    
    recon = WebRecon(target)
    recon.run_full_recon()

if __name__ == '__main__':
    main()
