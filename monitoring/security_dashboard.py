"""
Security Monitoring Dashboard for eLMS Django Application
Real-time security metrics and alerts visualization

Requirements:
    pip install flask psutil
"""
from flask import Flask, render_template_string, jsonify
import psutil
import json
from datetime import datetime
from pathlib import Path
from collections import defaultdict

app = Flask(__name__)

# Dashboard HTML template
DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>eLMS Security Dashboard</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        header {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        h1 {
            color: #333;
            font-size: 2em;
        }
        .subtitle {
            color: #666;
            font-size: 0.9em;
        }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        .card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .card h2 {
            color: #333;
            font-size: 1.2em;
            margin-bottom: 15px;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
        }
        .metric {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px 0;
            border-bottom: 1px solid #eee;
        }
        .metric:last-child {
            border-bottom: none;
        }
        .metric-label {
            color: #666;
            font-weight: 500;
        }
        .metric-value {
            font-size: 1.5em;
            font-weight: bold;
            color: #667eea;
        }
        .metric-value.danger {
            color: #dc3545;
        }
        .metric-value.warning {
            color: #ffc107;
        }
        .metric-value.success {
            color: #28a745;
        }
        .alert {
            background: #f8d7da;
            border-left: 4px solid #dc3545;
            padding: 15px;
            margin: 10px 0;
            border-radius: 5px;
        }
        .alert-title {
            font-weight: bold;
            color: #721c24;
            margin-bottom: 5px;
        }
        .alert-time {
            font-size: 0.8em;
            color: #666;
        }
        .status-indicator {
            display: inline-block;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 8px;
        }
        .status-indicator.active {
            background: #28a745;
            box-shadow: 0 0 10px #28a745;
        }
        .status-indicator.inactive {
            background: #dc3545;
        }
        .refresh-info {
            text-align: center;
            color: white;
            margin-top: 20px;
            font-size: 0.9em;
        }
        .progress-bar {
            width: 100%;
            height: 20px;
            background: #e9ecef;
            border-radius: 10px;
            overflow: hidden;
            margin-top: 10px;
        }
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
            transition: width 0.3s ease;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ eLMS Security Monitoring Dashboard</h1>
            <p class="subtitle">Real-time security metrics and threat detection</p>
        </header>
        
        <div class="grid">
            <!-- System Status -->
            <div class="card">
                <h2>System Status</h2>
                <div class="metric">
                    <span class="metric-label">
                        <span class="status-indicator active"></span>
                        Monitoring Status
                    </span>
                    <span class="metric-value success" id="monitoring-status">Active</span>
                </div>
                <div class="metric">
                    <span class="metric-label">CPU Usage</span>
                    <span class="metric-value" id="cpu-usage">--</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Memory Usage</span>
                    <span class="metric-value" id="memory-usage">--</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Disk Usage</span>
                    <span class="metric-value" id="disk-usage">--</span>
                </div>
            </div>
            
            <!-- Security Metrics -->
            <div class="card">
                <h2>Security Metrics</h2>
                <div class="metric">
                    <span class="metric-label">Total Requests</span>
                    <span class="metric-value" id="total-requests">0</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Failed Logins</span>
                    <span class="metric-value danger" id="failed-logins">0</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Active Alerts</span>
                    <span class="metric-value warning" id="active-alerts">0</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Blocked IPs</span>
                    <span class="metric-value danger" id="blocked-ips">0</span>
                </div>
            </div>
            
            <!-- IDS Status -->
            <div class="card">
                <h2>Intrusion Detection</h2>
                <div class="metric">
                    <span class="metric-label">IDS Status</span>
                    <span class="metric-value success" id="ids-status">Monitoring</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Threats Detected</span>
                    <span class="metric-value danger" id="threats-detected">0</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Last Scan</span>
                    <span class="metric-value" id="last-scan" style="font-size: 1em;">--</span>
                </div>
            </div>
        </div>
        
        <!-- Recent Alerts -->
        <div class="card">
            <h2>🚨 Recent Security Alerts</h2>
            <div id="alerts-container">
                <p style="color: #666; text-align: center; padding: 20px;">No alerts</p>
            </div>
        </div>
        
        <p class="refresh-info">
            Dashboard auto-refreshes every 5 seconds | Last updated: <span id="last-update">--</span>
        </p>
    </div>
    
    <script>
        function updateDashboard() {
            fetch('/api/metrics')
                .then(response => response.json())
                .then(data => {
                    // Update system metrics
                    document.getElementById('cpu-usage').textContent = data.system.cpu_percent + '%';
                    document.getElementById('memory-usage').textContent = data.system.memory_percent + '%';
                    document.getElementById('disk-usage').textContent = data.system.disk_percent + '%';
                    
                    // Update security metrics
                    document.getElementById('total-requests').textContent = data.security.total_requests;
                    document.getElementById('failed-logins').textContent = data.security.failed_logins;
                    document.getElementById('active-alerts').textContent = data.security.active_alerts;
                    document.getElementById('blocked-ips').textContent = data.security.blocked_ips;
                    document.getElementById('threats-detected').textContent = data.security.threats_detected;
                    
                    // Update last update time
                    document.getElementById('last-update').textContent = new Date().toLocaleTimeString();
                    document.getElementById('last-scan').textContent = new Date().toLocaleTimeString();
                })
                .catch(error => console.error('Error fetching metrics:', error));
            
            // Fetch alerts
            fetch('/api/alerts')
                .then(response => response.json())
                .then(data => {
                    const container = document.getElementById('alerts-container');
                    
                    if (data.length === 0) {
                        container.innerHTML = '<p style="color: #666; text-align: center; padding: 20px;">No alerts</p>';
                    } else {
                        container.innerHTML = data.map(alert => `
                            <div class="alert">
                                <div class="alert-title">${alert.type}: ${alert.severity}</div>
                                <div>${alert.description || alert.log_line || 'No description'}</div>
                                <div class="alert-time">${alert.timestamp}</div>
                            </div>
                        `).join('');
                    }
                })
                .catch(error => console.error('Error fetching alerts:', error));
        }
        
        // Update dashboard every 5 seconds
        updateDashboard();
        setInterval(updateDashboard, 5000);
    </script>
</body>
</html>
"""

@app.route('/')
def dashboard():
    """Main dashboard page"""
    return render_template_string(DASHBOARD_HTML)

@app.route('/api/metrics')
def get_metrics():
    """Get current security metrics"""
    # Get system metrics
    cpu_percent = round(psutil.cpu_percent(interval=0.1), 1)
    memory_percent = round(psutil.virtual_memory().percent, 1)
    disk_percent = round(psutil.disk_usage('/').percent, 1)
    
    # Get security metrics from IDS logs
    security_metrics = get_security_metrics()
    
    return jsonify({
        'timestamp': datetime.now().isoformat(),
        'system': {
            'cpu_percent': cpu_percent,
            'memory_percent': memory_percent,
            'disk_percent': disk_percent
        },
        'security': security_metrics
    })

@app.route('/api/alerts')
def get_alerts():
    """Get recent security alerts"""
    alerts_file = Path('logs/ids_alerts.json')
    
    if alerts_file.exists():
        try:
            with open(alerts_file, 'r') as f:
                alerts = json.load(f)
            
            # Return last 10 alerts
            return jsonify(alerts[-10:])
        except:
            return jsonify([])
    
    return jsonify([])

def get_security_metrics():
    """Get security metrics from logs"""
    metrics = {
        'total_requests': 0,
        'failed_logins': 0,
        'active_alerts': 0,
        'blocked_ips': 0,
        'threats_detected': 0
    }
    
    # Count alerts
    alerts_file = Path('logs/ids_alerts.json')
    if alerts_file.exists():
        try:
            with open(alerts_file, 'r') as f:
                alerts = json.load(f)
                metrics['active_alerts'] = len(alerts)
                metrics['threats_detected'] = len(alerts)
                
                # Count failed logins
                metrics['failed_logins'] = sum(
                    1 for alert in alerts 
                    if alert.get('type') == 'brute_force'
                )
        except:
            pass
    
    # Count blocked IPs
    blocked_ips_file = Path('logs/blocked_ips.log')
    if blocked_ips_file.exists():
        try:
            with open(blocked_ips_file, 'r') as f:
                metrics['blocked_ips'] = len(f.readlines())
        except:
            pass
    
    # Count total requests from access log
    access_log = Path('logs/access.log')
    if access_log.exists():
        try:
            with open(access_log, 'r') as f:
                metrics['total_requests'] = len(f.readlines())
        except:
            pass
    
    return metrics

def main():
    """Main function"""
    print("=" * 80)
    print("  SECURITY MONITORING DASHBOARD")
    print("=" * 80)
    print("\n🚀 Starting dashboard server...")
    print("\n📊 Access the dashboard at: http://localhost:5000")
    print("\n⚠️  Press Ctrl+C to stop the server")
    print("=" * 80 + "\n")
    
    # Create logs directory if it doesn't exist
    Path('logs').mkdir(exist_ok=True)
    
    # Run Flask app
    app.run(debug=False, host='0.0.0.0', port=5000)

if __name__ == '__main__':
    main()
