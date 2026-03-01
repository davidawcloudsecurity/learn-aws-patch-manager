#!/usr/bin/env python3
"""
External Lighthouse - Visible from anywhere, but only shows capture data
"""

import http.server
import json
import socket
import os
import time
from datetime import datetime

class ExternalLighthouseHandler(http.server.BaseHTTPRequestHandler):
    """Handles requests from anywhere in the world"""
    
    def do_GET(self):
        """Handle GET requests from external curl"""
        
        if self.path == '/status':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            
            response = {
                'lighthouse': 'ACTIVE',
                'state': self.server.state,
                'last_capture': self.server.capture_time,
                'message': 'I am the lighthouse - visible from sea'
            }
            self.wfile.write(json.dumps(response).encode())
        
        elif self.path == '/capture':
            if self.server.capture_data:
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(self.server.capture_data).encode())
            else:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b'{"message": "No capture data"}')
        
        elif self.path == '/health':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            
            response = {
                'ssm_agent': self.check_ssm(),
                'cloudwatch_agent': self.check_cw(),
                'timestamp': datetime.now().isoformat()
            }
            self.wfile.write(json.dumps(response).encode())
        
        else:
            self.send_response(404)
            self.end_headers()
    
    def check_ssm(self):
        """Check SSM agent"""
        try:
            result = os.system('systemctl is-active snap.amazon-ssm-agent.amazon-ssm-agent.service > /dev/null 2>&1')
            return result == 0
        except:
            return False
    
    def check_cw(self):
        """Check CloudWatch agent"""
        try:
            result = os.system('systemctl is-active amazon-cloudwatch-agent > /dev/null 2>&1')
            return result == 0
        except:
            return False

class ExternalLighthouseServer(http.server.HTTPServer):
    """Server that binds to ALL interfaces - visible from outside"""
    
    def __init__(self, port=8080):
        # CRITICAL: Bind to 0.0.0.0 to be visible from outside
        super().__init__(('0.0.0.0', port), ExternalLighthouseHandler)
        self.state = 'WATCHING'
        self.capture_data = None
        self.capture_time = None
        
        # Get public info
        self.public_ip = self.get_public_ip()
        print(f"🌊 LIGHTHOUSE ACTIVATED")
        print(f"📍 Visible at: http://{self.public_ip}:{port}")
        print(f"📡 Ships can see me from anywhere")
    
    def get_public_ip(self):
        """Try to get public IP"""
        try:
            # Try IMDS
            import requests
            token = requests.put('http://169.254.169.254/latest/api/token',
                               headers={'X-aws-ec2-metadata-token-ttl-seconds': '60'},
                               timeout=2)
            if token.status_code == 200:
                resp = requests.get('http://169.254.169.254/latest/meta-data/public-ipv4',
                                  headers={'X-aws-ec2-metadata-token': token.text},
                                  timeout=2)
                return resp.text if resp.status_code == 200 else 'unknown'
        except:
            pass
        return 'unknown'
    
    def capture_failure(self, failure_data):
        """Store failure data when detected"""
        self.state = 'FAILURE_DETECTED'
        self.capture_data = failure_data
        self.capture_time = datetime.now().isoformat()
        print(f"⚠️  Failure captured at {self.capture_time}")
        print(f"🌊 Lighthouse now showing: {self.state}")

def monitor_agents(server):
    """Background thread monitoring agents"""
    consecutive_failures = 0
    
    while True:
        try:
            ssm_running = os.system('systemctl is-active snap.amazon-ssm-agent.amazon-ssm-agent.service > /dev/null 2>&1') == 0
            cw_running = os.system('systemctl is-active amazon-cloudwatch-agent > /dev/null 2>&1') == 0
            
            if not ssm_running or not cw_running:
                consecutive_failures += 1
                
                if consecutive_failures >= 3:
                    # Capture failure
                    logs = get_last_logs(50)
                    failure = {
                        'timestamp': datetime.now().isoformat(),
                        'ssm_agent': 'DOWN' if not ssm_running else 'UP',
                        'cloudwatch_agent': 'DOWN' if not cw_running else 'UP',
                        'logs': logs,
                        'failure_count': consecutive_failures
                    }
                    server.capture_failure(failure)
                    
                    # Cooldown
                    time.sleep(300)
                    consecutive_failures = 0
            else:
                consecutive_failures = 0
                if server.state != 'WATCHING':
                    server.state = 'WATCHING'
            
            time.sleep(30)
            
        except Exception as e:
            print(f"Monitor error: {e}")
            time.sleep(30)

def get_last_logs(lines=50):
    """Get last N lines from both SSM logs and error logs"""
    logs = {}
    
    # SSM agent main log
    try:
        result = os.popen(f'tail -n {lines} /var/log/amazon/ssm/amazon-ssm-agent.log 2>/dev/null').read()
        logs['ssm_agent_log'] = result.split('\n')
    except:
        logs['ssm_agent_log'] = ['SSM agent log not found']
    
    # SSM agent error log
    try:
        result = os.popen(f'tail -n {lines} /var/log/amazon/ssm/errors.log 2>/dev/null').read()
        logs['ssm_error_log'] = result.split('\n')
    except:
        logs['ssm_error_log'] = ['SSM error log not found']
    
    # CloudWatch agent log
    try:
        result = os.popen(f'tail -n {lines} /opt/aws/amazon-cloudwatch-agent/logs/amazon-cloudwatch-agent.log 2>/dev/null').read()
        logs['cloudwatch_log'] = result.split('\n')
    except:
        logs['cloudwatch_log'] = ['CloudWatch log not found']
    
    # System log for agent-related entries
    try:
        result = os.popen(f'journalctl -n {lines} -u snap.amazon-ssm-agent.amazon-ssm-agent.service --no-pager 2>/dev/null').read()
        logs['systemd_log'] = result.split('\n')
    except:
        logs['systemd_log'] = ['Systemd log not found']
    
    return logs

def run_lighthouse():
    """Start the externally visible lighthouse"""
    import threading
    import time
    
    server = ExternalLighthouseServer(8080)
    
    # Start monitor thread
    monitor = threading.Thread(target=monitor_agents, args=(server,))
    monitor.daemon = True
    monitor.start()
    
    print("\n" + "="*50)
    print("🚨 IMPORTANT: Security Group must allow port 8080")
    print("="*50)
    print("\nTo check from your laptop:")
    print(f"  curl http://{server.public_ip}:8080/status")
    print(f"  curl http://{server.public_ip}:8080/health")
    print(f"  curl http://{server.public_ip}:8080/capture")
    print("\nPress Ctrl+C to stop\n")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n🌊 Lighthouse shutting down...")
        server.shutdown()

if __name__ == '__main__':
    run_lighthouse()
