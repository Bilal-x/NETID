import os
import subprocess
import platform
from datetime import datetime

# Store blocked IPs for tracking
blocked_ips = []
prevention_log = []

def block_ip_windows(ip_address):
    """Block an IP address using Windows Firewall"""
    try:
        rule_name = f"NETID_Block_{ip_address.replace('.', '_')}"
        cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip_address}'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            blocked_ips.append(ip_address)
            log_prevention_action(f"Blocked IP: {ip_address} (Windows Firewall)")
            return True
        else:
            log_prevention_action(f"Failed to block IP: {ip_address} - {result.stderr}")
            return False
    except Exception as e:
        log_prevention_action(f"Error blocking IP {ip_address}: {str(e)}")
        return False

def block_ip_linux(ip_address):
    """Block an IP address using iptables (Linux)"""
    try:
        cmd = f"sudo iptables -A INPUT -s {ip_address} -j DROP"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            blocked_ips.append(ip_address)
            log_prevention_action(f"Blocked IP: {ip_address} (iptables)")
            return True
        else:
            log_prevention_action(f"Failed to block IP: {ip_address} - {result.stderr}")
            return False
    except Exception as e:
        log_prevention_action(f"Error blocking IP {ip_address}: {str(e)}")
        return False

def log_prevention_action(message):
    """Log prevention actions with timestamp"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {message}"
    prevention_log.append(log_entry)
    print(f"PREVENTION: {log_entry}")

def block_suspicious_ip(packet):
    """Main function to block suspicious IP from packet"""
    try:
        # Extract source IP from packet
        src_ip = None
        if hasattr(packet, 'src'):
            src_ip = packet.src
        elif hasattr(packet, 'payload') and hasattr(packet.payload, 'src'):
            src_ip = packet.payload.src
        
        if src_ip and src_ip not in blocked_ips:
            # Determine OS and use appropriate blocking method
            system = platform.system().lower()
            
            if system == "windows":
                success = block_ip_windows(src_ip)
            elif system == "linux":
                success = block_ip_linux(src_ip)
            else:
                log_prevention_action(f"Unsupported OS: {system}. Cannot block {src_ip}")
                return False
                
            if success:
                return True
        else:
            log_prevention_action(f"IP {src_ip} already blocked or invalid")
            return False
            
    except Exception as e:
        log_prevention_action(f"Error in block_suspicious_ip: {str(e)}")
        return False

def get_prevention_logs():
    """Return recent prevention logs for UI display"""
    return prevention_log[-10:]  # Last 10 entries

def get_blocked_ips():
    """Return list of blocked IPs"""
    return blocked_ips.copy()

def simulate_block_action(packet_info):
    """Simulate blocking action for demo purposes"""
    fake_ip = "192.168.1.100"  # Simulated malicious IP
    log_entry = f"SIMULATED BLOCK: Malicious packet detected from {fake_ip}"
    prevention_log.append(log_entry)
    blocked_ips.append(fake_ip)
    return True
