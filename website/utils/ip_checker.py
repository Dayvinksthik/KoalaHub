import requests
import socket
from ipaddress import ip_address, IPv4Address
import logging
from config import Config

class IPChecker:
    def __init__(self):
        self.vpn_services = [
            'vpn', 'proxy', 'tor', 'anonymous', 'shield', 'hide',
            'expressvpn', 'nordvpn', 'surfshark', 'cyberghost', 'private'
        ]
        
    def get_client_ip(self, request):
        """Extract client IP from request"""
        if request.headers.get('X-Forwarded-For'):
            ip = request.headers['X-Forwarded-For'].split(',')[0].strip()
        elif request.headers.get('X-Real-IP'):
            ip = request.headers['X-Real-IP']
        else:
            ip = request.remote_addr
            
        return ip.split(':')[0]  # Remove port if present
        
    def check_vpn_free_api(self, ip):
        """Check if IP is VPN using free APIs"""
        try:
            # Try ipapi.co
            response = requests.get(f'https://ipapi.co/{ip}/json/', timeout=5)
            if response.status_code == 200:
                data = response.json()
                # Check for VPN/Proxy indicators
                if data.get('proxy') or data.get('vpn') or data.get('tor'):
                    return True
                    
            # Try ipqualityscore (if API key provided)
            if Config.VPN_API_KEY:
                response = requests.get(
                    f'https://ipqualityscore.com/api/json/ip/{Config.VPN_API_KEY}/{ip}',
                    params={'strictness': 1},
                    timeout=5
                )
                if response.status_code == 200:
                    data = response.json()
                    if data.get('vpn') or data.get('proxy') or data.get('tor'):
                        return True
                        
        except Exception as e:
            logging.error(f"VPN check failed: {e}")
            
        return False
        
    def is_private_ip(self, ip):
        """Check if IP is private/reserved"""
        try:
            ip_obj = ip_address(ip)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        except ValueError:
            return True
            
    def check_ip_reputation(self, ip):
        """Basic IP reputation check"""
        if self.is_private_ip(ip):
            return {"is_vpn": False, "is_private": True, "risk_level": "low"}
            
        is_vpn = self.check_vpn_free_api(ip)
        
        # Basic risk assessment
        risk_level = "high" if is_vpn else "medium"
        
        return {
            "ip": ip,
            "is_vpn": is_vpn,
            "is_private": False,
            "risk_level": risk_level,
            "recommendation": "block" if is_vpn else "allow"
        }