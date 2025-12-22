import requests
import time
from datetime import datetime
import json
from utils.logger import logger
from config import Config

class HealthMonitor:
    def __init__(self, website_url=None, webhook_url=None):
        self.website_url = website_url or Config.WEBSITE_URL
        self.webhook_url = webhook_url or Config.WEBHOOK_URL
        self.last_status = {}
        
    def check_website(self):
        """Check if website is responding"""
        try:
            start_time = time.time()
            response = requests.get(f"{self.website_url}/health", timeout=10)
            response_time = (time.time() - start_time) * 1000  # Convert to ms
            
            if response.status_code == 200:
                return {
                    'status': 'UP',
                    'response_time': f"{response_time:.2f}ms",
                    'status_code': response.status_code
                }
            else:
                return {
                    'status': 'DOWN',
                    'response_time': f"{response_time:.2f}ms",
                    'status_code': response.status_code,
                    'error': f"HTTP {response.status_code}"
                }
                
        except requests.exceptions.Timeout:
            return {
                'status': 'DOWN',
                'response_time': 'Timeout',
                'error': 'Request timeout'
            }
        except requests.exceptions.ConnectionError:
            return {
                'status': 'DOWN',
                'response_time': 'N/A',
                'error': 'Connection refused'
            }
        except Exception as e:
            return {
                'status': 'DOWN',
                'response_time': 'N/A',
                'error': str(e)
            }
    
    def check_database(self):
        """Check if database is connected"""
        try:
            from pymongo import MongoClient
            
            start_time = time.time()
            client = MongoClient(Config.MONGODB_URI, serverSelectionTimeoutMS=5000)
            client.server_info()  # This will raise exception if not connected
            response_time = (time.time() - start_time) * 1000
            
            # Test a simple query
            db = client[Config.DATABASE_NAME]
            db.users.count_documents({})
            
            return {
                'status': 'UP',
                'response_time': f"{response_time:.2f}ms",
                'connected': True
            }
            
        except Exception as e:
            return {
                'status': 'DOWN',
                'response_time': 'N/A',
                'error': str(e)
            }
    
    def get_system_stats(self):
        """Get system statistics"""
        try:
            import psutil
            import platform
            
            stats = {
                'cpu_percent': psutil.cpu_percent(interval=1),
                'memory_percent': psutil.virtual_memory().percent,
                'disk_percent': psutil.disk_usage('/').percent,
                'python_version': platform.python_version(),
                'system': platform.system(),
                'processor': platform.processor(),
                'timestamp': datetime.now().isoformat()
            }
            return stats
            
        except ImportError:
            return {
                'cpu_percent': 'N/A',
                'memory_percent': 'N/A',
                'python_version': platform.python_version(),
                'timestamp': datetime.now().isoformat()
            }
    
    def send_alert(self, component, status, details=None):
        """Send alert to Discord webhook"""
        if not self.webhook_url:
            return
            
        color = 0xff0000 if status == "DOWN" else 0x00ff00
        title = f"🚨 {component} {status}" if status == "DOWN" else f"✅ {component} {status}"
        
        embed = {
            "title": title,
            "color": color,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        if details:
            description = f"**Component:** {component}\n**Status:** {status}\n"
            for key, value in details.items():
                description += f"**{key}:** {value}\n"
            embed["description"] = description
        
        try:
            response = requests.post(self.webhook_url, json={"embeds": [embed]}, timeout=5)
            return response.status_code in [200, 204]
        except Exception as e:
            logger.error(f"Failed to send alert: {e}")
            return False
    
    def run_check(self):
        """Run all health checks"""
        logger.info("🔍 Running health checks...")
        
        checks = {
            'website': self.check_website(),
            'database': self.check_database(),
            'system': self.get_system_stats()
        }
        
        # Check for status changes
        for component, result in checks.items():
            if component in self.last_status:
                old_status = self.last_status[component].get('status')
                new_status = result.get('status')
                
                if old_status != new_status:
                    logger.warning(f"⚠️  {component} status changed: {old_status} -> {new_status}")
                    self.send_alert(component, new_status, result)
        
        self.last_status = checks
        
        # Log results
        logger.info(f"🌐 Website: {checks['website']['status']} ({checks['website'].get('response_time', 'N/A')})")
        logger.info(f"🗄️  Database: {checks['database']['status']} ({checks['database'].get('response_time', 'N/A')})")
        logger.info(f"💻 System: CPU {checks['system'].get('cpu_percent', 'N/A')}%, Memory {checks['system'].get('memory_percent', 'N/A')}%")
        
        return checks