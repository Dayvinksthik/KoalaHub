import bcrypt
import hashlib
import secrets
from typing import Tuple
import base64

class PasswordManager:
    @staticmethod
    def hash_password(password: str) -> Tuple[str, str]:
        """Hash password with bcrypt and return hash + salt"""
        salt = bcrypt.gensalt(rounds=12)
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8'), salt.decode('utf-8')
    
    @staticmethod
    def verify_password(password: str, hashed_password: str) -> bool:
        """Verify password against hash"""
        try:
            return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
        except:
            return False
    
    @staticmethod
    def generate_secure_token(length: int = 32) -> str:
        """Generate cryptographically secure token"""
        return secrets.token_urlsafe(length)
    
    @staticmethod
    def generate_api_key() -> str:
        """Generate API key for programmatic access"""
        return f"sk_{secrets.token_hex(16)}"
    
    @staticmethod
    def hash_ip(ip_address: str) -> str:
        """Hash IP address for privacy (one-way hash)"""
        return hashlib.sha256(f"{ip_address}_salt".encode()).hexdigest()[:32]