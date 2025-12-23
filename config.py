import os
import secrets
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Discord
    DISCORD_TOKEN = os.getenv('DISCORD_TOKEN', '')
    GUILD_ID = int(os.getenv('DISCORD_GUILD_ID', '0'))
    CLIENT_ID = os.getenv('CLIENT_ID', '')
    CLIENT_SECRET = os.getenv('CLIENT_SECRET', '')
    REDIRECT_URI = os.getenv('REDIRECT_URI', '')
    
    # Webhooks (NEW: Separate webhooks for different purposes)
    WEBHOOK_URL = os.getenv('DISCORD_WEBHOOK_URL', '')
    LOGS_WEBHOOK = os.getenv('DISCORD_LOGS_WEBHOOK', '')
    ALERTS_WEBHOOK = os.getenv('DISCORD_ALERTS_WEBHOOK', '')
    BACKUP_WEBHOOK = os.getenv('DISCORD_BACKUP_WEBHOOK', '')
    
    # MongoDB
    MONGODB_URI = os.getenv('MONGODB_URI', 'mongodb://localhost:27017/')
    DATABASE_NAME = os.getenv('DATABASE_NAME', 'discord_verification')
    
    # Flask
    SECRET_KEY = os.getenv('SECRET_KEY', secrets.token_hex(32))  # Auto-generate if missing
    FLASK_ENV = os.getenv('FLASK_ENV', 'production')
    PORT = int(os.getenv('PORT', '10000'))
    
    # Admin (NEW: Hashed passwords)
    ADMIN_USERNAME = os.getenv('ADMIN_USERNAME', 'Day')
    ADMIN_PASSWORD_HASH = os.getenv('ADMIN_PASSWORD_HASH', '')  # Store hash, not plain text
    
    # Verification Role
    VERIFIED_ROLE_NAME = "Verified"
    VERIFIED_ROLE_ID = os.getenv('VERIFIED_ROLE_ID', '')
    VERIFIED_ROLE_COLOR = 0x00ff00
    
    # API Services
    IPINFO_TOKEN = os.getenv('IPINFO_TOKEN', '')
    VPN_API_KEY = os.getenv('VPN_API_KEY', '')
    
    # Website URL
    WEBSITE_URL = os.getenv('WEBSITE_URL', '')
    VERIFY_URL = f"{WEBSITE_URL}/verify" if WEBSITE_URL else ""
    
    # Security Settings (NEW)
    RATE_LIMIT_PER_MINUTE = int(os.getenv('RATE_LIMIT_PER_MINUTE', '5'))
    MAX_LOGIN_ATTEMPTS = int(os.getenv('MAX_LOGIN_ATTEMPTS', '5'))
    SESSION_TIMEOUT_MINUTES = int(os.getenv('SESSION_TIMEOUT_MINUTES', '15'))
    REQUIRE_2FA = os.getenv('REQUIRE_2FA', 'false').lower() == 'true'
    
    # Monitoring (NEW)
    HEALTH_CHECK_INTERVAL = int(os.getenv('HEALTH_CHECK_INTERVAL', '300'))
    
    # Backup Settings (NEW)
    BACKUP_INTERVAL_HOURS = int(os.getenv('BACKUP_INTERVAL_HOURS', '6'))
    BACKUP_RETENTION_DAYS = int(os.getenv('BACKUP_RETENTION_DAYS', '7'))

    # Validation
    if not DISCORD_TOKEN:
        print("⚠️  WARNING: DISCORD_TOKEN not set. Discord bot will not start.")
    
    if not MONGODB_URI:
        raise ValueError("❌ ERROR: MONGODB_URI is required!")

    if not WEBSITE_URL:
        # Auto-detect for Render
        port = int(os.getenv('PORT', '10000'))
        WEBSITE_URL = f"https://koalahub.onrender.com"
        print(f"🌐 Auto-set WEBSITE_URL to: {WEBSITE_URL}")