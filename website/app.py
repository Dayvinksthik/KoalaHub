"""
Discord Verification System - Website Application
Complete implementation with all security, monitoring, and performance features
"""

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, g, abort
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
import requests
import json
from datetime import datetime, timedelta
import secrets
import os
import sys
import urllib.parse
import time
import bcrypt
import hashlib
import base64
from functools import wraps
import qrcode
import io
import pyotp
from bson import ObjectId

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import Config
from utils.logger import logger
from utils.password import PasswordManager
from utils.rate_limiter import rate_limiter
from database.connection import db_manager
from utils.backup import backup_database
import asyncio

def create_app():
    """Create and configure Flask application with all security features"""
    app = Flask(__name__, template_folder='templates', static_folder='static')
    
    # ============ SECURITY CONFIGURATION ============
    app.config['SECRET_KEY'] = Config.SECRET_KEY
    app.config['SESSION_TYPE'] = 'filesystem'
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=Config.SESSION_TIMEOUT_MINUTES)
    app.config['SESSION_REFRESH_EACH_REQUEST'] = True
    app.config['SESSION_COOKIE_SECURE'] = True  # Only send over HTTPS
    app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JS access
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection
    
    # Security headers with Talisman
    csp = {
        'default-src': ['\'self\'', 'https:', 'data:', 'blob:'],
        'style-src': ['\'self\'', '\'unsafe-inline\'', 'https://cdnjs.cloudflare.com'],
        'script-src': ['\'self\'', '\'unsafe-inline\'', 'https://cdnjs.cloudflare.com', 'https://www.google.com'],
        'font-src': ['\'self\'', 'https://cdnjs.cloudflare.com', 'data:'],
        'img-src': ['\'self\'', 'data:', 'blob:', 'https:']
    }
    
    Talisman(app, 
             force_https=True,
             session_cookie_secure=True,
             content_security_policy=csp,
             strict_transport_security=True,
             frame_options='DENY',
             x_xss_protection=True,
             x_content_type_options=True)
    
    CORS(app, resources={
        r"/api/*": {
            "origins": ["https://koalahub.onrender.com", "http://localhost:10000"],
            "methods": ["GET", "POST", "OPTIONS"],
            "allow_headers": ["Content-Type", "Authorization"]
        }
    })
    
    # Rate limiting
    limiter = Limiter(
        get_remote_address,
        app=app,
        storage_uri="memory://",
        strategy="fixed-window",
        default_limits=["200 per day", "50 per hour"]
    )
    
    # ============ SECURITY UTILITIES ============
    
    def get_client_ip():
        """Get client IP address with security"""
        if request.headers.get('CF-Connecting-IP'):
            ip = request.headers['CF-Connecting-IP']
        elif request.headers.get('X-Forwarded-For'):
            ip = request.headers['X-Forwarded-For'].split(',')[0].strip()
        elif request.headers.get('X-Real-IP'):
            ip = request.headers['X-Real-IP']
        else:
            ip = request.remote_addr
        
        # Security: Sanitize IP
        if ':' in ip and ip.count(':') == 1:
            ip = ip.split(':')[0]
        
        if ip.startswith('::ffff:'):
            ip = ip[7:]
        
        return ip
    
    def hash_user_agent(ua):
        """Hash user agent for privacy"""
        return hashlib.sha256(ua.encode()).hexdigest()[:16]
    
    def check_vpn_multiple_providers(ip):
        """Check VPN using multiple providers with fallback"""
        providers = [
            # Provider 1: IPHub (if key available)
            lambda: check_vpn_iphub(ip),
            # Provider 2: ProxyCheck
            lambda: check_vpn_proxycheck(ip),
            # Provider 3: IPAPI
            lambda: check_vpn_ipapi(ip),
            # Provider 4: Custom rules
            lambda: check_vpn_custom_rules(ip)
        ]
        
        for provider in providers:
            try:
                result = provider()
                if result['is_vpn']:
                    return result
            except:
                continue
        
        return {'is_vpn': False, 'confidence': 0, 'provider': 'fallback'}
    
    def check_vpn_iphub(ip):
        """Check VPN using IPHub"""
        if not Config.IPHUB_KEY:
            raise Exception("IPHub key not configured")
        
        try:
            response = requests.get(
                f'http://v2.api.iphub.info/ip/{ip}',
                headers={'X-Key': Config.IPHUB_KEY},
                timeout=3
            )
            if response.status_code == 200:
                data = response.json()
                return {
                    'is_vpn': data.get('block') == 1,
                    'confidence': 90 if data.get('block') == 1 else 10,
                    'provider': 'iphub'
                }
        except:
            pass
        raise Exception("IPHub check failed")
    
    def check_vpn_proxycheck(ip):
        """Check VPN using ProxyCheck.io"""
        try:
            response = requests.get(
                f'https://proxycheck.io/v2/{ip}',
                params={'vpn': 1, 'asn': 1},
                timeout=3
            )
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'ok':
                    ip_info = data.get(ip, {})
                    return {
                        'is_vpn': ip_info.get('proxy') == 'yes',
                        'confidence': 95 if ip_info.get('proxy') == 'yes' else 5,
                        'provider': 'proxycheck'
                    }
        except:
            pass
        raise Exception("ProxyCheck failed")
    
    def check_vpn_ipapi(ip):
        """Check VPN using IP-API.com"""
        try:
            response = requests.get(
                f'http://ip-api.com/json/{ip}',
                params={'fields': '66842623'},
                timeout=3
            )
            if response.status_code == 200:
                data = response.json()
                # Check for hosting/datacenter
                is_hosting = data.get('hosting', False) or data.get('proxy', False)
                isp = data.get('isp', '').lower()
                hosting_keywords = ['hosting', 'datacenter', 'server', 'cloud', 'vps']
                is_vpn = is_hosting or any(keyword in isp for keyword in hosting_keywords)
                
                return {
                    'is_vpn': is_vpn,
                    'confidence': 80 if is_vpn else 20,
                    'provider': 'ipapi',
                    'isp': isp
                }
        except:
            pass
        raise Exception("IP-API failed")
    
    def check_vpn_custom_rules(ip):
        """Custom VPN detection rules"""
        # Check for known VPN IP ranges
        vpn_ranges = [
            '104.16.0.0/12',  # Cloudflare
            '192.64.147.0/24', # Common VPN range
        ]
        
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            for range_str in vpn_ranges:
                if ip_obj in ipaddress.ip_network(range_str):
                    return {
                        'is_vpn': True,
                        'confidence': 70,
                        'provider': 'custom_rules'
                    }
        except:
            pass
        
        # Check for known VPN patterns
        if any(pattern in ip for pattern in ['vpn', 'proxy', 'tor', 'anonym']):
            return {
                'is_vpn': True,
                'confidence': 60,
                'provider': 'custom_patterns'
            }
        
        return {
            'is_vpn': False,
            'confidence': 30,
            'provider': 'custom_fallback'
        }
    
    def send_discord_webhook(title, description, color=0x00ff00, webhook_url=None, thumbnail=None):
        """Webhook sending with retries and formatting"""
        url = webhook_url or Config.WEBHOOK_URL
        if not url:
            return False
        
        embed = {
            "title": title[:256],
            "description": description[:4096],
            "color": color,
            "timestamp": datetime.utcnow().isoformat(),
            "footer": {
                "text": "Security System v2.0"
            },
            "author": {
                "name": "Verification System",
                "icon_url": "https://cdn.discordapp.com/attachments/1200387647512776704/1200387721230815232/koala.png"
            }
        }
        
        if thumbnail:
            embed["thumbnail"] = {"url": thumbnail}
        
        # Add fields for structured data
        if "**" in description:
            lines = description.split('\n')
            embed["fields"] = []
            for line in lines:
                if ":**" in line:
                    parts = line.split(":**", 1)
                    if len(parts) == 2:
                        embed["fields"].append({
                            "name": parts[0].replace("**", "") + ":",
                            "value": parts[1].strip(),
                            "inline": True
                        })
        
        payload = {
            "embeds": [embed],
            "username": "Security Bot",
            "avatar_url": "https://cdn.discordapp.com/attachments/1200387647512776704/1200387721230815232/koala.png"
        }
        
        # Retry logic
        for attempt in range(3):
            try:
                response = requests.post(url, json=payload, timeout=5)
                if response.status_code in [200, 204]:
                    return True
                elif response.status_code == 429:  # Rate limited
                    retry_after = int(response.headers.get('Retry-After', 1))
                    time.sleep(retry_after)
                    continue
            except Exception as e:
                logger.warning(f"Webhook attempt {attempt + 1} failed: {e}")
                time.sleep(1)
        
        logger.error(f"Webhook failed after 3 attempts: {title}")
        return False
    
    def log_security_event(event_type, user_id=None, ip=None, details="", level="INFO"):
        """Comprehensive security event logging"""
        ip_addr = ip or get_client_ip()
        timestamp = datetime.utcnow()
        
        event = {
            "type": event_type,
            "user_id": user_id,
            "ip_address": ip_addr,
            "hashed_ip": PasswordManager.hash_ip(ip_addr),
            "user_agent": hash_user_agent(request.headers.get('User-Agent', 'Unknown')),
            "details": details[:1000],
            "timestamp": timestamp,
            "level": level,
            "endpoint": request.endpoint,
            "method": request.method
        }
        
        # Store in database
        if db_manager.db:
            try:
                db_manager.db.security_logs.insert_one(event)
                
                # Auto-clean old logs (keep 30 days)
                cutoff = timestamp - timedelta(days=30)
                db_manager.db.security_logs.delete_many({"timestamp": {"$lt": cutoff}})
            except Exception as e:
                logger.error(f"Failed to log security event: {e}")
        
        # Send to webhook for important events
        if level in ["WARNING", "ERROR"]:
            color = 0xff9900 if level == "WARNING" else 0xff0000
            send_discord_webhook(
                f"🔐 {event_type}",
                f"**Level:** {level}\n**IP:** ||{ip_addr}||\n**Details:** {details}\n**Time:** {timestamp.strftime('%H:%M:%S')}",
                color,
                Config.ALERTS_WEBHOOK
            )
        
        # Local logging
        log_msg = f"SECURITY {level}: {event_type} - IP: {ip_addr} - Details: {details}"
        if level == "ERROR":
            logger.error(log_msg)
        elif level == "WARNING":
            logger.warning(log_msg)
        else:
            logger.info(log_msg)
    
    def create_temp_ban(ip_address, reason, duration_minutes=60):
        """Create temporary ban"""
        expires_at = datetime.utcnow() + timedelta(minutes=duration_minutes)
        
        ban_data = {
            "ip_address": ip_address,
            "reason": reason,
            "expires_at": expires_at,
            "created_at": datetime.utcnow(),
            "type": "temporary"
        }
        
        if db_manager.db:
            db_manager.db.temp_bans.update_one(
                {"ip_address": ip_address},
                {"$set": ban_data},
                upsert=True
            )
        
        return expires_at
    
    def is_temp_banned(ip_address):
        """Check if IP is temporarily banned"""
        if not db_manager.db:
            return False
        
        ban = db_manager.db.temp_bans.find_one({
            "ip_address": ip_address,
            "expires_at": {"$gt": datetime.utcnow()}
        })
        
        return ban is not None
    
    # ============ DECORATORS & MIDDLEWARE ============
    
    def admin_required(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not session.get('admin_logged_in'):
                log_security_event("UNAUTHORIZED_ADMIN_ACCESS", ip=get_client_ip())
                return redirect(url_for('admin_login'))
            
            # Check session expiration
            login_time = session.get('login_time')
            if login_time:
                login_dt = datetime.fromisoformat(login_time)
                if datetime.utcnow() - login_dt > timedelta(minutes=Config.SESSION_TIMEOUT_MINUTES):
                    session.clear()
                    log_security_event("ADMIN_SESSION_EXPIRED", ip=get_client_ip())
                    return redirect(url_for('admin_login'))
            
            # Check IP change (session hijacking detection)
            session_ip = session.get('admin_ip')
            current_ip = get_client_ip()
            if session_ip and session_ip != current_ip:
                log_security_event("ADMIN_SESSION_HIJACK_ATTEMPT", 
                                 ip=current_ip, 
                                 details=f"Original IP: {session_ip}, Current IP: {current_ip}",
                                 level="ERROR")
                session.clear()
                return redirect(url_for('admin_login'))
            
            return f(*args, **kwargs)
        return decorated_function
    
    def require_2fa(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if Config.REQUIRE_2FA and not session.get('admin_2fa_verified'):
                return redirect(url_for('admin_2fa_verify'))
            return f(*args, **kwargs)
        return decorated_function
    
    def rate_limit_by_ip(limit="5 per minute"):
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                client_ip = get_client_ip()
                
                # Check rate limit
                result = rate_limiter.check_rate_limit(
                    client_ip, 
                    f.__name__, 
                    limit=int(limit.split()[0]), 
                    window=60
                )
                
                if not result['allowed']:
                    return jsonify({
                        "success": False,
                        "error": "Rate limit exceeded. Please try again later.",
                        "retry_after": result['retry_after']
                    }), 429
                
                return f(*args, **kwargs)
            return decorated_function
        return decorator
    
    def check_maintenance_mode(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Check maintenance mode in database
            if db_manager.db:
                settings = db_manager.db.settings.find_one({"key": "maintenance_mode"})
                if settings and settings.get('value') is True and not session.get('admin_logged_in'):
                    return render_template('maintenance.html'), 503
            return f(*args, **kwargs)
        return decorated_function
    
    # ============ DATABASE INITIALIZATION ============
    
    @app.before_request
    def before_request():
        """Initialize request context"""
        g.start_time = time.time()
        g.client_ip = get_client_ip()
        
        # Check for banned IP
        if is_temp_banned(g.client_ip):
            abort(403, description="Temporary IP ban in effect")
    
    @app.after_request
    def after_request(response):
        """Log request details and add security headers"""
        # Calculate request time
        if hasattr(g, 'start_time'):
            duration = time.time() - g.start_time
            if duration > 1.0:  # Log slow requests
                logger.warning(f"Slow request: {request.path} took {duration:.2f}s")
        
        # Add security headers
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        # Add HSTS header for HTTPS
        if request.is_secure:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        
        return response
    
    # ============ PUBLIC ROUTES ============
    
    @app.route('/')
    @check_maintenance_mode
    def home():
        """Home page with system status"""
        system_status = {
            "online": True,
            "verifications_today": get_today_verifications(),
            "total_users": get_total_users(),
            "uptime": get_system_uptime()
        }
        
        return render_template('index.html', 
                             status=system_status,
                             maintenance=False)
    
    @app.route('/verify')
    @check_maintenance_mode
    @limiter.limit("10 per minute")
    def verify_page():
        """Verification page with security"""
        client_ip = get_client_ip()
        
        # Check for temporary ban
        if is_temp_banned(client_ip):
            ban_info = db_manager.db.temp_bans.find_one({"ip_address": client_ip})
            return render_template('blocked.html',
                                 reason=ban_info.get('reason', 'Security violation'),
                                 expires=ban_info.get('expires_at'))
        
        # Get Discord OAuth state
        discord_user = session.get('discord_user')
        
        # Generate OAuth2 state for CSRF protection
        state_token = secrets.token_urlsafe(16)
        session['oauth_state'] = state_token
        
        return render_template('verify.html',
                             discord_user=discord_user,
                             client_id=Config.CLIENT_ID,
                             redirect_uri=urllib.parse.quote(Config.REDIRECT_URI),
                             state=state_token)
    
    @app.route('/auth/discord')
    @limiter.limit("5 per minute")
    def auth_discord():
        """Discord OAuth2 authorization with state verification"""
        state = request.args.get('state', '')
        stored_state = session.get('oauth_state')
        
        if not stored_state or state != stored_state:
            log_security_event("OAUTH_STATE_MISMATCH", ip=get_client_ip())
            return redirect(url_for('verify_page'))
        
        discord_auth_url = (
            f"https://discord.com/api/oauth2/authorize"
            f"?client_id={Config.CLIENT_ID}"
            f"&redirect_uri={urllib.parse.quote(Config.REDIRECT_URI)}"
            f"&response_type=code"
            f"&scope=identify"
            f"&state={state}"
            f"&prompt=none"
        )
        return redirect(discord_auth_url)
    
    @app.route('/auth/callback')
    @limiter.limit("10 per minute")
    def auth_callback():
        """Discord OAuth2 callback with security"""
        code = request.args.get('code')
        state = request.args.get('state')
        error = request.args.get('error')
        
        if error:
            log_security_event("DISCORD_OAUTH_ERROR", ip=get_client_ip(), details=error)
            return redirect(url_for('verify_page'))
        
        # Verify state
        stored_state = session.get('oauth_state')
        if not stored_state or state != stored_state:
            log_security_event("OAUTH_STATE_MISMATCH", ip=get_client_ip())
            return redirect(url_for('verify_page'))
        
        if not code:
            log_security_event("OAUTH_NO_CODE", ip=get_client_ip())
            return redirect(url_for('verify_page'))
        
        # Exchange code for token
        token_data = exchange_code(code)
        if not token_data:
            log_security_event("OAUTH_TOKEN_EXCHANGE_FAILED", ip=get_client_ip())
            return redirect(url_for('verify_page'))
        
        # Get user info
        user_info = get_user_info(token_data.get('access_token'))
        if not user_info:
            log_security_event("OAUTH_USER_INFO_FAILED", ip=get_client_ip())
            return redirect(url_for('verify_page'))
        
        # Store user info in session
        session['discord_user'] = {
            'id': user_info['id'],
            'username': user_info['username'],
            'discriminator': user_info.get('discriminator', '0'),
            'avatar': user_info.get('avatar'),
            'avatar_url': f"https://cdn.discordapp.com/avatars/{user_info['id']}/{user_info.get('avatar')}.png" if user_info.get('avatar') else None,
            'full_username': f"{user_info['username']}#{user_info.get('discriminator', '0')}"
        }
        
        # Clear OAuth state
        session.pop('oauth_state', None)
        
        log_security_event("DISCORD_OAUTH_SUCCESS", user_info['id'], get_client_ip())
        
        return redirect(url_for('verify_page'))
    
    def exchange_code(code):
        """Exchange OAuth2 code for access token"""
        data = {
            'client_id': Config.CLIENT_ID,
            'client_secret': Config.CLIENT_SECRET,
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': Config.REDIRECT_URI,
            'scope': 'identify'
        }
        
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'Discord-Verification/2.0'
        }
        
        try:
            response = requests.post(
                'https://discord.com/api/oauth2/token',
                data=data,
                headers=headers,
                timeout=10
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"OAuth2 token exchange error: {e}")
            return None
    
    def get_user_info(access_token):
        """Get user info from Discord API"""
        headers = {
            'Authorization': f'Bearer {access_token}',
            'User-Agent': 'Discord-Verification/2.0'
        }
        
        try:
            response = requests.get(
                'https://discord.com/api/users/@me',
                headers=headers,
                timeout=10
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Discord API error: {e}")
            return None
    
    @app.route('/auth/logout')
    def auth_logout():
        """Logout from Discord OAuth2"""
        username = session.get('discord_user', {}).get('full_username', 'Unknown')
        session.pop('discord_user', None)
        log_security_event("USER_LOGOUT", details=username)
        return redirect(url_for('verify_page'))
    
    @app.route('/api/verify', methods=['POST'])
    @limiter.limit("5 per minute")
    @rate_limit_by_ip("3 per minute")
    def api_verify():
        """verification API with comprehensive security checks"""
        client_ip = get_client_ip()
        timestamp = datetime.utcnow()
        
        logger.info(f"Verification attempt from IP: {client_ip}")
        
        try:
            # Check Discord OAuth session
            discord_user = session.get('discord_user')
            if not discord_user:
                log_security_event("VERIFICATION_NO_OAUTH", ip=client_ip)
                return jsonify({
                    "success": False, 
                    "error": "Please connect your Discord account first.",
                    "requires_oauth": True
                }), 401
            
            discord_id = discord_user['id']
            username = discord_user['full_username']
            
            # Check if already verified
            existing_user = db_manager.get_user(discord_id)
            if existing_user and existing_user.get('verified_at'):
                logger.info(f"Already verified attempt: {username} ({discord_id})")
                return jsonify({
                    "success": False, 
                    "error": "You are already verified! Please return to the server.",
                    "already_verified": True
                }), 400
            
            # Get client information
            ip_address = get_client_ip()
            user_agent = request.headers.get('User-Agent', 'Unknown')
            hashed_ua = hash_user_agent(user_agent)
            
            # === SECURITY CHECKS ===
            
            # 1. Check temporary ban
            if is_temp_banned(ip_address):
                log_security_event("VERIFICATION_TEMPBAN_BLOCKED", discord_id, ip_address)
                return jsonify({
                    "success": False, 
                    "error": "Your IP is temporarily banned. Please try again later.",
                    "temp_banned": True
                }), 403
            
            # 2. Check permanent ban
            if db_manager.is_ip_banned(ip_address):
                log_security_event("VERIFICATION_BANNED_IP", discord_id, ip_address)
                send_discord_webhook(
                    "🚨 Banned IP Attempt",
                    f"**User:** {username}\n**ID:** {discord_id}\n**IP:** ||{ip_address}||\n**Status:** Banned IP attempted verification",
                    0xff0000,
                    Config.ALERTS_WEBHOOK
                )
                return jsonify({
                    "success": False, 
                    "error": "Access denied. Your IP is banned from this server.",
                    "banned": True
                }), 403
            
            # 3. Check VPN/Proxy
            vpn_check = check_vpn_multiple_providers(ip_address)
            if vpn_check['is_vpn']:
                # Create temporary ban
                create_temp_ban(
                    ip_address,
                    f"VPN detected (Confidence: {vpn_check['confidence']}%)",
                    1440  # 24 hours
                )
                
                # Log to permanent bans
                ban_data = {
                    "ip_address": ip_address,
                    "discord_id": discord_id,
                    "username": username,
                    "reason": f"VPN detected via {vpn_check['provider']} (Confidence: {vpn_check['confidence']}%)",
                    "banned_by": "System",
                    "banned_at": timestamp,
                    "type": "vpn",
                    "confidence": vpn_check['confidence']
                }
                
                if db_manager.db:
                    db_manager.db.banned_ips.insert_one(ban_data)
                    db_manager.db.vpn_logs.insert_one({
                        "ip_address": ip_address,
                        "discord_id": discord_id,
                        "detected_at": timestamp,
                        "provider": vpn_check['provider'],
                        "confidence": vpn_check['confidence']
                    })
                
                log_security_event("VPN_DETECTED_BANNED", discord_id, ip_address, 
                                 f"Provider: {vpn_check['provider']}, Confidence: {vpn_check['confidence']}%",
                                 "WARNING")
                
                send_discord_webhook(
                    "🚨 VPN Detected & Banned",
                    f"**User:** {username}\n**ID:** {discord_id}\n**IP:** ||{ip_address}||\n"
                    f"**Provider:** {vpn_check['provider']}\n**Confidence:** {vpn_check['confidence']}%\n"
                    f"**Action:** IP banned for 24 hours",
                    0xff0000,
                    Config.ALERTS_WEBHOOK
                )
                
                return jsonify({
                    "success": False, 
                    "error": "VPN/Proxy detected. Your IP has been temporarily banned.",
                    "vpn_detected": True,
                    "confidence": vpn_check['confidence']
                }), 403
            
            # 4. Check rate of verification attempts from this IP
            hour_ago = timestamp - timedelta(hours=1)
            if db_manager.db:
                recent_attempts = db_manager.db.verification_logs.count_documents({
                    "ip_address": ip_address,
                    "timestamp": {"$gte": hour_ago}
                })
                
                if recent_attempts >= 10:
                    create_temp_ban(ip_address, "Too many verification attempts", 60)
                    log_security_event("VERIFICATION_RATE_LIMIT", discord_id, ip_address,
                                     f"Attempts: {recent_attempts} in 1 hour", "WARNING")
                    return jsonify({
                        "success": False,
                        "error": "Too many verification attempts from this IP. Please try again later."
                    }), 429
            
            # === VERIFICATION SUCCESS ===
            
            # Save user data
            hashed_ip = PasswordManager.hash_ip(ip_address)
            
            user_data = {
                "discord_id": str(discord_id),
                "username": username,
                "ip_address": ip_address,
                "hashed_ip": hashed_ip,
                "user_agent": user_agent[:500],
                "hashed_user_agent": hashed_ua,
                "is_vpn": False,
                "vpn_confidence": 0,
                "last_seen": timestamp,
                "verified_at": timestamp,
                "verification_method": "discord_oauth",
                "verification_ip": ip_address,
                "is_banned": False,
                "role_added": False,
                "verification_count": 1,
                "security_level": "verified",
                "metadata": {
                    "avatar": discord_user.get('avatar'),
                    "discriminator": discord_user.get('discriminator')
                }
            }
            
            if db_manager.db:
                db_manager.db.users.update_one(
                    {"discord_id": str(discord_id)},
                    {"$set": user_data, "$inc": {"verification_count": 1}},
                    upsert=True
                )
                
                # Log verification
                db_manager.db.verification_logs.insert_one({
                    "discord_id": str(discord_id),
                    "username": username,
                    "ip_address": ip_address,
                    "hashed_ip": hashed_ip,
                    "hashed_user_agent": hashed_ua,
                    "timestamp": timestamp,
                    "success": True,
                    "method": "discord_oauth",
                    "user_agent": user_agent[:200],
                    "security_checks_passed": True,
                    "vpn_checked": True,
                    "vpn_result": False
                })
            
            # Send success notification
            send_discord_webhook(
                "✅ Verification Successful",
                f"**User:** {username}\n**ID:** {discord_id}\n"
                f"**IP Hash:** ||{hashed_ip[:8]}...||\n**Time:** {timestamp.strftime('%H:%M:%S')}\n"
                f"**VPN Check:** Passed ✅\n**Security:** All checks passed",
                0x00ff00,
                Config.WEBHOOK_URL,
                discord_user.get('avatar_url')
            )
            
            log_security_event("VERIFICATION_SUCCESS", discord_id, ip_address)
            
            # Clear session and prepare response
            session.pop('discord_user', None)
            
            return jsonify({
                "success": True,
                "message": "🎉 Verification successful! You can now return to Discord and access all channels.",
                "data": {
                    "username": username,
                    "discord_id": discord_id,
                    "timestamp": timestamp.isoformat(),
                    "security_checks": {
                        "vpn": "passed",
                        "ip_checks": "passed",
                        "rate_limit": "passed"
                    }
                }
            })
            
        except Exception as e:
            logger.error(f"Verification error: {str(e)}", exc_info=True)
            log_security_event("VERIFICATION_ERROR", ip=client_ip, details=str(e), level="ERROR")
            return jsonify({
                "success": False, 
                "error": "Internal server error. Please try again later.",
                "reference_id": f"ERR-{int(time.time())}"
            }), 500
    
    @app.route('/api/check-status/<discord_id>')
    @limiter.limit("30 per minute")
    def check_verification_status(discord_id):
        """Check verification status for a user"""
        try:
            user = db_manager.get_user(discord_id)
            
            if not user:
                return jsonify({
                    "verified": False,
                    "message": "User not found in verification system"
                })
            
            return jsonify({
                "verified": user.get('verified_at') is not None,
                "verified_at": user.get('verified_at'),
                "username": user.get('username'),
                "role_added": user.get('role_added', False),
                "is_banned": user.get('is_banned', False),
                "last_seen": user.get('last_seen')
            })
            
        except Exception as e:
            logger.error(f"Status check error: {e}")
            return jsonify({"error": "Internal server error"}), 500
    
    # ============ ADMIN ROUTES ============
    
    @app.route('/admin/login', methods=['GET', 'POST'])
    @limiter.limit("10 per hour")
    def admin_login():
        """Admin login with comprehensive security"""
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            remember = request.form.get('remember')
            client_ip = get_client_ip()
            
            # Check rate limit for this IP
            result = rate_limiter.check_rate_limit(
                f"admin_login_{client_ip}", 
                "admin_login", 
                limit=Config.MAX_LOGIN_ATTEMPTS, 
                window=3600
            )
            
            if not result['allowed']:
                log_security_event("ADMIN_LOGIN_RATE_LIMIT", ip=client_ip)
                return render_template('admin/login.html', 
                                     error=f"Too many login attempts. Try again in {result['retry_after']} seconds.")
            
            # Verify credentials
            if verify_admin_credentials(username, password):
                # Setup admin session
                session['admin_logged_in'] = True
                session['admin_username'] = username
                session['admin_ip'] = client_ip
                session['login_time'] = datetime.utcnow().isoformat()
                
                if remember:
                    session.permanent = True
                
                # Clear failed attempts
                rate_limiter.clear_attempts(f"admin_login_{client_ip}")
                
                log_security_event("ADMIN_LOGIN_SUCCESS", ip=client_ip, details=username)
                
                # Send security alert
                send_discord_webhook(
                    "👑 Admin Login",
                    f"**Admin:** {username}\n**IP:** ||{client_ip}||\n**Time:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
                    0x00ff00,
                    Config.ALERTS_WEBHOOK
                )
                
                # Check if 2FA is required
                if Config.REQUIRE_2FA:
                    return redirect(url_for('admin_2fa_verify'))
                
                return redirect(url_for('admin_dashboard'))
            else:
                # Track failed attempt
                attempts = rate_limiter.record_attempt(f"admin_login_{client_ip}")
                
                if attempts >= Config.MAX_LOGIN_ATTEMPTS:
                    # Lock IP for 1 hour
                    rate_limiter.lock_ip(client_ip, 3600)
                    
                    send_discord_webhook(
                        "🚨 Admin Login Lockout",
                        f"**IP:** ||{client_ip}||\n**Attempts:** {attempts}\n**Lock Duration:** 1 hour",
                        0xff0000,
                        Config.ALERTS_WEBHOOK
                    )
                
                log_security_event("ADMIN_LOGIN_FAILED", ip=client_ip, 
                                 details=f"username: {username}, attempt: {attempts}", 
                                 level="WARNING")
                
                remaining = Config.MAX_LOGIN_ATTEMPTS - attempts
                return render_template('admin/login.html', 
                                     error="Invalid credentials", 
                                     remaining_attempts=remaining)
        
        return render_template('admin/login.html')
    
    def verify_admin_credentials(username, password):
        """Verify admin credentials with bcrypt"""
        if username != Config.ADMIN_USERNAME:
            return False
        
        if not Config.ADMIN_PASSWORD_HASH:
            # Fallback to plain text (not recommended)
            return password == Config.ADMIN_PASSWORD
        
        return PasswordManager.verify_password(password, Config.ADMIN_PASSWORD_HASH)
    
    @app.route('/admin/2fa/verify', methods=['GET', 'POST'])
    @admin_required
    def admin_2fa_verify():
        """2FA verification for admin"""
        if not Config.REQUIRE_2FA:
            return redirect(url_for('admin_dashboard'))
        
        if request.method == 'POST':
            token = request.form.get('token')
            
            # Get or generate 2FA secret
            if 'admin_2fa_secret' not in session:
                # Generate new secret
                secret = pyotp.random_base32()
                session['admin_2fa_secret'] = secret
                session['admin_2fa_pending'] = True
            
            secret = session['admin_2fa_secret']
            totp = pyotp.TOTP(secret)
            
            if totp.verify(token, valid_window=1):
                session['admin_2fa_verified'] = True
                session.pop('admin_2fa_pending', None)
                
                log_security_event("ADMIN_2FA_SUCCESS", ip=get_client_ip())
                return redirect(url_for('admin_dashboard'))
            else:
                return render_template('admin/2fa.html', error="Invalid 2FA code")
        
        # Generate QR code for first-time setup
        if 'admin_2fa_secret' not in session:
            secret = pyotp.random_base32()
            session['admin_2fa_secret'] = secret
            session['admin_2fa_pending'] = True
        
        secret = session['admin_2fa_secret']
        totp = pyotp.TOTP(secret)
        
        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp.provisioning_uri(name=session['admin_username'], issuer_name="Discord Verification"))
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        img_io = io.BytesIO()
        img.save(img_io, 'PNG')
        img_io.seek(0)
        qr_code = base64.b64encode(img_io.getvalue()).decode()
        
        return render_template('admin/2fa.html', 
                             qr_code=qr_code,
                             secret=secret)
    
    @app.route('/admin/dashboard')
    @admin_required
    @require_2fa
    def admin_dashboard():
        """Admin dashboard with comprehensive stats"""
        try:
            # Get statistics
            stats = get_admin_stats()
            
            # Get recent security events
            recent_events = []
            if db_manager.db:
                recent_events = list(db_manager.db.security_logs.find()
                                   .sort("timestamp", -1)
                                   .limit(10))
                
                # Convert ObjectId to string
                for event in recent_events:
                    event['_id'] = str(event['_id'])
            
            # Get system performance
            performance = {
                "uptime": get_system_uptime(),
                "memory_usage": get_memory_usage(),
                "active_connections": get_active_connections(),
                "cache_hit_rate": db_manager.get_cache_hit_rate() if db_manager.cache_enabled else 0
            }
            
            # Get verification trends (last 7 days)
            trends = get_verification_trends(7)
            
            return render_template('admin/dashboard.html',
                                 stats=stats,
                                 recent_events=recent_events,
                                 performance=performance,
                                 trends=trends,
                                 Config=Config)
            
        except Exception as e:
            logger.error(f"Dashboard error: {e}")
            return render_template('admin/error.html', error=str(e))
    
    def get_admin_stats():
        """Get comprehensive admin statistics"""
        stats = {
            "total_users": 0,
            "verified_users": 0,
            "banned_users": 0,
            "today_verifications": 0,
            "vpn_detections_today": 0,
            "failed_logins_today": 0,
            "active_temp_bans": 0,
            "pending_verifications": 0
        }
        
        try:
            if db_manager.db:
                # Basic counts
                stats["total_users"] = db_manager.db.users.count_documents({})
                stats["verified_users"] = db_manager.db.users.count_documents({"verified_at": {"$exists": True}})
                stats["banned_users"] = db_manager.db.banned_ips.count_documents({"is_active": True})
                
                # Today's stats
                today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
                stats["today_verifications"] = db_manager.db.verification_logs.count_documents({
                    "timestamp": {"$gte": today},
                    "success": True
                })
                
                stats["vpn_detections_today"] = db_manager.db.vpn_logs.count_documents({
                    "detected_at": {"$gte": today}
                })
                
                stats["failed_logins_today"] = db_manager.db.security_logs.count_documents({
                    "type": "ADMIN_LOGIN_FAILED",
                    "timestamp": {"$gte": today}
                })
                
                stats["active_temp_bans"] = db_manager.db.temp_bans.count_documents({
                    "expires_at": {"$gt": datetime.utcnow()}
                })
                
                # Pending verifications (verified but no role)
                stats["pending_verifications"] = db_manager.db.users.count_documents({
                    "verified_at": {"$exists": True},
                    "role_added": False,
                    "is_banned": False
                })
        
        except Exception as e:
            logger.error(f"Stats calculation error: {e}")
        
        return stats
    
    @app.route('/admin/users')
    @admin_required
    @require_2fa
    def admin_users():
        """Manage verified users"""
        try:
            page = int(request.args.get('page', 1))
            per_page = 50
            skip = (page - 1) * per_page
            
            search = request.args.get('search', '')
            filter_status = request.args.get('status', 'all')
            
            query = {}
            
            if search:
                query['$or'] = [
                    {'username': {'$regex': search, '$options': 'i'}},
                    {'discord_id': {'$regex': search, '$options': 'i'}},
                    {'ip_address': {'$regex': search, '$options': 'i'}}
                ]
            
            if filter_status == 'verified':
                query['verified_at'] = {'$exists': True}
            elif filter_status == 'unverified':
                query['verified_at'] = {'$exists': False}
            elif filter_status == 'banned':
                query['is_banned'] = True
            
            users = []
            total = 0
            
            if db_manager.db:
                total = db_manager.db.users.count_documents(query)
                cursor = db_manager.db.users.find(query) \
                    .sort('last_seen', -1) \
                    .skip(skip) \
                    .limit(per_page)
                
                users = list(cursor)
                
                # Convert ObjectId and datetime
                for user in users:
                    user['_id'] = str(user['_id'])
                    if 'verified_at' in user and user['verified_at']:
                        user['verified_at'] = user['verified_at'].strftime('%Y-%m-%d %H:%M')
                    if 'last_seen' in user and user['last_seen']:
                        user['last_seen'] = user['last_seen'].strftime('%Y-%m-%d %H:%M')
            
            total_pages = (total + per_page - 1) // per_page
            
            return render_template('admin/users.html',
                                 users=users,
                                 page=page,
                                 total_pages=total_pages,
                                 total=total,
                                 search=search,
                                 status=filter_status)
            
        except Exception as e:
            logger.error(f"Users admin error: {e}")
            return render_template('admin/error.html', error=str(e))
    
    @app.route('/admin/banned')
    @admin_required
    @require_2fa
    def admin_banned():
        """Manage banned IPs and users"""
        try:
            page = int(request.args.get('page', 1))
            per_page = 50
            skip = (page - 1) * per_page
            
            filter_type = request.args.get('type', 'all')
            search = request.args.get('search', '')
            
            query = {}
            
            if filter_type == 'permanent':
                query['type'] = {'$ne': 'temporary'}
            elif filter_type == 'temporary':
                query['type'] = 'temporary'
            elif filter_type == 'vpn':
                query['type'] = 'vpn'
            
            if search:
                query['$or'] = [
                    {'ip_address': {'$regex': search, '$options': 'i'}},
                    {'username': {'$regex': search, '$options': 'i'}},
                    {'discord_id': {'$regex': search, '$options': 'i'}},
                    {'reason': {'$regex': search, '$options': 'i'}}
                ]
            
            bans = []
            total = 0
            
            if db_manager.db:
                # Get permanent bans
                perm_query = query.copy()
                if 'type' in perm_query and perm_query['type'] == 'temporary':
                    bans = []
                else:
                    total = db_manager.db.banned_ips.count_documents(perm_query)
                    cursor = db_manager.db.banned_ips.find(perm_query) \
                        .sort('banned_at', -1) \
                        .skip(skip) \
                        .limit(per_page)
                    
                    bans = list(cursor)
                
                # Get temporary bans if needed
                if filter_type in ['all', 'temporary']:
                    temp_query = {'expires_at': {'$gt': datetime.utcnow()}}
                    if search:
                        temp_query['$or'] = [
                            {'ip_address': {'$regex': search, '$options': 'i'}},
                            {'reason': {'$regex': search, '$options': 'i'}}
                        ]
                    
                    temp_bans = list(db_manager.db.temp_bans.find(temp_query)
                                   .sort('created_at', -1)
                                   .limit(per_page))
                    
                    # Convert temporary bans to same format
                    for ban in temp_bans:
                        ban['type'] = 'temporary'
                        ban['banned_at'] = ban.get('created_at')
                        if ban['type'] not in ['temporary']:
                            bans.append(ban)
                    
                    if filter_type == 'temporary':
                        total = len(temp_bans)
                        bans = temp_bans
            
            # Process bans for display
            for ban in bans:
                ban['_id'] = str(ban.get('_id', ''))
                if 'banned_at' in ban and ban['banned_at']:
                    ban['banned_at'] = ban['banned_at'].strftime('%Y-%m-%d %H:%M')
                if 'expires_at' in ban and ban['expires_at']:
                    ban['expires_at'] = ban['expires_at'].strftime('%Y-%m-%d %H:%M')
            
            total_pages = (total + per_page - 1) // per_page
            
            return render_template('admin/banned.html',
                                 bans=bans,
                                 page=page,
                                 total_pages=total_pages,
                                 total=total,
                                 search=search,
                                 type=filter_type)
            
        except Exception as e:
            logger.error(f"Banned admin error: {e}")
            return render_template('admin/error.html', error=str(e))
    
    @app.route('/admin/unban/<ban_id>')
    @admin_required
    @require_2fa
    def admin_unban(ban_id):
        """Unban an IP or user"""
        try:
            ban_type = request.args.get('type', 'permanent')
            
            if ban_type == 'permanent':
                # Remove from banned_ips
                result = db_manager.db.banned_ips.delete_one({'_id': ObjectId(ban_id)})
                if result.deleted_count > 0:
                    log_security_event("ADMIN_UNBAN_PERMANENT", 
                                     ip=get_client_ip(), 
                                     details=f"Ban ID: {ban_id}")
                    send_discord_webhook(
                        "🔓 Permanent Ban Removed",
                        f"**Action by:** {session['admin_username']}\n**Ban ID:** {ban_id}",
                        0x00ff00,
                        Config.ALERTS_WEBHOOK
                    )
            elif ban_type == 'temporary':
                # Remove from temp_bans
                result = db_manager.db.temp_bans.delete_one({'_id': ObjectId(ban_id)})
                if result.deleted_count > 0:
                    log_security_event("ADMIN_UNBAN_TEMPORARY",
                                     ip=get_client_ip(),
                                     details=f"Temp Ban ID: {ban_id}")
                    send_discord_webhook(
                        "🔓 Temporary Ban Removed",
                        f"**Action by:** {session['admin_username']}\n**Ban ID:** {ban_id}",
                        0x00ff00,
                        Config.ALERTS_WEBHOOK
                    )
            
            return redirect(url_for('admin_banned'))
            
        except Exception as e:
            logger.error(f"Unban error: {e}")
            return redirect(url_for('admin_banned'))
    
    @app.route('/admin/logs')
    @admin_required
    @require_2fa
    def admin_logs():
        """View system logs"""
        try:
            page = int(request.args.get('page', 1))
            per_page = 100
            skip = (page - 1) * per_page
            
            log_type = request.args.get('type', 'all')
            level = request.args.get('level', 'all')
            search = request.args.get('search', '')
            
            query = {}
            
            if log_type != 'all':
                query['type'] = log_type
            
            if level != 'all':
                query['level'] = level
            
            if search:
                query['$or'] = [
                    {'details': {'$regex': search, '$options': 'i'}},
                    {'ip_address': {'$regex': search, '$options': 'i'}},
                    {'user_id': {'$regex': search, '$options': 'i'}}
                ]
            
            logs = []
            total = 0
            
            if db_manager.db:
                total = db_manager.db.security_logs.count_documents(query)
                cursor = db_manager.db.security_logs.find(query) \
                    .sort('timestamp', -1) \
                    .skip(skip) \
                    .limit(per_page)
                
                logs = list(cursor)
                
                # Process for display
                for log in logs:
                    log['_id'] = str(log['_id'])
                    log['timestamp'] = log['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
                    # Truncate long details
                    if 'details' in log and len(log['details']) > 200:
                        log['details'] = log['details'][:200] + '...'
            
            total_pages = (total + per_page - 1) // per_page
            
            # Get log types for filter
            log_types = []
            if db_manager.db:
                log_types = db_manager.db.security_logs.distinct('type')
            
            return render_template('admin/logs.html',
                                 logs=logs,
                                 page=page,
                                 total_pages=total_pages,
                                 total=total,
                                 search=search,
                                 log_type=log_type,
                                 level=level,
                                 log_types=log_types)
            
        except Exception as e:
            logger.error(f"Logs admin error: {e}")
            return render_template('admin/error.html', error=str(e))
    
    @app.route('/admin/settings', methods=['GET', 'POST'])
    @admin_required
    @require_2fa
    def admin_settings():
        """Admin settings page"""
        if request.method == 'POST':
            try:
                action = request.form.get('action')
                
                if action == 'maintenance':
                    enabled = request.form.get('enabled') == 'true'
                    
                    db_manager.db.settings.update_one(
                        {'key': 'maintenance_mode'},
                        {'$set': {'value': enabled, 'updated_at': datetime.utcnow()}},
                        upsert=True
                    )
                    
                    log_security_event("ADMIN_MAINTENANCE_TOGGLE",
                                     ip=get_client_ip(),
                                     details=f"Maintenance mode: {enabled}")
                    
                    send_discord_webhook(
                        "🛠️ Maintenance Mode Updated",
                        f"**Action by:** {session['admin_username']}\n**Status:** {'Enabled' if enabled else 'Disabled'}",
                        0xff9900,
                        Config.ALERTS_WEBHOOK
                    )
                    
                    return jsonify({'success': True, 'message': 'Settings updated'})
                
                elif action == 'rate_limit':
                    limit = int(request.form.get('limit', 5))
                    
                    db_manager.db.settings.update_one(
                        {'key': 'rate_limit'},
                        {'$set': {'value': limit, 'updated_at': datetime.utcnow()}},
                        upsert=True
                    )
                    
                    return jsonify({'success': True, 'message': 'Rate limit updated'})
                
            except Exception as e:
                logger.error(f"Settings update error: {e}")
                return jsonify({'success': False, 'error': str(e)}), 500
        
        # GET request - load settings
        settings = {}
        if db_manager.db:
            setting_docs = db_manager.db.settings.find()
            for doc in setting_docs:
                settings[doc['key']] = doc.get('value')
        
        return render_template('admin/settings.html',
                             settings=settings,
                             Config=Config)
    
    @app.route('/admin/backup')
    @admin_required
    @require_2fa
    def admin_backup():
        """Manual database backup"""
        try:
            backup_path = backup_database()
            
            if backup_path:
                send_discord_webhook(
                    "💾 Manual Backup Created",
                    f"**Admin:** {session['admin_username']}\n**Backup:** {backup_path}\n**Time:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}",
                    0x00ff00,
                    Config.BACKUP_WEBHOOK
                )
                
                log_security_event("ADMIN_MANUAL_BACKUP",
                                 ip=get_client_ip(),
                                 details=f"Backup path: {backup_path}")
                
                return jsonify({'success': True, 'backup_path': backup_path})
            else:
                return jsonify({'success': False, 'error': 'Backup failed'}), 500
                
        except Exception as e:
            logger.error(f"Backup error: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500
    
    @app.route('/admin/api/statistics')
    @admin_required
    @require_2fa
    def admin_api_statistics():
        """API endpoint for statistics (for charts)"""
        try:
            # Get verification trends for chart
            days = int(request.args.get('days', 7))
            trends = get_verification_trends(days)
            
            # Get hourly data for today
            hourly = get_hourly_verifications()
            
            # Get top IPs
            top_ips = get_top_ips(10)
            
            return jsonify({
                'success': True,
                'trends': trends,
                'hourly': hourly,
                'top_ips': top_ips,
                'timestamp': datetime.utcnow().isoformat()
            })
            
        except Exception as e:
            logger.error(f"Statistics API error: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500
    
    def get_verification_trends(days=7):
        """Get verification trends for chart"""
        trends = []
        
        try:
            if db_manager.db:
                for i in range(days):
                    date = (datetime.utcnow() - timedelta(days=i)).replace(
                        hour=0, minute=0, second=0, microsecond=0
                    )
                    next_date = date + timedelta(days=1)
                    
                    count = db_manager.db.verification_logs.count_documents({
                        'timestamp': {'$gte': date, '$lt': next_date},
                        'success': True
                    })
                    
                    vpn_count = db_manager.db.vpn_logs.count_documents({
                        'detected_at': {'$gte': date, '$lt': next_date}
                    })
                    
                    trends.append({
                        'date': date.strftime('%Y-%m-%d'),
                        'verifications': count,
                        'vpn_detections': vpn_count,
                        'success_rate': (count / (count + vpn_count)) * 100 if (count + vpn_count) > 0 else 100
                    })
                
                trends.reverse()  # Oldest to newest
        
        except Exception as e:
            logger.error(f"Trends error: {e}")
        
        return trends
    
    def get_hourly_verifications():
        """Get hourly verification data for today"""
        hourly = []
        
        try:
            if db_manager.db:
                today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
                
                for hour in range(24):
                    start = today + timedelta(hours=hour)
                    end = start + timedelta(hours=1)
                    
                    count = db_manager.db.verification_logs.count_documents({
                        'timestamp': {'$gte': start, '$lt': end},
                        'success': True
                    })
                    
                    hourly.append({
                        'hour': f"{hour:02d}:00",
                        'count': count
                    })
        
        except Exception as e:
            logger.error(f"Hourly data error: {e}")
        
        return hourly
    
    def get_top_ips(limit=10):
        """Get top IPs by verification attempts"""
        top_ips = []
        
        try:
            if db_manager.db:
                pipeline = [
                    {
                        '$match': {
                            'timestamp': {
                                '$gte': datetime.utcnow() - timedelta(days=7)
                            }
                        }
                    },
                    {
                        '$group': {
                            '_id': '$ip_address',
                            'count': {'$sum': 1},
                            'last_attempt': {'$max': '$timestamp'}
                        }
                    },
                    {
                        '$sort': {'count': -1}
                    },
                    {
                        '$limit': limit
                    }
                ]
                
                results = db_manager.db.verification_logs.aggregate(pipeline)
                
                for result in results:
                    top_ips.append({
                        'ip': result['_id'],
                        'count': result['count'],
                        'last_attempt': result['last_attempt'].strftime('%Y-%m-%d %H:%M')
                    })
        
        except Exception as e:
            logger.error(f"Top IPs error: {e}")
        
        return top_ips
    
    @app.route('/admin/logout')
    def admin_logout():
        """Admin logout with security cleanup"""
        username = session.get('admin_username', 'Unknown')
        client_ip = get_client_ip()
        
        log_security_event("ADMIN_LOGOUT", ip=client_ip, details=username)
        
        # Clear all session data
        session.clear()
        
        return redirect(url_for('admin_login'))
    
    # ============ UTILITY ROUTES ============
    
    @app.route('/health')
    @limiter.exempt
    def health_check():
        """Comprehensive health check endpoint"""
        health_status = {
            "status": "healthy",
            "service": "discord-verification",
            "version": "2.0.0",
            "timestamp": datetime.utcnow().isoformat(),
            "checks": {}
        }
        
        # Database health
        try:
            if db_manager.db:
                db_manager.db.command('ping')
                health_status["checks"]["database"] = {
                    "status": "healthy",
                    "response_time": "ok"
                }
            else:
                health_status["checks"]["database"] = {
                    "status": "unavailable",
                    "error": "No database connection"
                }
        except Exception as e:
            health_status["checks"]["database"] = {
                "status": "unhealthy",
                "error": str(e)
            }
        
        # Redis health
        if db_manager.cache_enabled:
            health_status["checks"]["redis"] = {
                "status": "healthy",
                "cache_enabled": True
            }
        else:
            health_status["checks"]["redis"] = {
                "status": "disabled",
                "cache_enabled": False
            }
        
        # System metrics
        health_status["metrics"] = {
            "uptime": get_system_uptime(),
            "memory_usage_mb": get_memory_usage(),
            "active_threads": threading.active_count(),
            "python_version": sys.version
        }
        
        # If any critical check fails, mark as unhealthy
        if any(check.get('status') == 'unhealthy' for check in health_status["checks"].values()):
            health_status["status"] = "unhealthy"
        
        return jsonify(health_status)
    
    @app.route('/metrics')
    @admin_required
    @require_2fa
    def metrics():
        """Prometheus metrics endpoint"""
        from prometheus_client import generate_latest, Counter, Gauge, Histogram
        from prometheus_client.core import CollectorRegistry
        
        registry = CollectorRegistry()
        
        # Define metrics
        verifications_total = Counter('verifications_total', 'Total verification attempts', registry=registry)
        verifications_success = Counter('verifications_success', 'Successful verifications', registry=registry)
        verifications_failed = Counter('verifications_failed', 'Failed verifications', registry=registry)
        vpn_detections = Counter('vpn_detections_total', 'VPN detections', registry=registry)
        active_users = Gauge('active_users_total', 'Active users in system', registry=registry)
        request_duration = Histogram('http_request_duration_seconds', 'HTTP request duration', registry=registry)
        
        # Update metrics with actual data
        try:
            if db_manager.db:
                # Get counts
                total_verifications = db_manager.db.verification_logs.count_documents({})
                success_verifications = db_manager.db.verification_logs.count_documents({'success': True})
                failed_verifications = total_verifications - success_verifications
                vpn_count = db_manager.db.vpn_logs.count_documents({})
                users_count = db_manager.db.users.count_documents({})
                
                # Set metric values
                verifications_total._value.set(total_verifications)
                verifications_success._value.set(success_verifications)
                verifications_failed._value.set(failed_verifications)
                vpn_detections._value.set(vpn_count)
                active_users.set(users_count)
        
        except Exception as e:
            logger.error(f"Metrics error: {e}")
        
        return generate_latest(registry), 200, {'Content-Type': 'text/plain'}
    
    @app.route('/feedback')
    @check_maintenance_mode
    def feedback():
        """Feedback and support page"""
        return render_template('feedback.html')
    
    @app.route('/privacy')
    def privacy():
        """Privacy policy page"""
        return render_template('privacy.html')
    
    @app.route('/terms')
    def terms():
        """Terms of service page"""
        return render_template('terms.html')
    
    # ============ HELPER FUNCTIONS ============
    
    def get_today_verifications():
        """Get today's verification count"""
        try:
            if db_manager.db:
                today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
                return db_manager.db.verification_logs.count_documents({
                    'timestamp': {'$gte': today},
                    'success': True
                })
        except:
            pass
        return 0
    
    def get_total_users():
        """Get total user count"""
        try:
            if db_manager.db:
                return db_manager.db.users.count_documents({})
        except:
            pass
        return 0
    
    def get_system_uptime():
        """Get system uptime"""
        try:
            with open('/proc/uptime', 'r') as f:
                uptime_seconds = float(f.readline().split()[0])
                days = int(uptime_seconds // 86400)
                hours = int((uptime_seconds % 86400) // 3600)
                return f"{days}d {hours}h"
        except:
            return "Unknown"
    
    def get_memory_usage():
        """Get memory usage in MB"""
        try:
            import psutil
            process = psutil.Process()
            return int(process.memory_info().rss / 1024 / 1024)
        except:
            return 0
    
    def get_active_connections():
        """Get active database connections"""
        try:
            if db_manager.db:
                # This is MongoDB specific
                server_status = db_manager.db.command('serverStatus')
                return server_status.get('connections', {}).get('current', 0)
        except:
            pass
        return 0
    
    # ============ ERROR HANDLERS ============
    
    @app.errorhandler(404)
    def not_found_error(error):
        """404 error handler"""
        log_security_event("404_NOT_FOUND", ip=get_client_ip(), details=request.path)
        return render_template('error.html', 
                             error_code=404,
                             error_message="Page not found",
                             error_details="The page you're looking for doesn't exist."), 404
    
    @app.errorhandler(403)
    def forbidden_error(error):
        """403 error handler"""
        log_security_event("403_FORBIDDEN", ip=get_client_ip(), details=str(error))
        return render_template('error.html',
                             error_code=403,
                             error_message="Access forbidden",
                             error_details="You don't have permission to access this resource."), 403
    
    @app.errorhandler(429)
    def rate_limit_error(error):
        """429 rate limit error handler"""
        return jsonify({
            "success": False,
            "error": "Rate limit exceeded. Please try again later.",
            "retry_after": getattr(error, 'retry_after', 60)
        }), 429
    
    @app.errorhandler(500)
    def internal_error(error):
        """500 error handler"""
        log_security_event("500_INTERNAL_ERROR", ip=get_client_ip(), details=str(error), level="ERROR")
        return render_template('error.html',
                             error_code=500,
                             error_message="Internal server error",
                             error_details="An unexpected error occurred. Our team has been notified."), 500
    
    @app.errorhandler(Exception)
    def handle_exception(error):
        """Global exception handler"""
        logger.error(f"Unhandled exception: {error}", exc_info=True)
        log_security_event("UNHANDLED_EXCEPTION", ip=get_client_ip(), details=str(error), level="ERROR")
        return render_template('error.html',
                             error_code=500,
                             error_message="System error",
                             error_details="An unexpected system error occurred."), 500
    
    # ============ SCHEDULED TASKS ============
    
    def run_scheduled_tasks():
        """Run scheduled maintenance tasks"""
        try:
            # Clean old temp bans
            if db_manager.db:
                cutoff = datetime.utcnow() - timedelta(days=7)
                result = db_manager.db.temp_bans.delete_many({
                    'expires_at': {'$lt': datetime.utcnow()}
                })
                if result.deleted_count > 0:
                    logger.info(f"Cleaned {result.deleted_count} expired temp bans")
            
            # Clean old security logs (keep 30 days)
            if db_manager.db:
                cutoff = datetime.utcnow() - timedelta(days=30)
                result = db_manager.db.security_logs.delete_many({
                    'timestamp': {'$lt': cutoff}
                })
                if result.deleted_count > 0:
                    logger.info(f"Cleaned {result.deleted_count} old security logs")
            
            # Auto-backup if configured
            if Config.BACKUP_INTERVAL_HOURS > 0:
                last_backup = db_manager.cache_get('last_backup_time')
                if not last_backup or (datetime.utcnow() - datetime.fromisoformat(last_backup)).total_seconds() > Config.BACKUP_INTERVAL_HOURS * 3600:
                    backup_path = backup_database()
                    if backup_path:
                        db_manager.cache_set('last_backup_time', datetime.utcnow().isoformat(), 3600)
                        logger.info(f"Auto-backup created: {backup_path}")
        
        except Exception as e:
            logger.error(f"Scheduled task error: {e}")
    
    # Run scheduled tasks on startup
    import threading
    def schedule_tasks():
        """Background task scheduler"""
        import schedule
        import time
        
        # Schedule tasks
        schedule.every(1).hours.do(run_scheduled_tasks)
        schedule.every(6).hours.do(lambda: backup_database() if Config.BACKUP_INTERVAL_HOURS > 0 else None)
        
        while True:
            schedule.run_pending()
            time.sleep(60)
    
    # Start scheduler in background thread
    scheduler_thread = threading.Thread(target=schedule_tasks, daemon=True)
    scheduler_thread.start()
    
    logger.info("✅ Flask application initialized with all security features")
    return app