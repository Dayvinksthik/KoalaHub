"""
Discord Verification System - Website Application
Enhanced with maximum security features
"""

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, g, abort
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired, Length, Regexp
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
import bleach
import re

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import Config
from utils.logger import logger
from utils.password import PasswordManager
from utils.rate_limiter import rate_limiter
from database.connection import db_manager

def create_app():
    """Create and configure Flask application with maximum security"""
    app = Flask(__name__, template_folder='templates', static_folder='static')
    
    # ============ SECURITY CONFIGURATION ============
    app.config['SECRET_KEY'] = Config.SECRET_KEY
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=Config.SESSION_TIMEOUT_MINUTES)
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['WTF_CSRF_ENABLED'] = True
    app.config['WTF_CSRF_SECRET_KEY'] = secrets.token_hex(32)
    
    # Security headers with Talisman
    csp = {
        'default-src': ["'self'"],
        'style-src': ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
        'script-src': ["'self'", "'unsafe-inline'"],
        'font-src': ["'self'", "https://cdnjs.cloudflare.com"],
        'img-src': ["'self'", "data:", "https:"],
        'connect-src': ["'self'", "https://discord.com"]
    }
    
    Talisman(app, 
             force_https=True,
             session_cookie_secure=True,
             content_security_policy=csp,
             strict_transport_security=True,
             frame_options='DENY',
             x_xss_protection=True,
             x_content_type_options=True)
    
    CORS(app, origins=[Config.WEBSITE_URL, "http://localhost:10000"])
    
    # Rate limiting with stricter limits
    limiter = Limiter(
        get_remote_address,
        app=app,
        storage_uri="memory://",
        default_limits=["100 per day", "20 per hour"]
    )
    
    # ============ SECURITY UTILITIES ============
    
    class HoneypotField(StringField):
        """Honeypot field to catch bots"""
        pass
    
    class SecureLoginForm(FlaskForm):
        """Secure login form with CSRF and honeypot"""
        username = StringField('Username', validators=[
            DataRequired(),
            Length(min=3, max=50),
            Regexp(r'^[a-zA-Z0-9_]+$', message='Invalid username')
        ])
        password = PasswordField('Password', validators=[
            DataRequired(),
            Length(min=8, max=128)
        ])
        honeypot = HoneypotField('Leave this empty')  # Honeypot for bots
    
    def get_client_ip():
        """Get client IP address with security checks"""
        if request.headers.get('CF-Connecting-IP'):
            ip = request.headers['CF-Connecting-IP']
        elif request.headers.get('X-Forwarded-For'):
            ips = request.headers['X-Forwarded-For'].split(',')
            ip = ips[0].strip()
        elif request.headers.get('X-Real-IP'):
            ip = request.headers['X-Real-IP']
        else:
            ip = request.remote_addr
        
        # Validate IP format
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if not re.match(ip_pattern, ip):
            ip = '0.0.0.0'
        
        return ip
    
    def sanitize_input(text):
        """Sanitize user input to prevent XSS"""
        if not text:
            return ''
        
        # Remove null bytes
        text = text.replace('\0', '')
        
        # Strip dangerous characters
        text = bleach.clean(text, tags=[], attributes={}, styles=[], strip=True)
        
        # Limit length
        return text[:1000]
    
    def validate_csrf_token():
        """Validate CSRF token"""
        if request.method in ['POST', 'PUT', 'DELETE', 'PATCH']:
            csrf_token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')
            if not csrf_token or csrf_token != session.get('csrf_token'):
                return False
        return True
    
    def generate_csrf_token():
        """Generate CSRF token"""
        if 'csrf_token' not in session:
            session['csrf_token'] = secrets.token_hex(32)
        return session['csrf_token']
    
    def log_security_event(event_type, user_id=None, details="", level="INFO"):
        """Enhanced security logging"""
        ip_addr = get_client_ip()
        timestamp = datetime.utcnow()
        
        event = {
            "type": event_type,
            "user_id": user_id,
            "ip_address": ip_addr,
            "hashed_ip": PasswordManager.hash_ip(ip_addr),
            "user_agent": request.headers.get('User-Agent', 'Unknown')[:200],
            "details": sanitize_input(details),
            "timestamp": timestamp,
            "level": level,
            "endpoint": request.endpoint,
            "method": request.method,
            "referrer": request.referrer[:200] if request.referrer else None
        }
        
        # Store in database
        if db_manager.db:
            try:
                db_manager.db.security_logs.insert_one(event)
            except Exception as e:
                logger.error(f"Failed to log security event: {e}")
        
        # Send alert for critical events
        if level in ["CRITICAL", "ERROR"]:
            send_security_alert(event_type, details, ip_addr)
        
        logger.info(f"SECURITY {level}: {event_type} - IP: {ip_addr}")
    
    def send_security_alert(event_type, details, ip_addr):
        """Send security alert"""
        if not Config.ALERTS_WEBHOOK:
            return
        
        embed = {
            "title": f"🚨 {event_type}",
            "description": f"**IP:** ||{ip_addr}||\n**Details:** {details[:500]}",
            "color": 0xff0000,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        try:
            requests.post(Config.ALERTS_WEBHOOK, json={"embeds": [embed]}, timeout=5)
        except:
            pass
    
    def check_request_limits(ip_addr):
        """Check request limits for IP"""
        key = f"request_limit:{ip_addr}"
        limit = 100  # Max requests per minute
        
        current = db_manager.cache_incr(key)
        if current == 1:
            db_manager.cache_set(key, 1, 60)  # Expire in 1 minute
        
        if current and current > limit:
            log_security_event("RATE_LIMIT_EXCEEDED", ip=ip_addr, level="WARNING")
            return False
        
        return True
    
    def require_csrf(f):
        """CSRF protection decorator"""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not validate_csrf_token():
                log_security_event("CSRF_VALIDATION_FAILED", ip=get_client_ip(), level="WARNING")
                abort(403, description="CSRF validation failed")
            return f(*args, **kwargs)
        return decorated_function
    
    def require_authentication(f):
        """Authentication required decorator"""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not session.get('admin_logged_in'):
                log_security_event("UNAUTHORIZED_ACCESS", ip=get_client_ip(), level="WARNING")
                return redirect(url_for('admin_login'))
            return f(*args, **kwargs)
        return decorated_function
    
    # ============ REQUEST HANDLING ============
    
    @app.before_request
    def before_request():
        """Handle requests with security checks"""
        g.start_time = time.time()
        g.client_ip = get_client_ip()
        
        # Generate CSRF token
        generate_csrf_token()
        
        # Check request limits
        if not check_request_limits(g.client_ip):
            abort(429, description="Too many requests")
        
        # Log all requests for sensitive endpoints
        if request.endpoint in ['admin_login', 'api_verify', 'auth_callback']:
            logger.info(f"Request: {request.method} {request.path} - IP: {g.client_ip}")
    
    @app.after_request
    def after_request(response):
        """Add security headers and log slow requests"""
        # Add security headers
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        # Log slow requests
        if hasattr(g, 'start_time'):
            duration = time.time() - g.start_time
            if duration > 2.0:  # Log requests taking more than 2 seconds
                logger.warning(f"Slow request: {request.path} took {duration:.2f}s - IP: {g.client_ip}")
        
        return response
    
    # ============ ROUTES ============
    
    @app.route('/')
    @limiter.limit("50 per minute")
    def home():
        """Home page"""
        return render_template('index.html', csrf_token=generate_csrf_token())
    
    @app.route('/verify')
    @limiter.limit("10 per minute")
    def verify_page():
        """Verification page with enhanced security"""
        client_ip = get_client_ip()
        
        # Check for bans
        if db_manager.is_ip_banned(client_ip):
            log_security_event("BANNED_IP_ACCESS", ip=client_ip, level="WARNING")
            return render_template('blocked.html'), 403
        
        # Generate state for OAuth
        state = secrets.token_urlsafe(32)
        session['oauth_state'] = state
        session['oauth_timestamp'] = time.time()
        
        return render_template('verify.html', 
                             csrf_token=generate_csrf_token(),
                             client_id=Config.CLIENT_ID,
                             redirect_uri=urllib.parse.quote(Config.REDIRECT_URI),
                             state=state)
    
    @app.route('/api/verify', methods=['POST'])
    @limiter.limit("3 per minute")
    @require_csrf
    def api_verify():
        """verification API with maximum security"""
        client_ip = get_client_ip()
        
        try:
            # Check honeypot field
            if request.form.get('honeypot'):
                log_security_event("HONEYPOT_TRIGGERED", ip=client_ip, level="WARNING")
                time.sleep(2)  # Delay to slow down bots
                return jsonify({"success": False, "error": "Verification failed"}), 400
            
            # Validate Discord session
            discord_user = session.get('discord_user')
            if not discord_user:
                return jsonify({
                    "success": False, 
                    "error": "Please connect your Discord account first."
                }), 401
            
            discord_id = discord_user['id']
            username = discord_user['full_username']
            
            # Check if already verified
            existing_user = db_manager.get_user(discord_id)
            if existing_user and existing_user.get('verified_at'):
                return jsonify({
                    "success": False, 
                    "error": "You are already verified!"
                }), 400
            
            # Security checks
            if db_manager.is_ip_banned(client_ip):
                return jsonify({
                    "success": False, 
                    "error": "Your IP is banned from this server."
                }), 403
            
            # Check VPN (implement your VPN detection here)
            # ...
            
            # Save verification
            user_data = {
                "discord_id": str(discord_id),
                "username": username,
                "ip_address": client_ip,
                "hashed_ip": PasswordManager.hash_ip(client_ip),
                "verified_at": datetime.utcnow(),
                "is_banned": False,
                "role_added": False
            }
            
            if db_manager.db:
                db_manager.db.users.update_one(
                    {"discord_id": str(discord_id)},
                    {"$set": user_data},
                    upsert=True
                )
            
            # Clear session
            session.pop('discord_user', None)
            
            log_security_event("VERIFICATION_SUCCESS", discord_id, f"User: {username}")
            
            return jsonify({
                "success": True,
                "message": "✅ Verification successful! Return to Discord.",
                "username": username
            })
            
        except Exception as e:
            logger.error(f"Verification error: {e}")
            log_security_event("VERIFICATION_ERROR", ip=client_ip, details=str(e), level="ERROR")
            return jsonify({
                "success": False, 
                "error": "Internal server error"
            }), 500
    
    @app.route('/admin/login', methods=['GET', 'POST'])
    @limiter.limit("5 per hour")
    def admin_login():
        """Admin login with maximum security"""
        form = SecureLoginForm()
        
        if request.method == 'POST' and form.validate():
            client_ip = get_client_ip()
            
            # Check honeypot
            if form.honeypot.data:
                log_security_event("ADMIN_HONEYPOT_TRIGGERED", ip=client_ip, level="WARNING")
                time.sleep(5)  # Long delay for bots
                return render_template('admin/login.html', form=form, error="Invalid credentials")
            
            username = sanitize_input(form.username.data)
            password = form.password.data
            
            # Rate limiting per IP
            attempts_key = f"admin_login_attempts:{client_ip}"
            attempts = db_manager.cache_get(attempts_key) or 0
            
            if attempts >= Config.MAX_LOGIN_ATTEMPTS:
                log_security_event("ADMIN_LOGIN_LOCKOUT", ip=client_ip, level="WARNING")
                return render_template('admin/login.html', form=form, 
                                     error=f"Too many attempts. Try again in {60 - (time.time() % 60):.0f} seconds")
            
            # Verify credentials
            if username == Config.ADMIN_USERNAME and PasswordManager.verify_password(password, Config.ADMIN_PASSWORD_HASH):
                # Successful login
                session['admin_logged_in'] = True
                session['admin_username'] = username
                session['admin_ip'] = client_ip
                session['login_time'] = datetime.utcnow().isoformat()
                
                # Reset attempts
                db_manager.cache_delete(attempts_key)
                
                log_security_event("ADMIN_LOGIN_SUCCESS", ip=client_ip)
                
                # 2FA if enabled
                if Config.REQUIRE_2FA:
                    return redirect(url_for('admin_2fa'))
                
                return redirect(url_for('admin_dashboard'))
            else:
                # Failed login
                attempts += 1
                db_manager.cache_set(attempts_key, attempts, 300)  # 5 minute lockout
                
                remaining = Config.MAX_LOGIN_ATTEMPTS - attempts
                log_security_event("ADMIN_LOGIN_FAILED", ip=client_ip, 
                                 details=f"Attempts: {attempts}, Remaining: {remaining}", level="WARNING")
                
                return render_template('admin/login.html', form=form, 
                                     error=f"Invalid credentials. {remaining} attempts remaining")
        
        return render_template('admin/login.html', form=form, csrf_token=generate_csrf_token())
    
    @app.route('/admin/dashboard')
    @require_authentication
    def admin_dashboard():
        """Admin dashboard"""
        # Check session expiration
        login_time = datetime.fromisoformat(session.get('login_time', '2000-01-01'))
        if datetime.utcnow() - login_time > timedelta(minutes=Config.SESSION_TIMEOUT_MINUTES):
            session.clear()
            return redirect(url_for('admin_login'))
        
        # Check IP change (session hijacking)
        if session.get('admin_ip') != get_client_ip():
            log_security_event("ADMIN_SESSION_HIJACK", ip=get_client_ip(), level="CRITICAL")
            session.clear()
            return redirect(url_for('admin_login'))
        
        return render_template('admin/dashboard.html')
    
    @app.route('/admin/logout')
    def admin_logout():
        """Admin logout with security cleanup"""
        log_security_event("ADMIN_LOGOUT", ip=get_client_ip())
        session.clear()
        return redirect(url_for('admin_login'))
    
    @app.route('/health')
    @limiter.exempt
    def health_check():
        """Health check endpoint"""
        return jsonify({
            "status": "healthy",
            "service": "discord-verification",
            "timestamp": datetime.utcnow().isoformat()
        })
    
    # ============ ERROR HANDLERS ============
    
    @app.errorhandler(404)
    def not_found_error(error):
        """404 error handler"""
        log_security_event("404_NOT_FOUND", ip=get_client_ip(), details=request.path)
        return render_template('error.html', error_code=404), 404
    
    @app.errorhandler(403)
    def forbidden_error(error):
        """403 error handler"""
        log_security_event("403_FORBIDDEN", ip=get_client_ip(), details=str(error))
        return render_template('error.html', error_code=403), 403
    
    @app.errorhandler(429)
    def rate_limit_error(error):
        """429 rate limit error"""
        return jsonify({"error": "Rate limit exceeded"}), 429
    
    @app.errorhandler(500)
    def internal_error(error):
        """500 error handler"""
        log_security_event("500_INTERNAL_ERROR", ip=get_client_ip(), details=str(error), level="ERROR")
        return render_template('error.html', error_code=500), 500
    
    return app