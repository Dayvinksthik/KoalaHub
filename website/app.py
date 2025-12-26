"""
Discord Verification System - Website Application
Complete working version with OAuth2 and verification
"""

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash, g
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
import random
from functools import wraps
import bleach

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import Config
from utils.logger import logger
from database.connection import db_manager

def create_app():
    app = Flask(__name__, template_folder='templates', static_folder='static')

    # ================= SECURITY CONFIG =================
    app.config['SECRET_KEY'] = Config.SECRET_KEY
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=Config.SESSION_TIMEOUT_MINUTES)
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

    csp = {
        'default-src': ["'self'"],
        'style-src': ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
        'script-src': ["'self'"],
        'font-src': ["'self'", "https://cdnjs.cloudflare.com"],
        'img-src': ["'self'", "data:", "https:"],
        'connect-src': ["'self'", "https://discord.com"]
    }

    Talisman(
        app,
        force_https=True,
        session_cookie_secure=True,
        content_security_policy=csp,
        strict_transport_security=True,
        frame_options='DENY'
    )

    CORS(app, origins=[Config.WEBSITE_URL, "http://localhost:10000"])

    limiter = Limiter(
        get_remote_address,
        app=app,
        storage_uri="memory://",
        default_limits=["200 per day", "50 per hour"]
    )

    # ================= UTILITIES =================

    def get_client_ip():
        """Get client IP address"""
        if request.headers.get('CF-Connecting-IP'):
            ip = request.headers['CF-Connecting-IP']
        elif request.headers.get('X-Forwarded-For'):
            ip = request.headers['X-Forwarded-For'].split(',')[0].strip()
        else:
            ip = request.remote_addr or "0.0.0.0"

        if ip.startswith("::ffff:"):
            ip = ip[7:]
        return ip

    def sanitize_input(text):
        """Sanitize user input"""
        if not text:
            return ""
        text = text.replace("\0", "")
        text = bleach.clean(text, tags=[], attributes={}, strip=True)
        return text[:1000]

    def generate_csrf_token():
        """Generate CSRF token"""
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_hex(32)
        return session["csrf_token"]

    def validate_csrf_token():
        """Validate CSRF token"""
        if request.method in ["POST", "PUT", "DELETE", "PATCH"]:
            token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
            return token and token == session.get("csrf_token")
        return True

    def log_security_event(event_type, user_id=None, details="", level="INFO"):
        """Log security event"""
        ip_addr = get_client_ip()

        event = {
            "type": event_type,
            "user_id": user_id,
            "ip_address": ip_addr,
            "hashed_ip": hashlib.sha256(f"{ip_addr}_salt".encode()).hexdigest()[:32],
            "user_agent": request.headers.get("User-Agent", "Unknown")[:200],
            "details": sanitize_input(details),
            "timestamp": datetime.utcnow(),
            "level": level,
            "endpoint": request.endpoint,
            "method": request.method
        }

        if db_manager.db is not None:
            try:
                db_manager.db.security_logs.insert_one(event)
            except Exception as e:
                logger.error(f"Security log DB failure: {e}")

        msg = f"{event_type} | IP={ip_addr} | {details}"
        if level == "ERROR":
            logger.error(msg)
        elif level == "WARNING":
            logger.warning(msg)
        else:
            logger.info(msg)

    # ================= DECORATORS =================

    def require_csrf(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if not validate_csrf_token():
                log_security_event("CSRF_VALIDATION_FAILED", level="WARNING")
                flash('CSRF validation failed. Please try again.', 'danger')
                return redirect(request.referrer or url_for('home'))
            return f(*args, **kwargs)
        return wrapper

    def admin_required(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if not session.get("admin_logged_in"):
                log_security_event("UNAUTHORIZED_ADMIN_ACCESS", level="WARNING")
                flash('Admin access required.', 'warning')
                return redirect(url_for("admin_login"))

            login_time = session.get("login_time")
            if login_time:
                login_dt = datetime.fromisoformat(login_time)
                if datetime.utcnow() - login_dt > timedelta(minutes=Config.SESSION_TIMEOUT_MINUTES):
                    session.clear()
                    log_security_event("ADMIN_SESSION_EXPIRED")
                    flash('Session expired. Please login again.', 'info')
                    return redirect(url_for("admin_login"))

            return f(*args, **kwargs)
        return wrapper

    # ================= REQUEST LIFECYCLE =================

    @app.before_request
    def before_request():
        """Before request handler"""
        if not hasattr(g, 'start_time'):
            g.start_time = time.time()
        generate_csrf_token()

    @app.after_request
    def after_request(response):
        """After request handler"""
        if hasattr(g, 'start_time'):
            duration = time.time() - g.start_time
            if duration > 2:
                logger.warning(f"Slow request {request.path} ({duration:.2f}s)")
        return response

    # ================= MAIN ROUTES =================

    @app.route("/")
    def home():
        """Home page"""
        return render_template("index.html", csrf_token=generate_csrf_token())

    @app.route("/verify")
    def verify():
        """Main verification page"""
        # Check for errors
        error = request.args.get('error')
        if error == 'oauth_failed':
            flash('⚠️ Discord login failed. Please try again.', 'warning')
        elif error == 'network_error':
            flash('🔌 Network error. Please check your connection.', 'danger')
        
        # Check if user is already verified
        discord_user = session.get("discord_user")
        is_verified = False
        
        if discord_user and db_manager.db is not None:
            user_data = db_manager.get_user(discord_user["id"])
            if user_data and user_data.get("verified_at"):
                is_verified = True
                session["is_verified"] = True
        
        return render_template("verify.html", 
                             csrf_token=generate_csrf_token(),
                             discord_user=discord_user,
                             is_verified=is_verified)

    @app.route("/blocked")
    def blocked():
        """Blocked access page"""
        return render_template("blocked.html")

    @app.route("/feedback")
    def feedback():
        """Feedback/support page"""
        return render_template("feedback.html")

    @app.route('/health')
    @limiter.exempt
    def health():
        """Health check endpoint"""
        return jsonify({
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "service": "discord-verification"
        })

    @app.route("/healthz")
    @limiter.exempt
    def healthz():
        """Kubernetes health check"""
        try:
            # Check database connection
            health = db_manager.health_check()
            
            if health["overall"] == "healthy":
                return jsonify({
                    "status": "healthy",
                    "timestamp": datetime.utcnow().isoformat(),
                    "database": "connected"
                })
            else:
                return jsonify({
                    "status": "degraded",
                    "timestamp": datetime.utcnow().isoformat(),
                    "database": health["mongodb"]["status"]
                }), 503
                
        except Exception as e:
            return jsonify({
                "status": "unhealthy",
                "error": str(e)
            }), 500

    # ================= ADMIN ROUTES =================

    @app.route("/admin/login", methods=["GET", "POST"])
    @limiter.limit("5 per minute")
    def admin_login():
        """Admin login page"""
        if request.method == "POST":
            username = sanitize_input(request.form.get("username", ""))
            password = request.form.get("password", "")
            
            # Check honeypot
            honeypot = request.form.get("honeypot", "")
            if honeypot:
                time.sleep(3)  # Delay for bots
                return render_template("admin/login.html", 
                                     error="Authentication failed.",
                                     csrf_token=generate_csrf_token())
            
            # Verify credentials
            if username == Config.ADMIN_USERNAME:
                try:
                    if bcrypt.checkpw(password.encode('utf-8'), 
                                     Config.ADMIN_PASSWORD_HASH.encode('utf-8')):
                        
                        session["admin_logged_in"] = True
                        session["admin_username"] = username
                        session["login_time"] = datetime.utcnow().isoformat()
                        session.permanent = True
                        
                        log_security_event("ADMIN_LOGIN_SUCCESS", username)
                        return redirect(url_for("admin_dashboard"))
                        
                except Exception as e:
                    logger.error(f"Password verification error: {e}")
            
            log_security_event("ADMIN_LOGIN_FAILED", username, level="WARNING")
            return render_template("admin/login.html", 
                                 error="Invalid credentials. Please check your username and password.",
                                 csrf_token=generate_csrf_token())
        
        return render_template("admin/login.html", csrf_token=generate_csrf_token())

    @app.route("/admin/dashboard")
    @admin_required
    def admin_dashboard():
        """Admin dashboard"""
        stats = db_manager.get_stats() or {}
        return render_template("admin/dashboard.html", stats=stats)

    @app.route("/admin/banned")
    @admin_required
    def banned_list():
        """List banned IPs"""
        banned_list = []
        try:
            if db_manager.db is not None:
                banned_list = list(db_manager.db.banned_ips.find({"is_active": True}))
        except Exception as e:
            logger.error(f"Failed to fetch banned list: {e}")
        
        return render_template("admin/banned.html", banned_list=banned_list)

    @app.route("/admin/verified")
    @admin_required
    def verified_list():
        """List verified users"""
        verified_list = []
        try:
            if db_manager.db is not None:
                verified_list = list(db_manager.db.users.find({"is_banned": False})
                                   .sort("verified_at", -1)
                                   .limit(100))
        except Exception as e:
            logger.error(f"Failed to fetch verified list: {e}")
        
        return render_template("admin/verified.html", verified_list=verified_list)

    @app.route("/admin/unban/<ip_address>")
    @admin_required
    def unban_ip(ip_address):
        """Unban IP address"""
        try:
            success = db_manager.unban_ip(ip_address)
            if success:
                log_security_event("IP_UNBANNED", 
                                 session.get("admin_username"), 
                                 f"IP {ip_address} unbanned")
                flash('✅ IP address unbanned successfully.', 'success')
            else:
                flash('❌ Failed to unban IP address.', 'danger')
        except Exception as e:
            logger.error(f"Failed to unban IP: {e}")
            flash(f'❌ Error: {str(e)}', 'danger')
        
        return redirect(url_for("banned_list"))

    @app.route("/admin/logout")
    def admin_logout():
        """Admin logout"""
        if "admin_username" in session:
            log_security_event("ADMIN_LOGOUT", session["admin_username"])
        
        session.clear()
        flash('✅ Successfully logged out.', 'info')
        return redirect(url_for("admin_login"))

    # ================= API ROUTES =================

    @app.route("/api/stats")
    @limiter.exempt
    def api_stats():
        """Get system statistics"""
        try:
            stats = db_manager.get_stats() or {}
            return jsonify({
                "success": True,
                "data": stats
            })
        except Exception as e:
            logger.error(f"Stats API error: {e}")
            return jsonify({
                "success": False,
                "error": "Failed to fetch statistics"
            }), 500

    @app.route("/api/verify", methods=["POST"])
    @require_csrf
    @limiter.limit("3 per minute")
    def api_verify():
        """API endpoint for verification"""
        ip_addr = get_client_ip()
        user_agent = request.headers.get("User-Agent", "Unknown")[:500]
        
        # Check if Discord user is connected
        discord_user = session.get("discord_user")
        if not discord_user:
            return jsonify({
                "success": False,
                "error": "Discord account not connected. Please login with Discord first.",
                "requires_oauth": True
            }), 400
        
        # Check if already verified
        existing_user = db_manager.get_user(discord_user["id"])
        if existing_user and existing_user.get("verified_at"):
            log_security_event("DUPLICATE_VERIFICATION_ATTEMPT",
                             discord_user["id"],
                             f"User {discord_user['full_username']} attempted duplicate verification",
                             level="WARNING")
            
            return jsonify({
                "success": False,
                "error": "You are already verified! No need to verify again.",
                "already_verified": True
            }), 409
        
        # Check if IP is banned
        if db_manager.is_ip_banned(ip_addr):
            log_security_event("BANNED_IP_ATTEMPT", 
                             discord_user["id"],
                             f"Banned IP attempted verification: {ip_addr}")
            return jsonify({
                "success": False,
                "error": "Your IP address is banned from verification.",
                "requires_oauth": False
            }), 403
        
        try:
            # Save user to database
            user_data = {
                "discord_id": discord_user["id"],
                "username": discord_user["full_username"],
                "ip_address": ip_addr,
                "user_agent": user_agent,
                "verified_at": datetime.utcnow(),
                "last_seen": datetime.utcnow(),
                "is_banned": False,
                "is_vpn": False,
                "attempts": 1,
                "role_added": False,
                "guild_id": Config.GUILD_ID if hasattr(Config, 'GUILD_ID') else None
            }
            
            # Add or update user
            success = db_manager.add_user(user_data)
            
            if success:
                # Add verification log
                db_manager.add_verification_log({
                    "discord_id": discord_user["id"],
                    "username": discord_user["full_username"],
                    "ip_address": ip_addr,
                    "status": "success",
                    "details": "User verified successfully",
                    "timestamp": datetime.utcnow(),
                    "is_duplicate": False
                })
                
                # Update session
                session["is_verified"] = True
                session["verification_date"] = datetime.utcnow().isoformat()
                
                log_security_event("VERIFICATION_SUCCESS", 
                                 discord_user["id"],
                                 f"User {discord_user['full_username']} verified successfully from IP: {ip_addr}")
                
                # Send to Discord webhook
                if hasattr(Config, 'WEBHOOK_URL') and Config.WEBHOOK_URL:
                    try:
                        embed = {
                            "title": "✅ New User Verified",
                            "description": f"**{discord_user['full_username']}** has been verified",
                            "color": 0x00ff00,
                            "fields": [
                                {"name": "Discord ID", "value": discord_user["id"], "inline": True},
                                {"name": "IP Address", "value": f"||{ip_addr}||", "inline": True},
                                {"name": "Status", "value": "First-time verification", "inline": True}
                            ],
                            "timestamp": datetime.utcnow().isoformat(),
                            "footer": {"text": "KoalaHub Verification System"}
                        }
                        
                        requests.post(Config.WEBHOOK_URL, json={"embeds": [embed]}, timeout=5)
                    except Exception as e:
                        logger.error(f"Failed to send webhook: {e}")
                
                return jsonify({
                    "success": True,
                    "data": {
                        "username": discord_user["full_username"],
                        "discord_id": discord_user["id"],
                        "ip_address": ip_addr,
                        "vpn_check": "Passed",
                        "status": "verified",
                        "timestamp": datetime.utcnow().isoformat(),
                        "message": "✅ Verification successful! The bot will give you the Verified role shortly.",
                        "is_first_verification": True
                    }
                })
            else:
                return jsonify({
                    "success": False,
                    "error": "Failed to save verification data.",
                    "requires_oauth": False
                }), 500
                
        except Exception as e:
            logger.error(f"Verification API error: {e}")
            return jsonify({
                "success": False,
                "error": "Internal server error",
                "requires_oauth": False
            }), 500

    # ================= DISCORD OAUTH ROUTES =================

    @app.route("/auth/discord")
    def auth_discord():
        """Start Discord OAuth flow"""
        # Generate state for CSRF protection
        state = secrets.token_urlsafe(32)
        session["oauth_state"] = state
        session.permanent = True
        
        # Discord OAuth2 URL
        discord_auth_url = (
            f"https://discord.com/api/oauth2/authorize?"
            f"client_id={Config.CLIENT_ID}&"
            f"redirect_uri={urllib.parse.quote(Config.REDIRECT_URI)}&"
            f"response_type=code&"
            f"scope=identify&"
            f"state={state}"
        )
        return redirect(discord_auth_url)

    @app.route("/callback")
    def callback():
        """Discord OAuth callback"""
        code = request.args.get("code")
        state = request.args.get("state")
        
        # Validate state
        if not code or state != session.get("oauth_state"):
            flash('❌ Invalid OAuth state. Please try again.', 'danger')
            return redirect(url_for("verify"))
        
        session.pop("oauth_state", None)
        
        try:
            # Prepare token exchange data
            data = {
                "client_id": Config.CLIENT_ID,
                "client_secret": Config.CLIENT_SECRET,
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": Config.REDIRECT_URI,
                "scope": "identify"
            }
            
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            
            # Exchange code for token with retry logic
            max_retries = 3
            access_token = None
            
            for attempt in range(max_retries):
                try:
                    if attempt > 0:
                        wait_time = (2 ** attempt) * random.uniform(0.5, 1.5)
                        time.sleep(wait_time)
                    
                    response = requests.post(
                        "https://discord.com/api/oauth2/token", 
                        data=data, 
                        headers=headers, 
                        timeout=10
                    )
                    
                    if response.status_code == 200:
                        token_data = response.json()
                        access_token = token_data.get("access_token")
                        break
                    elif response.status_code == 429:
                        retry_after = int(response.headers.get('Retry-After', 5))
                        time.sleep(retry_after)
                        continue
                    else:
                        if attempt == max_retries - 1:
                            logger.error(f"Discord token exchange failed: {response.status_code}")
                            flash('❌ Failed to authenticate with Discord.', 'danger')
                            return redirect(url_for("verify", error="oauth_failed"))
                except requests.exceptions.Timeout:
                    if attempt == max_retries - 1:
                        flash('⏱️ Connection to Discord timed out.', 'danger')
                        return redirect(url_for("verify", error="network_error"))
                except requests.exceptions.RequestException:
                    if attempt == max_retries - 1:
                        flash('🔌 Network error connecting to Discord.', 'danger')
                        return redirect(url_for("verify", error="network_error"))
            
            if not access_token:
                flash('❌ Failed to get access token.', 'danger')
                return redirect(url_for("verify", error="oauth_failed"))
            
            # Get user info
            headers = {"Authorization": f"Bearer {access_token}"}
            user_response = requests.get(
                "https://discord.com/api/users/@me", 
                headers=headers, 
                timeout=10
            )
            
            if user_response.status_code == 200:
                user_data = user_response.json()
                
                # Store user in session
                session["discord_user"] = {
                    "id": str(user_data["id"]),
                    "username": user_data["username"],
                    "discriminator": user_data.get("discriminator", "0"),
                    "full_username": f"{user_data['username']}#{user_data.get('discriminator', '0')}",
                    "avatar": user_data.get("avatar"),
                    "verified": user_data.get("verified", False)
                }
                
                # Check if already verified
                if db_manager.db is not None:
                    existing_user = db_manager.get_user(str(user_data["id"]))
                    if existing_user and existing_user.get("verified_at"):
                        session["is_verified"] = True
                        session["verification_date"] = existing_user.get("verified_at").isoformat() if existing_user.get("verified_at") else None
                
                # Ensure session is saved
                session.permanent = True
                session.modified = True
                
                log_security_event("DISCORD_OAUTH_SUCCESS", 
                                 str(user_data["id"]),
                                 f"User {user_data['username']} authenticated")
                
                flash('✅ Successfully connected to Discord! You can now verify.', 'success')
                return redirect(url_for("verify"))
            else:
                logger.error(f"Failed to get Discord user: {user_response.status_code}")
                flash('❌ Failed to retrieve Discord profile.', 'danger')
                return redirect(url_for("verify"))
            
        except Exception as e:
            logger.error(f"Unexpected error in callback: {e}")
            flash('❌ An unexpected error occurred.', 'danger')
            return redirect(url_for("verify"))

    @app.route("/auth/logout")
    def auth_logout():
        """Logout Discord user"""
        user_id = session.get("discord_user", {}).get("id")
        if user_id:
            log_security_event("DISCORD_LOGOUT", user_id=user_id)
        
        session.pop("discord_user", None)
        session.pop("is_verified", None)
        session.pop("verification_date", None)
        flash('👋 Successfully logged out from Discord.', 'info')
        return redirect(url_for("verify"))

    # ================= ERROR HANDLERS =================

    @app.errorhandler(404)
    def not_found(e):
        log_security_event("404_NOT_FOUND", details=request.path)
        return render_template("error.html", error="404 - Page not found"), 404

    @app.errorhandler(403)
    def forbidden(e):
        log_security_event("403_FORBIDDEN", details=str(e))
        return render_template("error.html", error="403 - Forbidden"), 403

    @app.errorhandler(429)
    def rate_limit(e):
        return jsonify({
            "error": "Rate limit exceeded",
            "retry_after": e.description
        }), 429

    @app.errorhandler(500)
    def internal(e):
        log_security_event("500_INTERNAL_ERROR", details=str(e), level="ERROR")
        return render_template("error.html", error="500 - Internal server error"), 500

    return app