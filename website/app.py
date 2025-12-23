"""
Discord Verification System - Website Application
Fixed version for Python 3.13 compatibility with all required routes
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
import bleach
import re

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import Config
from utils.logger import logger
from utils.password import PasswordManager
from utils.rate_limiter import rate_limiter
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
        if request.headers.get('CF-Connecting-IP'):
            ip = request.headers['CF-Connecting-IP']
        elif request.headers.get('X-Forwarded-For'):
            ip = request.headers['X-Forwarded-For'].split(',')[0].strip()
        else:
            ip = request.remote_addr or "0.0.0.0"

        if ip.startswith("::ffff:"):
            ip = ip[7:]
        if ":" in ip and ip.count(":") == 1:
            ip = ip.split(":")[0]

        return ip

    def sanitize_input(text):
        if not text:
            return ""
        text = text.replace("\0", "")
        text = bleach.clean(text, tags=[], attributes={}, strip=True)
        return text[:1000]

    def generate_csrf_token():
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_hex(32)
        return session["csrf_token"]

    def validate_csrf_token():
        if request.method in ["POST", "PUT", "DELETE", "PATCH"]:
            token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
            return token and token == session.get("csrf_token")
        return True

    def log_security_event(event_type, user_id=None, details="", level="INFO"):
        ip_addr = get_client_ip()

        event = {
            "type": event_type,
            "user_id": user_id,
            "ip_address": ip_addr,
            "hashed_ip": PasswordManager.hash_ip(ip_addr),
            "user_agent": request.headers.get("User-Agent", "Unknown")[:200],
            "details": sanitize_input(details),
            "timestamp": datetime.utcnow(),
            "level": level,
            "endpoint": request.endpoint,
            "method": request.method
        }

        # FIXED LINE: Use "is not None" instead of boolean test
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
                abort(403)
            return f(*args, **kwargs)
        return wrapper

    def admin_required(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if not session.get("admin_logged_in"):
                log_security_event("UNAUTHORIZED_ADMIN_ACCESS", level="WARNING")
                return redirect(url_for("admin_login"))

            login_time = session.get("login_time")
            if login_time:
                if datetime.utcnow() - datetime.fromisoformat(login_time) > timedelta(
                    minutes=Config.SESSION_TIMEOUT_MINUTES
                ):
                    session.clear()
                    log_security_event("ADMIN_SESSION_EXPIRED")
                    return redirect(url_for("admin_login"))

            return f(*args, **kwargs)
        return wrapper

    # ================= REQUEST LIFECYCLE =================

    @app.before_request
    def before_request():
        g.start_time = time.time()
        g.client_ip = get_client_ip()
        generate_csrf_token()

    @app.after_request
    def after_request(response):
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
        return render_template("verify.html", csrf_token=generate_csrf_token())

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
        return jsonify(status="healthy", timestamp=datetime.utcnow().isoformat())

    @app.route("/healthz")
    @limiter.exempt
    def healthz():
        """Kubernetes/container health check endpoint"""
        try:
            # Simple health check
            return jsonify({
                "status": "healthy",
                "timestamp": datetime.utcnow().isoformat(),
                "service": "discord-verification"
            })
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
            
            # Rate limiting check
            ip_addr = get_client_ip()
            
            # Check credentials
            if username == Config.ADMIN_USERNAME and bcrypt.checkpw(
                password.encode("utf-8"), 
                Config.ADMIN_PASSWORD_HASH.encode("utf-8")
            ):
                session["admin_logged_in"] = True
                session["admin_username"] = username
                session["login_time"] = datetime.utcnow().isoformat()
                session.permanent = True
                
                log_security_event("ADMIN_LOGIN_SUCCESS", username)
                return redirect(url_for("admin_dashboard"))
            else:
                log_security_event("ADMIN_LOGIN_FAILED", username, level="WARNING")
                return render_template("admin/login.html", 
                                     error="Invalid credentials")
        
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
            db_manager.unban_ip(ip_address)
            log_security_event("IP_UNBANNED", session.get("admin_username"), 
                             f"IP {ip_address} unbanned")
        except Exception as e:
            logger.error(f"Failed to unban IP: {e}")
        
        return redirect(url_for("banned_list"))

    @app.route("/admin/logout")
    def admin_logout():
        """Admin logout"""
        if "admin_username" in session:
            log_security_event("ADMIN_LOGOUT", session["admin_username"])
        
        session.clear()
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
                "error": str(e)
            }), 500

    @app.route("/api/verify", methods=["POST"])
    @require_csrf
    @limiter.limit("3 per minute")
    def api_verify():
        """API endpoint for verification"""
        ip_addr = get_client_ip()
        
        # Rate limiting
        rate_check = rate_limiter.check_rate_limit(
            f"verify_{ip_addr}", 
            "verification", 
            3,  # 3 attempts
            60   # 1 minute
        )
        
        if not rate_check["allowed"]:
            return jsonify({
                "success": False,
                "error": f"Rate limit exceeded. Try again in {rate_check['retry_after']} seconds.",
                "requires_oauth": False
            }), 429
        
        # Check if IP is banned
        if db_manager.is_ip_banned(ip_addr):
            log_security_event("BANNED_IP_ATTEMPT", None, f"Banned IP attempted verification: {ip_addr}")
            return jsonify({
                "success": False,
                "error": "Your IP address is banned from verification.",
                "requires_oauth": False
            }), 403
        
        # For demo purposes, return success
        # In production, you would verify Discord OAuth2 here
        
        return jsonify({
            "success": True,
            "data": {
                "username": "DemoUser",
                "vpn_check": "Passed",
                "status": "verified"
            }
        })

    # ================= DISCORD OAUTH ROUTES =================

    @app.route("/auth/discord")
    def auth_discord():
        """Start Discord OAuth flow"""
        # Discord OAuth2 URL
        discord_auth_url = f"https://discord.com/api/oauth2/authorize?client_id={Config.CLIENT_ID}&redirect_uri={urllib.parse.quote(Config.REDIRECT_URI)}&response_type=code&scope=identify"
        return redirect(discord_auth_url)

    @app.route("/callback")
    def callback():
        """Discord OAuth callback"""
        code = request.args.get("code")
        
        if not code:
            return redirect(url_for("verify"))
        
        try:
            # Exchange code for token
            data = {
                "client_id": Config.CLIENT_ID,
                "client_secret": Config.CLIENT_SECRET,
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": Config.REDIRECT_URI,
                "scope": "identify"
            }
            
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            response = requests.post("https://discord.com/api/oauth2/token", data=data, headers=headers)
            
            if response.status_code != 200:
                logger.error(f"Discord token exchange failed: {response.text}")
                return redirect(url_for("verify"))
            
            token_data = response.json()
            access_token = token_data["access_token"]
            
            # Get user info
            headers = {"Authorization": f"Bearer {access_token}"}
            user_response = requests.get("https://discord.com/api/users/@me", headers=headers)
            
            if user_response.status_code != 200:
                logger.error(f"Failed to get Discord user: {user_response.text}")
                return redirect(url_for("verify"))
            
            user_data = user_response.json()
            
            # Store user in session
            session["discord_user"] = {
                "id": str(user_data["id"]),
                "username": user_data["username"],
                "discriminator": user_data.get("discriminator", "0"),
                "full_username": f"{user_data['username']}#{user_data.get('discriminator', '0')}",
                "avatar": user_data.get("avatar")
            }
            
            return redirect(url_for("verify"))
            
        except Exception as e:
            logger.error(f"Discord OAuth error: {e}")
            return redirect(url_for("verify"))

    @app.route("/auth/logout")
    def auth_logout():
        """Logout Discord user"""
        session.pop("discord_user", None)
        return redirect(url_for("verify"))

    # ================= ERROR HANDLERS =================

    @app.errorhandler(404)
    def not_found(e):
        log_security_event("404_NOT_FOUND", details=request.path)
        return render_template("error.html", error_code=404), 404

    @app.errorhandler(403)
    def forbidden(e):
        log_security_event("403_FORBIDDEN", details=str(e))
        return render_template("error.html", error_code=403), 403

    @app.errorhandler(429)
    def rate_limit(e):
        return jsonify(error="Rate limit exceeded"), 429

    @app.errorhandler(500)
    def internal(e):
        log_security_event("500_INTERNAL_ERROR", details=str(e), level="ERROR")
        return render_template("error.html", error_code=500), 500

    return app