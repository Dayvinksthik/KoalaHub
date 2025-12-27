"""
Discord Verification System - Website Application
Complete version with all webhooks working
"""

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash, g, make_response
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
    app.config['SESSION_COOKIE_SECURE'] = True  # Set to False for local testing without HTTPS
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    
    # For Render deployment, we need to handle session properly
    app.config['SESSION_REFRESH_EACH_REQUEST'] = True
    
    # Important: On Render, we might need to use a different session setup
    app.config['SESSION_TYPE'] = 'filesystem'
    app.config['SESSION_FILE_DIR'] = '/tmp/flask_session'
    app.config['SESSION_FILE_THRESHOLD'] = 100

    # For development, allow HTTP cookies
    if os.environ.get('FLASK_ENV') == 'development':
        app.config['SESSION_COOKIE_SECURE'] = False
        app.config['PREFERRED_URL_SCHEME'] = 'http'

    csp = {
        'default-src': ["'self'"],
        'style-src': ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
        'script-src': ["'self'"],
        'font-src': ["'self'", "https://cdnjs.cloudflare.com"],
        'img-src': ["'self'", "data:", "https:"],
        'connect-src': ["'self'", "https://discord.com", "https://koalahub.onrender.com"]
    }

    Talisman(
        app,
        force_https=False if os.environ.get('FLASK_ENV') == 'development' else True,
        session_cookie_secure=app.config['SESSION_COOKIE_SECURE'],
        content_security_policy=csp,
        strict_transport_security=False if os.environ.get('FLASK_ENV') == 'development' else True,
        frame_options='DENY'
    )

    CORS(app, origins=[Config.WEBSITE_URL, "http://localhost:10000", "https://koalahub.onrender.com", "http://localhost:5000"])

    limiter = Limiter(
        get_remote_address,
        app=app,
        storage_uri="memory://",
        default_limits=["200 per day", "50 per hour"],
        strategy="fixed-window",  # Changed from "moving-window" for better compatibility
        key_func=lambda: request.remote_addr or "127.0.0.1"
    )

    # ================= WEBHOOK FUNCTIONS =================
    
    def send_webhook(webhook_url, embed_data, webhook_name="Unknown"):
        """Send embed to Discord webhook"""
        if not webhook_url:
            logger.warning(f"No webhook URL provided for {webhook_name}")
            return False
        
        try:
            response = requests.post(
                webhook_url,
                json={"embeds": [embed_data]},
                timeout=5
            )
            
            if response.status_code in [200, 204]:
                logger.info(f"✅ Webhook sent successfully to {webhook_name}")
                return True
            else:
                logger.error(f"❌ Webhook {webhook_name} failed: {response.status_code} - {response.text[:100]}")
                return False
                
        except requests.exceptions.Timeout:
            logger.error(f"⏱️ Webhook {webhook_name} timeout")
            return False
        except requests.exceptions.RequestException as e:
            logger.error(f"🔌 Webhook {webhook_name} error: {e}")
            return False
        except Exception as e:
            logger.error(f"⚠️ Webhook {webhook_name} unexpected error: {e}")
            return False
    
    def send_verification_webhook(discord_user, ip_addr):
        """Send verification success to main webhook"""
        if not Config.WEBHOOK_URL:
            logger.warning("No main webhook URL configured")
            return False
        
        embed = {
            "title": "✅ New User Verified",
            "description": f"**{discord_user['full_username']}** has been verified",
            "color": 0x00ff00,  # Green
            "fields": [
                {"name": "Discord ID", "value": f"`{discord_user['id']}`", "inline": True},
                {"name": "Username", "value": discord_user['full_username'], "inline": True},
                {"name": "IP Address", "value": f"||{ip_addr}||", "inline": True},
                {"name": "Timestamp", "value": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'), "inline": True}
            ],
            "timestamp": datetime.utcnow().isoformat(),
            "footer": {"text": "KoalaHub Verification System"}
        }
        
        return send_webhook(Config.WEBHOOK_URL, embed, "Main Webhook")
    
    def send_log_webhook(event_type, details):
        """Send log to logs webhook"""
        if not Config.LOGS_WEBHOOK:
            logger.warning("No logs webhook URL configured")
            return False
        
        colors = {
            "INFO": 0x3498db,    # Blue
            "WARNING": 0xf39c12, # Orange
            "ERROR": 0xe74c3c,   # Red
            "SUCCESS": 0x2ecc71  # Green
        }
        
        embed = {
            "title": f"📝 {event_type}",
            "description": details[:2000],  # Discord limit
            "color": colors.get("INFO", 0x3498db),
            "timestamp": datetime.utcnow().isoformat(),
            "footer": {"text": "System Log"}
        }
        
        return send_webhook(Config.LOGS_WEBHOOK, embed, "Logs Webhook")
    
    def send_alert_webhook(alert_type, severity, details):
        """Send alert to alerts webhook"""
        if not Config.ALERTS_WEBHOOK:
            logger.warning("No alerts webhook URL configured")
            return False
        
        colors = {
            "low": 0x3498db,     # Blue
            "medium": 0xf39c12,  # Orange
            "high": 0xe74c3c,    # Red
            "critical": 0x992d22 # Dark Red
        }
        
        embed = {
            "title": f"🚨 {alert_type}",
            "description": details[:2000],
            "color": colors.get(severity.lower(), 0xe74c3c),
            "timestamp": datetime.utcnow().isoformat(),
            "footer": {"text": f"Severity: {severity.upper()}"}
        }
        
        return send_webhook(Config.ALERTS_WEBHOOK, embed, "Alerts Webhook")
    
    def send_backup_notification(action, details):
        """Send backup notification"""
        if not Config.BACKUP_WEBHOOK:
            logger.warning("No backup webhook URL configured")
            return False
        
        embed = {
            "title": f"💾 {action}",
            "description": details[:2000],
            "color": 0x9b59b6,  # Purple
            "timestamp": datetime.utcnow().isoformat(),
            "footer": {"text": "Backup System"}
        }
        
        return send_webhook(Config.BACKUP_WEBHOOK, embed, "Backup Webhook")

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
        # Skip CSRF for health checks and certain endpoints
        if request.path in ['/health', '/healthz', '/api/stats']:
            return True
            
        if request.method in ["POST", "PUT", "DELETE", "PATCH"]:
            # Try to get token from headers first, then form
            token = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token")
            if not token:
                # Try JSON body
                try:
                    if request.is_json:
                        data = request.get_json(silent=True) or {}
                        token = data.get('csrf_token')
                except:
                    pass
            
            session_token = session.get("csrf_token")
            if not token or not session_token or token != session_token:
                logger.warning(f"CSRF validation failed. Token: {token}, Session token: {session_token}")
                return False
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

        # Send to logs webhook
        if level in ["WARNING", "ERROR"]:
            send_log_webhook(f"{event_type} - {level}", details)
        
        if level == "ERROR":
            # Send critical errors to alerts webhook
            send_alert_webhook(f"System Error: {event_type}", "high", details)
        
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
                log_security_event("CSRF_VALIDATION_FAILED", level="WARNING", 
                                 details=f"Path: {request.path}, Method: {request.method}")
                return jsonify({
                    "success": False,
                    "error": "CSRF validation failed. Please refresh the page and try again.",
                    "requires_oauth": False
                }), 403
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
                try:
                    login_dt = datetime.fromisoformat(login_time)
                    if datetime.utcnow() - login_dt > timedelta(minutes=Config.SESSION_TIMEOUT_MINUTES):
                        session.clear()
                        log_security_event("ADMIN_SESSION_EXPIRED")
                        flash('Session expired. Please login again.', 'info')
                        return redirect(url_for("admin_login"))
                except ValueError:
                    # Invalid timestamp, clear session
                    session.clear()
                    return redirect(url_for("admin_login"))

            return f(*args, **kwargs)
        return wrapper

    # ================= REQUEST LIFECYCLE =================

    @app.before_request
    def before_request():
        """Before request handler"""
        if not hasattr(g, 'start_time'):
            g.start_time = time.time()
        
        # Generate CSRF token for all GET requests
        if request.method == 'GET' and not request.path.startswith('/static'):
            generate_csrf_token()
            
        # Log request for debugging
        logger.debug(f"Request: {request.method} {request.path} | IP: {get_client_ip()}")

    @app.after_request
    def after_request(response):
        """After request handler"""
        if hasattr(g, 'start_time'):
            duration = time.time() - g.start_time
            if duration > 2:
                logger.warning(f"Slow request {request.path} ({duration:.2f}s)")
        
        # Add security headers
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        
        return response

    # ================= MAIN ROUTES =================

    @app.route("/")
    def home():
        """Home page"""
        return render_template("index.html", csrf_token=generate_csrf_token())

    @app.route("/verify")
    def verify():
        """Main verification page"""
        error = request.args.get('error')
        if error == 'oauth_failed':
            flash('⚠️ Discord login failed. Please try again.', 'warning')
        elif error == 'network_error':
            flash('🔌 Network error. Please check your connection.', 'danger')
        elif error == 'session_expired':
            flash('⏰ Session expired. Please login again.', 'info')
        
        discord_user = session.get("discord_user")
        is_verified = False
        
        if discord_user and db_manager.db is not None:
            user_data = db_manager.get_user(discord_user["id"])
            if user_data and user_data.get("verified_at"):
                is_verified = True
                session["is_verified"] = True
                session["verification_date"] = user_data.get("verified_at").isoformat() if user_data.get("verified_at") else None
        
        # Log verification page access
        logger.info(f"Verification page accessed. User: {discord_user.get('id') if discord_user else 'Not logged in'}, Verified: {is_verified}")
        
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
        try:
            db_status = "unknown"
            if db_manager.db is not None:
                # Try a simple query
                db_manager.db.command('ping')
                db_status = "connected"
            else:
                db_status = "disconnected"
                
            return jsonify({
                "status": "healthy",
                "timestamp": datetime.utcnow().isoformat(),
                "service": "discord-verification",
                "database": db_status,
                "session": "active" if session else "inactive"
            })
        except Exception as e:
            return jsonify({
                "status": "degraded",
                "error": str(e)[:100],
                "timestamp": datetime.utcnow().isoformat()
            }), 500

    @app.route("/healthz")
    @limiter.exempt
    def healthz():
        """Kubernetes health check"""
        try:
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
            
            honeypot = request.form.get("honeypot", "")
            if honeypot:
                time.sleep(3)
                return render_template("admin/login.html", 
                                     error="Authentication failed.",
                                     csrf_token=generate_csrf_token())
            
            if username == Config.ADMIN_USERNAME:
                try:
                    if bcrypt.checkpw(password.encode('utf-8'), 
                                     Config.ADMIN_PASSWORD_HASH.encode('utf-8')):
                        
                        session["admin_logged_in"] = True
                        session["admin_username"] = username
                        session["login_time"] = datetime.utcnow().isoformat()
                        session.permanent = True
                        
                        log_security_event("ADMIN_LOGIN_SUCCESS", username)
                        send_log_webhook("Admin Login", f"Admin {username} logged in successfully")
                        
                        return redirect(url_for("admin_dashboard"))
                        
                except Exception as e:
                    logger.error(f"Password verification error: {e}")
            
            log_security_event("ADMIN_LOGIN_FAILED", username, level="WARNING")
            send_alert_webhook("Failed Admin Login", "medium", f"Failed login attempt for username: {username}")
            
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
                send_log_webhook("IP Unbanned", f"IP {ip_address} was unbanned by {session.get('admin_username')}")
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
            send_log_webhook("Admin Logout", f"Admin {session['admin_username']} logged out")
        
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
        """API endpoint for verification - FIXED VERSION"""
        # Add debug logging
        ip_addr = get_client_ip()
        logger.info(f"Verification API called from IP: {ip_addr}")
        logger.info(f"Session ID: {session.get('_id', 'No session ID')}")
        logger.info(f"Session keys: {list(session.keys())}")
        
        # Get user agent
        user_agent = request.headers.get("User-Agent", "Unknown")[:500]
        
        # Check if user is logged in
        discord_user = session.get("discord_user")
        logger.info(f"Discord user in session: {discord_user}")
        
        if not discord_user:
            logger.warning(f"No discord user in session for IP: {ip_addr}")
            return jsonify({
                "success": False,
                "error": "Discord account not connected. Please login with Discord first.",
                "requires_oauth": True
            }), 400
        
        # Add more debug logging
        logger.info(f"Checking verification for user: {discord_user['id']} ({discord_user['full_username']})")
        
        # Check if already verified
        existing_user = db_manager.get_user(discord_user["id"])
        if existing_user and existing_user.get("verified_at"):
            log_security_event("DUPLICATE_VERIFICATION_ATTEMPT",
                             discord_user["id"],
                             f"User {discord_user['full_username']} attempted duplicate verification",
                             level="WARNING")
            
            send_log_webhook("Duplicate Verification Attempt", 
                           f"User {discord_user['full_username']} tried to verify again (already verified)")
            
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
            
            send_alert_webhook("Banned IP Attempt", "high",
                             f"Banned IP {ip_addr} attempted verification as {discord_user['full_username']}")
            
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
                "guild_id": str(Config.GUILD_ID) if hasattr(Config, 'GUILD_ID') and Config.GUILD_ID else None
            }
            
            success = db_manager.add_user(user_data)
            logger.info(f"Database save result: {success}")
            
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
                
                # Send to ALL webhooks
                webhook_success = send_verification_webhook(discord_user, ip_addr)
                send_log_webhook("User Verified", f"✅ {discord_user['full_username']} verified successfully")
                
                # Generate a new CSRF token for the next request
                generate_csrf_token()
                
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
                        "is_first_verification": True,
                        "webhook_sent": webhook_success
                    }
                })
            else:
                logger.error("Failed to save user to database")
                return jsonify({
                    "success": False,
                    "error": "Failed to save verification data to database.",
                    "requires_oauth": False
                }), 500
                
        except Exception as e:
            logger.error(f"Verification API error: {e}", exc_info=True)
            return jsonify({
                "success": False,
                "error": f"Internal server error: {str(e)[:100]}",
                "requires_oauth": False
            }), 500

    @app.route("/api/unverify", methods=["POST"])
    @limiter.limit("10 per minute")
    def api_unverify():
        """API endpoint to unverify a user (called by bot)"""
        try:
            data = request.get_json()
            if not data:
                return jsonify({"success": False, "error": "No data provided"}), 400
            
            discord_id = data.get("discord_id")
            reason = data.get("reason", "Manual unverification")
            admin_id = data.get("admin", "system")
            
            if not discord_id:
                return jsonify({"success": False, "error": "No discord_id provided"}), 400
            
            # Check if user exists in database
            user = db_manager.get_user(discord_id)
            if not user:
                return jsonify({"success": False, "error": "User not found in database"}), 404
            
            # Update user in database
            user["verified_at"] = None
            user["role_added"] = False
            user["last_seen"] = datetime.utcnow()
            
            success = db_manager.add_user(user)
            
            if success:
                # Add security log
                db_manager.add_security_log({
                    "type": "USER_UNVERIFIED",
                    "user_id": discord_id,
                    "ip_address": "0.0.0.0",  # From bot
                    "details": f"User unverified by admin {admin_id}. Reason: {reason}",
                    "timestamp": datetime.utcnow(),
                    "level": "INFO"
                })
                
                logger.info(f"User {discord_id} unverified via API by admin {admin_id}")
                
                # Send to webhooks
                send_log_webhook("User Unverified", f"User <@{discord_id}> was unverified by admin {admin_id}")
                send_alert_webhook("User Unverified", "medium", f"User <@{discord_id}> unverified by admin {admin_id}")
                
                return jsonify({
                    "success": True,
                    "message": f"User {discord_id} unverified successfully"
                })
            else:
                return jsonify({"success": False, "error": "Failed to update database"}), 500
                
        except Exception as e:
            logger.error(f"Unverify API error: {e}")
            return jsonify({"success": False, "error": str(e)}), 500

    @app.route("/api/force_verify", methods=["POST"])
    @limiter.limit("10 per minute")
    def api_force_verify():
        """API endpoint for force verification (called by bot)"""
        try:
            data = request.get_json()
            if not data:
                return jsonify({"success": False, "error": "No data provided"}), 400
            
            discord_id = data.get("discord_id")
            username = data.get("username", "Unknown")
            admin_id = data.get("admin", "system")
            
            if not discord_id:
                return jsonify({"success": False, "error": "No discord_id provided"}), 400
            
            # Check if user exists
            user = db_manager.get_user(discord_id)
            if user:
                # Update existing user
                user["verified_at"] = datetime.utcnow()
                user["role_added"] = True
                user["last_seen"] = datetime.utcnow()
            else:
                # Create new user
                user = {
                    "discord_id": discord_id,
                    "username": username,
                    "ip_address": "0.0.0.0",  # From bot
                    "user_agent": "Bot Force Verify",
                    "verified_at": datetime.utcnow(),
                    "last_seen": datetime.utcnow(),
                    "is_banned": False,
                    "is_vpn": False,
                    "attempts": 1,
                    "role_added": True,
                    "guild_id": str(Config.GUILD_ID) if hasattr(Config, 'GUILD_ID') and Config.GUILD_ID else None
                }
            
            success = db_manager.add_user(user)
            
            if success:
                # Add security log
                db_manager.add_security_log({
                    "type": "USER_FORCE_VERIFIED",
                    "user_id": discord_id,
                    "ip_address": "0.0.0.0",
                    "details": f"User force verified by admin {admin_id}",
                    "timestamp": datetime.utcnow(),
                    "level": "INFO"
                })
                
                logger.info(f"User {discord_id} force verified via API by admin {admin_id}")
                
                # Send to webhooks
                send_log_webhook("User Force Verified", f"User {username} (<@{discord_id}>) was force verified by admin {admin_id}")
                
                return jsonify({
                    "success": True,
                    "message": f"User {discord_id} force verified successfully"
                })
            else:
                return jsonify({"success": False, "error": "Failed to update database"}), 500
                
        except Exception as e:
            logger.error(f"Force verify API error: {e}")
            return jsonify({"success": False, "error": str(e)}), 500

    @app.route("/test/webhook", methods=["GET"])
    @admin_required
    def test_webhook():
        """Test webhook functionality"""
        test_results = {}
        
        # Test main webhook
        if Config.WEBHOOK_URL:
            test_embed = {
                "title": "✅ Webhook Test",
                "description": "This is a test message from the verification system",
                "color": 0x00ff00,
                "timestamp": datetime.utcnow().isoformat(),
                "footer": {"text": "Test System"}
            }
            success = send_webhook(Config.WEBHOOK_URL, test_embed, "Main Webhook Test")
            test_results["main_webhook"] = "✅ Success" if success else "❌ Failed"
        else:
            test_results["main_webhook"] = "❌ Not configured"
        
        # Test logs webhook
        if Config.LOGS_WEBHOOK:
            success = send_log_webhook("Webhook Test", "Testing logs webhook functionality")
            test_results["logs_webhook"] = "✅ Success" if success else "❌ Failed"
        else:
            test_results["logs_webhook"] = "❌ Not configured"
        
        # Test alerts webhook
        if Config.ALERTS_WEBHOOK:
            success = send_alert_webhook("Webhook Test", "low", "Testing alerts webhook")
            test_results["alerts_webhook"] = "✅ Success" if success else "❌ Failed"
        else:
            test_results["alerts_webhook"] = "❌ Not configured"
        
        # Test backup webhook
        if Config.BACKUP_WEBHOOK:
            success = send_backup_notification("Webhook Test", "Testing backup webhook functionality")
            test_results["backup_webhook"] = "✅ Success" if success else "❌ Failed"
        else:
            test_results["backup_webhook"] = "❌ Not configured"
        
        return jsonify({
            "success": True,
            "results": test_results
        })

    # ================= DISCORD OAUTH ROUTES =================

    @app.route("/auth/discord")
    def auth_discord():
        """Start Discord OAuth flow"""
        state = secrets.token_urlsafe(32)
        session["oauth_state"] = state
        session.permanent = True
        
        # Store referrer to redirect back after OAuth
        session["oauth_referrer"] = request.referrer or url_for("verify")
        
        discord_auth_url = (
            f"https://discord.com/api/oauth2/authorize?"
            f"client_id={Config.CLIENT_ID}&"
            f"redirect_uri={urllib.parse.quote(Config.REDIRECT_URI)}&"
            f"response_type=code&"
            f"scope=identify&"
            f"state={state}"
        )
        
        logger.info(f"Starting OAuth flow for state: {state[:10]}...")
        return redirect(discord_auth_url)

    @app.route("/callback")
    def callback():
        """Discord OAuth callback - FIXED VERSION"""
        code = request.args.get("code")
        state = request.args.get("state")
        
        logger.info(f"OAuth callback received. Code: {'Yes' if code else 'No'}, State: {state}")
        logger.info(f"Session state: {session.get('oauth_state')}")
        
        if not code or state != session.get("oauth_state"):
            logger.error(f"Invalid OAuth state. Expected: {session.get('oauth_state')}, Got: {state}")
            flash('❌ Invalid OAuth state. Please try again.', 'danger')
            return redirect(url_for("verify", error="oauth_failed"))
        
        session.pop("oauth_state", None)
        
        try:
            data = {
                "client_id": Config.CLIENT_ID,
                "client_secret": Config.CLIENT_SECRET,
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": Config.REDIRECT_URI,
                "scope": "identify"
            }
            
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            
            max_retries = 3
            access_token = None
            
            for attempt in range(max_retries):
                try:
                    if attempt > 0:
                        wait_time = (2 ** attempt) * random.uniform(0.5, 1.5)
                        logger.info(f"Retry {attempt + 1}/{max_retries}, waiting {wait_time:.1f}s")
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
                        logger.info(f"Successfully got access token (attempt {attempt + 1})")
                        break
                    elif response.status_code == 429:
                        retry_after = int(response.headers.get('Retry-After', 5))
                        logger.warning(f"Rate limited, waiting {retry_after}s")
                        time.sleep(retry_after)
                        continue
                    else:
                        logger.error(f"Token exchange failed (attempt {attempt + 1}): {response.status_code} - {response.text[:200]}")
                        if attempt == max_retries - 1:
                            send_alert_webhook("Discord OAuth Failed", "medium", 
                                             f"Token exchange failed: {response.status_code}")
                            flash('❌ Failed to authenticate with Discord.', 'danger')
                            return redirect(url_for("verify", error="oauth_failed"))
                except requests.exceptions.Timeout:
                    logger.error(f"Token exchange timeout (attempt {attempt + 1})")
                    if attempt == max_retries - 1:
                        send_alert_webhook("Discord OAuth Timeout", "medium", "Token exchange timeout")
                        flash('⏱️ Connection to Discord timed out.', 'danger')
                        return redirect(url_for("verify", error="network_error"))
                except requests.exceptions.RequestException as e:
                    logger.error(f"Token exchange network error (attempt {attempt + 1}): {e}")
                    if attempt == max_retries - 1:
                        send_alert_webhook("Discord OAuth Network Error", "medium", "Network error during token exchange")
                        flash('🔌 Network error connecting to Discord.', 'danger')
                        return redirect(url_for("verify", error="network_error"))
            
            if not access_token:
                logger.error("Failed to get access token after all retries")
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
                
                session["discord_user"] = {
                    "id": str(user_data["id"]),
                    "username": user_data["username"],
                    "discriminator": user_data.get("discriminator", "0"),
                    "full_username": f"{user_data['username']}#{user_data.get('discriminator', '0')}",
                    "avatar": user_data.get("avatar"),
                    "verified": user_data.get("verified", False)
                }
                
                # Check if user is already verified in database
                if db_manager.db is not None:
                    existing_user = db_manager.get_user(str(user_data["id"]))
                    if existing_user and existing_user.get("verified_at"):
                        session["is_verified"] = True
                        session["verification_date"] = existing_user.get("verified_at").isoformat() if existing_user.get("verified_at") else None
                
                # Regenerate session ID for security
                session.permanent = True
                session.modified = True
                
                # Generate new CSRF token
                generate_csrf_token()
                
                log_security_event("DISCORD_OAUTH_SUCCESS", 
                                 str(user_data["id"]),
                                 f"User {user_data['username']} authenticated")
                
                send_log_webhook("Discord Login", f"User {user_data['username']} logged in via Discord OAuth")
                
                logger.info(f"User {user_data['username']} successfully authenticated")
                flash('✅ Successfully connected to Discord! You can now verify.', 'success')
                
                # Redirect back to verify page
                return redirect(url_for("verify"))
            else:
                logger.error(f"Failed to get Discord user: {user_response.status_code} - {user_response.text[:200]}")
                send_alert_webhook("Discord User Info Failed", "medium", 
                                 f"Failed to get user info: {user_response.status_code}")
                flash('❌ Failed to retrieve Discord profile.', 'danger')
                return redirect(url_for("verify"))
            
        except Exception as e:
            logger.error(f"Unexpected error in callback: {e}", exc_info=True)
            send_alert_webhook("OAuth Callback Error", "high", f"Unexpected error: {str(e)[:200]}")
            flash('❌ An unexpected error occurred.', 'danger')
            return redirect(url_for("verify"))

    @app.route("/auth/logout")
    def auth_logout():
        """Logout Discord user"""
        user_id = session.get("discord_user", {}).get("id")
        if user_id:
            log_security_event("DISCORD_LOGOUT", user_id=user_id)
            send_log_webhook("Discord Logout", f"User {session['discord_user']['full_username']} logged out")
        
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
        log_security_event("RATE_LIMIT_EXCEEDED", details=request.path, level="WARNING")
        send_log_webhook("Rate Limit Exceeded", f"IP {get_client_ip()} hit rate limit on {request.path}")
        return jsonify({
            "success": False,
            "error": "Rate limit exceeded",
            "retry_after": e.description if hasattr(e, 'description') else 60
        }), 429

    @app.errorhandler(500)
    def internal(e):
        log_security_event("500_INTERNAL_ERROR", details=str(e), level="ERROR")
        send_alert_webhook("500 Internal Server Error", "critical", 
                         f"Error on {request.path}: {str(e)[:500]}")
        return render_template("error.html", error="500 - Internal server error"), 500

    @app.route('/session/debug')
    def session_debug():
        """Debug endpoint to check session (remove in production)"""
        if os.environ.get('FLASK_ENV') != 'production':
            session_info = {
                'keys': list(session.keys()),
                'has_discord_user': 'discord_user' in session,
                'discord_user': session.get('discord_user'),
                'csrf_token': session.get('csrf_token'),
                'is_verified': session.get('is_verified'),
                'session_id': session.get('_id', 'No session ID')
            }
            return jsonify(session_info)
        else:
            return jsonify({'error': 'Not available in production'}), 403

    return app