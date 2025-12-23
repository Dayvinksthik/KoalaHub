"""
Discord Verification System - Website Application
Simplified version without flask_wtf for Python 3.13 compatibility
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

    # ================= ROUTES =================

    @app.route("/")
    def home():
        return render_template("index.html", csrf_token=generate_csrf_token())

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