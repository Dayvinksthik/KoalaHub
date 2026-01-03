import os
import sys
import threading
import time
import signal
import atexit
import traceback

# Check Python version
PYTHON_VERSION = sys.version_info
print(f"🐍 Python {PYTHON_VERSION.major}.{PYTHON_VERSION.minor}.{PYTHON_VERSION.micro}")

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from website.app import create_app
    from config import Config
    from utils.logger import logger
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("Current sys.path:", sys.path)
    raise

# Global bot thread
bot_thread = None

def cleanup():
    """Cleanup resources on exit"""
    logger.info("🧹 Cleaning up resources...")
    
    # Signal bot thread to stop if running
    global bot_thread
    if bot_thread and bot_thread.is_alive():
        logger.info("🛑 Bot thread will exit when service stops")

def signal_handler(signum, frame):
    """Handle shutdown signals"""
    logger.info(f"🛑 Received signal {signum}, shutting down...")
    cleanup()
    sys.exit(0)

def run_discord_bot_safe():
    """Run Discord bot with proper error handling"""
    logger.info("🤖 Attempting to start Discord bot...")
    
    try:
        # Import inside function to avoid circular imports
        import asyncio
        from bot.bot import SecurityMonitorBot
        
        # Create and run the bot
        bot = SecurityMonitorBot()
        
        # Run the bot
        bot.run(Config.DISCORD_TOKEN)
        
    except KeyboardInterrupt:
        logger.info("🛑 Bot stopped by user")
    except Exception as e:
        logger.error(f"❌ Bot error: {e}")
        logger.error("Bot traceback:")
        traceback.print_exc()
        
        # Log configuration status
        logger.info(f"📋 Config Check:")
        logger.info(f"  Discord Token present: {'Yes' if Config.DISCORD_TOKEN else 'No'}")
        logger.info(f"  Token length: {len(Config.DISCORD_TOKEN) if Config.DISCORD_TOKEN else 0}")
        logger.info(f"  Token starts with: {Config.DISCORD_TOKEN[:10] if Config.DISCORD_TOKEN else 'N/A'}...")
        logger.info(f"  Guild ID: {Config.GUILD_ID}")
        logger.info(f"  Website URL: {Config.WEBSITE_URL}")
        
        # Don't restart automatically - let it fail
        logger.error("❌ Bot failed to start. Please check logs above.")

def start_bot_in_thread():
    """Start Discord bot in background thread"""
    global bot_thread
    
    # Only start if we have a token
    if not Config.DISCORD_TOKEN:
        logger.error("❌ No Discord token found! Bot will not start.")
        logger.error("⚠️  Please set DISCORD_TOKEN environment variable")
        return
    
    logger.info("🚀 Starting Discord bot in background...")
    
    bot_thread = threading.Thread(target=run_discord_bot_safe, daemon=True)
    bot_thread.start()
    
    # Give it time to start
    time.sleep(3)
    
    if bot_thread.is_alive():
        logger.info("✅ Discord bot thread started successfully")
    else:
        logger.warning("⚠️ Discord bot thread may have failed to start")

def run_website():
    """Run Flask website - this is the main service"""
    logger.info("🌐 Starting website...")
    
    # Create app
    app = create_app()
    
    # Get port from environment
    port = int(os.environ.get("PORT", 10000))
    host = "0.0.0.0"
    
    # Print banner
    print("\n" + "=" * 60)
    print("🚀 DISCORD VERIFICATION & SECURITY SYSTEM")
    print("=" * 60)
    print(f"📅 {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"🐍 Python {PYTHON_VERSION.major}.{PYTHON_VERSION.minor}.{PYTHON_VERSION.micro}")
    print(f"🌐 Port: {port}")
    print(f"🔗 Website: https://koalahub.onrender.com")
    print(f"🤖 Bot Status: {'Will attempt to start' if Config.DISCORD_TOKEN else 'Disabled - No Token'}")
    print("=" * 60 + "\n")
    
    # Log important info
    logger.info("=" * 50)
    logger.info(f"🌍 Website URL: https://koalahub.onrender.com")
    logger.info(f"🔗 Verification: https://koalahub.onrender.com/verify")
    logger.info(f"👑 Admin: https://koalahub.onrender.com/admin/login")
    logger.info(f"📊 Health Check: https://koalahub.onrender.com/healthz")
    logger.info("=" * 50)
    
    # Try to start bot in background
    start_bot_in_thread()
    
    # Run Flask with gunicorn
    logger.info("🚀 Starting web server...")
    
    if os.environ.get("FLASK_ENV") == "production":
        # Use gunicorn for production
        try:
            from gunicorn.app.base import BaseApplication
            
            class FlaskApplication(BaseApplication):
                def __init__(self, app, options=None):
                    self.options = options or {}
                    self.application = app
                    super().__init__()
                
                def load_config(self):
                    for key, value in self.options.items():
                        if key in self.cfg.settings and value is not None:
                            self.cfg.set(key.lower(), value)
                
                def load(self):
                    return self.application
            
            options = {
                "bind": f"{host}:{port}",
                "workers": 1,  # Use 1 worker to save memory
                "threads": 2,
                "timeout": 120,
                "keepalive": 5,
                "worker_class": "sync",
                "accesslog": "-",
                "errorlog": "-",
                "loglevel": "info"
            }
            
            FlaskApplication(app, options).run()
            
        except ImportError:
            logger.warning("⚠️ Gunicorn not available, using Flask dev server")
            app.run(host=host, port=port, debug=False, use_reloader=False)
    else:
        # Development
        logger.info("🔧 Running in development mode")
        app.run(host=host, port=port, debug=True, use_reloader=False)

def main():
    """Main entry point"""
    # Register cleanup handlers
    atexit.register(cleanup)
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    
    # Validate basic config
    if not Config.MONGODB_URI:
        logger.error("❌ ERROR: MONGODB_URI not configured!")
        sys.exit(1)
    
    # Check if bot can run
    if not Config.DISCORD_TOKEN:
        logger.warning("⚠️  WARNING: DISCORD_TOKEN not configured!")
        logger.warning("⚠️  Discord bot will not start, but website will run")
    
    # Run website (blocks forever)
    run_website()

if __name__ == "__main__":
    main()