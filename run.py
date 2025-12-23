"""
Main entry point for Discord Verification System
Fixed to run both website and Discord bot reliably
"""

import os
import sys
import threading
import time
import signal
import atexit
import subprocess
import traceback

# Check Python version
PYTHON_VERSION = sys.version_info
print(f"🐍 Python {PYTHON_VERSION.major}.{PYTHON_VERSION.minor}.{PYTHON_VERSION.micro}")

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import after path setup
try:
    from website.app import create_app
    from bot.bot import run_discord_bot
    from config import Config
    from utils.logger import logger
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("Current sys.path:", sys.path)
    raise

# Global variables
bot_process = None
bot_thread = None

def cleanup():
    """Cleanup resources on exit"""
    logger.info("🧹 Cleaning up resources...")
    global bot_process, bot_thread
    
    # Stop bot thread
    if bot_thread and bot_thread.is_alive():
        logger.info("🛑 Stopping Discord bot thread...")
    
    # Stop bot process if running
    if bot_process and bot_process.poll() is None:
        logger.info("🛑 Stopping Discord bot process...")
        bot_process.terminate()
        try:
            bot_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            bot_process.kill()
    
    logger.info("✅ Cleanup complete")

def signal_handler(signum, frame):
    """Handle shutdown signals"""
    logger.info(f"🛑 Received signal {signum}, shutting down...")
    cleanup()
    sys.exit(0)

def run_bot():
    """Run Discord bot with error handling"""
    logger.info("🤖 Starting Discord bot...")
    
    try:
        # Import and run the bot function
        from bot.bot import run_discord_bot
        run_discord_bot()
        
    except Exception as e:
        logger.error(f"❌ Bot error: {e}")
        logger.error("Bot traceback:")
        traceback.print_exc()
        
        # Log additional info
        logger.info(f"Discord Token present: {'Yes' if Config.DISCORD_TOKEN else 'No'}")
        logger.info(f"Guild ID: {Config.GUILD_ID}")
        
        # Restart after delay
        logger.info("🔄 Restarting bot in 30 seconds...")
        time.sleep(30)
        run_bot()  # Restart recursively

def start_bot_in_thread():
    """Start the Discord bot in a separate thread"""
    global bot_thread
    logger.info("🚀 Starting Discord bot in background thread...")
    
    bot_thread = threading.Thread(target=run_bot, daemon=True)
    bot_thread.start()
    
    # Wait for bot to initialize
    logger.info("⏳ Waiting for bot to initialize (5 seconds)...")
    time.sleep(5)
    
    if bot_thread.is_alive():
        logger.info("✅ Discord bot is running in background")
    else:
        logger.warning("⚠️ Discord bot thread may not be running properly")

def run_website():
    """Run Flask website"""
    logger.info("🌐 Starting website...")
    
    # Create app
    app = create_app()
    
    # Get port from environment
    port = int(os.environ.get("PORT", 10000))
    host = "0.0.0.0"  # Bind to all interfaces
    
    logger.info("=" * 50)
    logger.info(f"🌍 Website URL: http://{host}:{port}")
    logger.info(f"🔗 Verification: http://{host}:{port}/verify")
    logger.info(f"👑 Admin: http://{host}:{port}/admin/login")
    logger.info(f"📊 Health Check: http://{host}:{port}/healthz")
    logger.info("=" * 50)
    
    # Print startup banner
    print("\n" + "=" * 60)
    print("🚀 DISCORD VERIFICATION & SECURITY SYSTEM")
    print("=" * 60)
    print(f"📅 {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"🐍 Python {PYTHON_VERSION.major}.{PYTHON_VERSION.minor}.{PYTHON_VERSION.micro}")
    print(f"🌐 Port: {port}")
    print(f"🔗 Website: http://{host}:{port}")
    print("=" * 60 + "\n")
    
    # Run Flask app with gunicorn if in production
    if os.environ.get("FLASK_ENV") == "production":
        logger.info("🚀 Starting with gunicorn (production mode)")
        try:
            # Run gunicorn programmatically
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
                "workers": 2,
                "threads": 4,
                "timeout": 120,
                "keepalive": 5,
                "worker_class": "sync",
                "accesslog": "-",
                "errorlog": "-"
            }
            
            FlaskApplication(app, options).run()
            
        except ImportError:
            logger.warning("⚠️ Gunicorn not available, falling back to Flask dev server")
            app.run(host=host, port=port, debug=False, use_reloader=False)
    else:
        # Development mode
        logger.info("🔧 Running in development mode")
        app.run(host=host, port=port, debug=True, use_reloader=False)

def main():
    """Main entry point"""
    # Register cleanup handlers
    atexit.register(cleanup)
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    
    # Validate configuration
    if not Config.DISCORD_TOKEN:
        logger.error("❌ ERROR: DISCORD_TOKEN not configured!")
        print("Please set DISCORD_TOKEN environment variable")
        sys.exit(1)
    
    # Set website URL if not set
    if not Config.WEBSITE_URL:
        port = int(os.environ.get("PORT", 10000))
        os.environ["WEBSITE_URL"] = f"http://localhost:{port}"
        logger.info(f"🌐 Set WEBSITE_URL to: http://localhost:{port}")
    
    # Start Discord bot in background thread
    start_bot_in_thread()
    
    # Start Flask website (this will block)
    run_website()

if __name__ == "__main__":
    main()