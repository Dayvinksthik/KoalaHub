import os
import sys
import threading
import time
import signal
import atexit

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
bot_thread = None

def cleanup():
    """Cleanup resources on exit"""
    logger.info("🧹 Cleaning up resources...")
    global bot_thread
    
    if bot_thread and bot_thread.is_alive():
        logger.info("🛑 Bot thread will terminate with main process...")

def signal_handler(signum, frame):
    """Handle shutdown signals"""
    logger.info(f"🛑 Received signal {signum}, shutting down...")
    cleanup()
    sys.exit(0)

def run_bot():
    """Run Discord bot"""
    logger.info("🤖 Starting Discord bot...")
    try:
        run_discord_bot()
    except Exception as e:
        logger.error(f"❌ Bot error: {e}")
        import traceback
        traceback.print_exc()

def run_website():
    """Run Flask website"""
    logger.info("🌐 Starting website...")
    
    # Create app
    app = create_app()
    
    # Get port from environment
    port = int(os.environ.get("PORT", 10000))
    host = os.environ.get("HOST", "0.0.0.0")
    
    logger.info(f"🌍 Server will run on: http://{host}:{port}")
    logger.info(f"🔗 Verification: http://{host}:{port}/verify")
    logger.info(f"👑 Admin: http://{host}:{port}/admin/login")
    logger.info("=" * 50)
    
    # Run Flask app
    app.run(host=host, port=port, debug=False, use_reloader=False)

def main():
    """Main entry point"""
    print("=" * 60)
    print("🚀 DISCORD VERIFICATION SYSTEM")
    print("=" * 60)
    
    # Register cleanup handlers
    atexit.register(cleanup)
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    
    # Validate configuration
    if not Config.DISCORD_TOKEN:
        logger.error("❌ ERROR: DISCORD_TOKEN not configured!")
        print("Please set DISCORD_TOKEN environment variable")
        sys.exit(1)
    
    # Set website URL
    website_url = os.environ.get("WEBSITE_URL", f"http://localhost:{os.environ.get('PORT', 10000)}")
    os.environ["WEBSITE_URL"] = website_url
    logger.info(f"🌐 Website URL: {website_url}")
    
    # Start Discord bot in separate thread
    global bot_thread
    bot_thread = threading.Thread(target=run_bot, daemon=True)
    bot_thread.start()
    
    # Wait for bot to initialize
    logger.info("⏳ Initializing bot (3 seconds)...")
    time.sleep(3)
    
    # Start Flask website (this will block)
    run_website()

if __name__ == "__main__":
    main()