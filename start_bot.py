#!/usr/bin/env python3
"""
Standalone Discord bot starter
Run this separately from the website if you're having issues
"""

import os
import sys
import traceback
import time

# Add the project root to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from config import Config
from utils.logger import logger

def start_bot():
    """Start the Discord bot"""
    logger.info("🤖 Starting Discord bot standalone...")
    
    try:
        from bot.bot import SecurityMonitorBot
        
        bot = SecurityMonitorBot()
        
        # Print startup info
        print("=" * 60)
        print("🤖 DISCORD SECURITY BOT")
        print("=" * 60)
        print(f"📅 {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"🔑 Token present: {'Yes' if Config.DISCORD_TOKEN else 'No'}")
        print(f"🏰 Guild ID: {Config.GUILD_ID}")
        print("=" * 60)
        
        # Run the bot
        bot.run(Config.DISCORD_TOKEN)
        
    except KeyboardInterrupt:
        logger.info("🛑 Bot stopped by user")
    except Exception as e:
        logger.error(f"❌ Bot crashed: {e}")
        traceback.print_exc()
        print("\n🔄 Restarting in 10 seconds...")
        time.sleep(10)
        start_bot()  # Restart

if __name__ == "__main__":
    if not Config.DISCORD_TOKEN:
        print("❌ ERROR: No Discord token found in config!")
        print("Please set DISCORD_TOKEN environment variable")
        sys.exit(1)
    
    start_bot()