import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import threading
import time
from flask import Flask, render_template_string
import discord
from discord.ext import commands
import asyncio

# ============= SIMPLE FLASK APP =============
app = Flask(__name__)

@app.route('/')
def home():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Discord Verification</title>
        <style>
            body {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                font-family: Arial, sans-serif;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                margin: 0;
            }
            .container {
                background: white;
                padding: 40px;
                border-radius: 10px;
                box-shadow: 0 10px 40px rgba(0,0,0,0.3);
                text-align: center;
                max-width: 500px;
            }
            h1 {
                color: #333;
                margin-bottom: 20px;
            }
            .status {
                background: #4CAF50;
                color: white;
                padding: 10px 20px;
                border-radius: 5px;
                margin: 20px 0;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🎮 Discord Verification System</h1>
            <div class="status">✅ System is running!</div>
            <p>This is a simplified version to get you started.</p>
            <p>Access the full system at:</p>
            <ul style="text-align: left;">
                <li><strong>Website:</strong> https://koalahub.onrender.com</li>
                <li><strong>Admin:</strong> https://koalahub.onrender.com/admin</li>
                <li><strong>Verify:</strong> https://koalahub.onrender.com/verify</li>
            </ul>
        </div>
    </body>
    </html>
    """

def run_website():
    app.run(debug=True, port=5000, use_reloader=False)

# ============= SIMPLE BOT =============
class SimpleBot(commands.Bot):
    def __init__(self):
        intents = discord.Intents.default()
        intents.members = True
        intents.message_content = True
        super().__init__(command_prefix="!", intents=intents)
        
    async def on_ready(self):
        print(f'✅ Bot logged in as {self.user}')
        
    async def setup_hook(self):
        await self.tree.sync()
        
    async def on_message(self, message):
        if message.author == self.user:
            return
            
        if message.content.startswith('!setup'):
            if message.author.guild_permissions.administrator:
                embed = discord.Embed(
                    title="🔐 Verification System",
                    description="Click the button below to verify!",
                    color=discord.Color.blue()
                )
                await message.channel.send(embed=embed)

def run_bot():
    # Load token from .env or ask for it
    try:
        from dotenv import load_dotenv
        load_dotenv()
        token = os.getenv('DISCORD_TOKEN')
        
        if not token:
            print("❌ No Discord token found in .env file!")
            print("Please add your Discord token to the .env file:")
            print("DISCORD_TOKEN=your_token_here")
            return
            
        bot = SimpleBot()
        bot.run(token)
    except Exception as e:
        print(f"❌ Bot error: {e}")

# ============= MAIN =============
if __name__ == "__main__":
    print("🚀 Starting Discord Verification System...")
    print("=" * 50)
    
    # Create .env file if it doesn't exist
    if not os.path.exists('.env'):
        with open('.env', 'w') as f:
            f.write("""# Discord Bot
DISCORD_TOKEN=your_discord_token_here
DISCORD_GUILD_ID=your_server_id_here

# Website
SECRET_KEY=dev_key_1234567890
FLASK_ENV=development
PORT=5000

# Admin
ADMIN_USERNAME=admin
ADMIN_PASSWORD=admin123
""")
        print("📁 Created .env file. Please edit it with your Discord token!")
    
    # Start bot in thread
    bot_thread = threading.Thread(target=run_bot, daemon=True)
    bot_thread.start()
    
    # Start website
    print("🌐 Starting website on https://koalahub.onrender.com")
    print("🔄 Bot is starting in background...")
    run_website()