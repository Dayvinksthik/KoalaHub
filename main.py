import discord
from discord.ext import commands
from discord import app_commands
import asyncio
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_cors import CORS
import threading
import os
from dotenv import load_dotenv
import requests
import json
from datetime import datetime
import secrets

# Load environment variables
load_dotenv()

# ============= CONFIGURATION =============
DISCORD_TOKEN = os.getenv('DISCORD_TOKEN')
GUILD_ID = int(os.getenv('DISCORD_GUILD_ID', 0))
SECRET_KEY = os.getenv('SECRET_KEY', secrets.token_hex(32))
ADMIN_USERNAME = os.getenv('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'admin123')

# ============= SIMPLE DATABASE (Using JSON files) =============
class SimpleDB:
    def __init__(self):
        self.banned_file = 'banned.json'
        self.verified_file = 'verified.json'
        self.load_data()
        
    def load_data(self):
        try:
            with open(self.banned_file, 'r') as f:
                self.banned = json.load(f)
        except:
            self.banned = []
            
        try:
            with open(self.verified_file, 'r') as f:
                self.verified = json.load(f)
        except:
            self.verified = []
            
    def save_banned(self):
        with open(self.banned_file, 'w') as f:
            json.dump(self.banned, f, indent=2)
            
    def save_verified(self):
        with open(self.verified_file, 'w') as f:
            json.dump(self.verified, f, indent=2)
            
    def add_banned(self, discord_id, username, ip_address, reason="VPN detected"):
        self.banned.append({
            'discord_id': discord_id,
            'username': username,
            'ip_address': ip_address,
            'reason': reason,
            'banned_at': datetime.now().isoformat()
        })
        self.save_banned()
        
    def add_verified(self, discord_id, username, ip_address):
        self.verified.append({
            'discord_id': discord_id,
            'username': username,
            'ip_address': ip_address,
            'verified_at': datetime.now().isoformat()
        })
        self.save_verified()
        
    def is_banned(self, discord_id=None, ip_address=None):
        for ban in self.banned:
            if discord_id and ban['discord_id'] == discord_id:
                return True
            if ip_address and ban['ip_address'] == ip_address:
                return True
        return False
        
    def get_banned_list(self):
        return self.banned
        
    def get_verified_list(self):
        return self.verified

# Initialize database
db = SimpleDB()

# ============= DISCORD BOT =============
class VerificationBot(commands.Bot):
    def __init__(self):
        intents = discord.Intents.default()
        intents.members = True
        intents.message_content = True
        super().__init__(command_prefix="!", intents=intents)
        
    async def setup_hook(self):
        # Sync slash commands
        await self.tree.sync()
        
        # Add slash command
        @self.tree.command(name="setup", description="Setup verification system")
        async def setup_command(interaction: discord.Interaction):
            if not interaction.user.guild_permissions.administrator:
                await interaction.response.send_message("❌ You need administrator permissions!", ephemeral=True)
                return
                
            embed = discord.Embed(
                title="🔐 Server Verification",
                description="**Click the green button below to verify**",
                color=discord.Color.green()
            )
            await interaction.response.send_message(embed=embed)
            
        @self.tree.command(name="ban", description="Ban a user and their IP")
        async def ban_command(interaction: discord.Interaction, user: discord.Member, reason: str = "No reason provided"):
            if not interaction.user.guild_permissions.ban_members:
                await interaction.response.send_message("❌ You need ban permissions!", ephemeral=True)
                return
                
            try:
                await user.ban(reason=reason)
                db.add_banned(str(user.id), str(user), "Unknown IP", reason)
                
                embed = discord.Embed(
                    title="✅ User Banned",
                    description=f"**User:** {user.mention}\n**Reason:** {reason}\n\nTheir IP has been added to the ban list.",
                    color=discord.Color.red()
                )
                await interaction.response.send_message(embed=embed)
            except Exception as e:
                await interaction.response.send_message(f"❌ Error: {str(e)}", ephemeral=True)
                
    async def on_ready(self):
        print(f'✅ Bot logged in as {self.user}')
        await self.change_presence(activity=discord.Activity(type=discord.ActivityType.watching, name="for verifications"))
        
    async def on_member_join(self, member):
        # Check if user is banned in our database
        if db.is_banned(discord_id=str(member.id)):
            try:
                await member.ban(reason="Previously banned user")
            except:
                pass

def run_bot():
    if not DISCORD_TOKEN:
        print("❌ No Discord token found in .env file!")
        print("Please add: DISCORD_TOKEN=your_token_here")
        return
        
    bot = VerificationBot()
    bot.run(DISCORD_TOKEN)

# ============= FLASK WEBSITE =============
app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
CORS(app)

def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    return redirect(url_for('verify_page'))

@app.route('/verify')
def verify_page():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Discord Verification</title>
        <style>
            body {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                font-family: 'Segoe UI', sans-serif;
                margin: 0;
                padding: 0;
            }
            .container {
                display: flex;
                justify-content: center;
                align-items: center;
                min-height: 100vh;
                padding: 20px;
            }
            .card {
                background: white;
                border-radius: 15px;
                padding: 40px;
                box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                width: 100%;
                max-width: 500px;
                text-align: center;
            }
            h1 {
                color: #333;
                margin-bottom: 20px;
            }
            .btn {
                background: #5865F2;
                color: white;
                border: none;
                padding: 15px 30px;
                border-radius: 8px;
                font-size: 18px;
                cursor: pointer;
                margin: 20px 0;
                display: inline-flex;
                align-items: center;
                gap: 10px;
                text-decoration: none;
            }
            .btn:hover {
                background: #4752C4;
            }
            .steps {
                display: flex;
                justify-content: space-between;
                margin: 30px 0;
            }
            .step {
                text-align: center;
                flex: 1;
            }
            .step-number {
                width: 40px;
                height: 40px;
                background: #ddd;
                border-radius: 50%;
                display: flex;
                align-items: center;
                justify-content: center;
                margin: 0 auto 10px;
            }
            .step.active .step-number {
                background: #5865F2;
                color: white;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="card">
                <h1>🔐 Discord Verification</h1>
                <p>Complete verification to join our server</p>
                
                <div class="steps">
                    <div class="step active">
                        <div class="step-number">1</div>
                        <div>Connect Discord</div>
                    </div>
                    <div class="step">
                        <div class="step-number">2</div>
                        <div>IP Check</div>
                    </div>
                    <div class="step">
                        <div class="step-number">3</div>
                        <div>Complete</div>
                    </div>
                </div>
                
                <a href="/api/start_verify" class="btn">
                    <i class="fab fa-discord"></i> Start Verification
                </a>
                
                <div style="margin-top: 20px; padding: 15px; background: #f8f9fa; border-radius: 8px;">
                    <strong>⚠️ Important:</strong>
                    <ul style="text-align: left;">
                        <li>VPN/Proxy users will be banned</li>
                        <li>One account per person</li>
                        <li>IP address will be recorded</li>
                    </ul>
                </div>
            </div>
        </div>
        
        <script src="https://kit.fontawesome.com/your-fontawesome-kit.js" crossorigin="anonymous"></script>
    </body>
    </html>
    """

@app.route('/api/start_verify')
def start_verify():
    # In production, you would redirect to Discord OAuth2
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {
                font-family: Arial, sans-serif;
                padding: 50px;
                text-align: center;
            }
            .success {
                color: green;
                font-size: 24px;
                margin: 20px 0;
            }
        </style>
    </head>
    <body>
        <h1>Verification Complete!</h1>
        <div class="success">✅ You have been verified!</div>
        <p>Return to Discord to access the server.</p>
        <p><em>Note: This is a demo. In production, this would connect to Discord OAuth2.</em></p>
    </body>
    </html>
    """

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['admin_logged_in'] = True
            return redirect(url_for('admin_dashboard'))
            
        return '''
        <h2>Login Failed</h2>
        <p>Invalid credentials. <a href="/admin/login">Try again</a></p>
        '''
        
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {
                font-family: Arial, sans-serif;
                background: #f0f0f0;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
            }
            .login-box {
                background: white;
                padding: 40px;
                border-radius: 10px;
                box-shadow: 0 0 20px rgba(0,0,0,0.1);
            }
            input {
                display: block;
                width: 100%;
                padding: 10px;
                margin: 10px 0;
                border: 1px solid #ddd;
                border-radius: 5px;
            }
            button {
                background: #5865F2;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 5px;
                cursor: pointer;
                width: 100%;
            }
        </style>
    </head>
    <body>
        <div class="login-box">
            <h2>Admin Login</h2>
            <form method="POST">
                <input type="text" name="username" placeholder="Username" required>
                <input type="password" name="password" placeholder="Password" required>
                <button type="submit">Login</button>
            </form>
            <p><em>Default: admin / admin123</em></p>
        </div>
    </body>
    </html>
    '''

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    banned = db.get_banned_list()
    verified = db.get_verified_list()
    
    banned_html = ""
    for ban in banned:
        banned_html += f"<tr><td>{ban['username']}</td><td>{ban['discord_id']}</td><td>{ban['ip_address']}</td><td>{ban['reason']}</td></tr>"
        
    verified_html = ""
    for user in verified:
        verified_html += f"<tr><td>{user['username']}</td><td>{user['discord_id']}</td><td>{user['ip_address']}</td></tr>"
    
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; }}
            .container {{ display: flex; }}
            .sidebar {{
                width: 250px;
                background: #2c3e50;
                color: white;
                padding: 20px;
                min-height: 100vh;
            }}
            .content {{ flex: 1; padding: 20px; }}
            table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
            th, td {{ border: 1px solid #ddd; padding: 10px; text-align: left; }}
            th {{ background: #f2f2f2; }}
            .stats {{ display: flex; gap: 20px; margin-bottom: 30px; }}
            .stat-card {{
                background: white;
                padding: 20px;
                border-radius: 10px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                flex: 1;
                text-align: center;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="sidebar">
                <h2>Admin Panel</h2>
                <ul>
                    <li><a href="/admin/dashboard" style="color: white;">Dashboard</a></li>
                    <li><a href="/admin/logout" style="color: white;">Logout</a></li>
                </ul>
            </div>
            <div class="content">
                <h1>Dashboard</h1>
                
                <div class="stats">
                    <div class="stat-card">
                        <h3>Total Banned</h3>
                        <p style="font-size: 24px;">{len(banned)}</p>
                    </div>
                    <div class="stat-card">
                        <h3>Total Verified</h3>
                        <p style="font-size: 24px;">{len(verified)}</p>
                    </div>
                </div>
                
                <h2>Banned Users</h2>
                <table>
                    <tr><th>Username</th><th>Discord ID</th><th>IP Address</th><th>Reason</th></tr>
                    {banned_html}
                </table>
                
                <h2>Verified Users</h2>
                <table>
                    <tr><th>Username</th><th>Discord ID</th><th>IP Address</th></tr>
                    {verified_html}
                </table>
            </div>
        </div>
    </body>
    </html>
    '''

@app.route('/admin/logout')
def admin_logout():
    session.clear()
    return redirect(url_for('admin_login'))

# ============= START EVERYTHING =============
if __name__ == "__main__":
    print("🚀 Starting Discord Verification System...")
    print("🌐 Website: https://koalahub.onrender.com")
    print("👑 Admin: https://koalahub.onrender.com/admin/login")
    print("🔐 Verify: https://koalahub.onrender.com/verify")
    print("=" * 50)
    
    # Start bot in separate thread
    bot_thread = threading.Thread(target=run_bot, daemon=True)
    bot_thread.start()
    
    # Start website
    app.run(debug=True, port=5000, use_reloader=False)