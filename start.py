import discord
from discord.ext import commands
import asyncio
import threading
from flask import Flask, render_template_string, redirect, url_for, session, request
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# ============= CONFIG =============
DISCORD_TOKEN = os.getenv('DISCORD_TOKEN')
PORT = 5000

# ============= FLASK WEBSITE =============
app = Flask(__name__)
app.secret_key = 'your-secret-key-here'

@app.route('/')
def home():
    return redirect('/verify')

@app.route('/verify')
def verify():
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Discord Verification</title>
        <style>
            body {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                font-family: 'Segoe UI', sans-serif;
                margin: 0;
                padding: 20px;
                display: flex;
                justify-content: center;
                align-items: center;
                min-height: 100vh;
            }
            .card {
                background: white;
                border-radius: 15px;
                padding: 40px;
                box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                max-width: 500px;
                width: 100%;
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
                text-decoration: none;
                display: inline-block;
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
        <div class="card">
            <h1>🔐 Discord Verification</h1>
            <p>Complete verification to access our server</p>
            
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
                Start Verification
            </a>
            
            <div style="margin-top: 20px; padding: 15px; background: #f8f9fa; border-radius: 8px;">
                <strong>⚠️ Important:</strong>
                <ul style="text-align: left;">
                    <li>VPN/Proxy users will be banned</li>
                    <li>One account per person</li>
                    <li>IP address will be recorded</li>
                </ul>
            </div>
            
            <div style="margin-top: 30px; font-size: 14px; color: #666;">
                <p><a href="/admin/login" style="color: #5865F2;">Admin Login</a></p>
            </div>
        </div>
    </body>
    </html>
    '''

@app.route('/api/start_verify')
def start_verify():
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body { font-family: Arial, sans-serif; padding: 50px; text-align: center; }
            .success { color: green; font-size: 24px; margin: 20px 0; }
            .info { background: #e7f3ff; padding: 20px; border-radius: 10px; margin: 20px 0; }
        </style>
    </head>
    <body>
        <h1>✅ Verification Complete!</h1>
        <div class="success">Your verification was successful!</div>
        <div class="info">
            <p><strong>In production, this would:</strong></p>
            <ol style="text-align: left; display: inline-block;">
                <li>Check your IP for VPN/Proxy</li>
                <li>Record your IP address</li>
                <li>Give you the "Verified" role in Discord</li>
                <li>Ban your IP if VPN is detected</li>
            </ol>
        </div>
        <p>You can now return to Discord.</p>
        <p><a href="/verify">← Back to verification</a></p>
    </body>
    </html>
    '''

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username == 'admin' and password == 'admin123':
            session['admin'] = True
            return redirect('/admin/dashboard')
    
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body { font-family: Arial, sans-serif; background: #f0f0f0; display: flex; justify-content: center; align-items: center; height: 100vh; }
            .login-box { background: white; padding: 40px; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); width: 300px; }
            input { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px; }
            button { background: #5865F2; color: white; border: none; padding: 10px; border-radius: 5px; cursor: pointer; width: 100%; }
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
            <p style="font-size: 12px; color: #666; margin-top: 20px;">Default: admin / admin123</p>
        </div>
    </body>
    </html>
    '''

@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('admin'):
        return redirect('/admin/login')
    
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body { font-family: Arial, sans-serif; margin: 0; padding: 20px; }
            .container { display: flex; }
            .sidebar { width: 250px; background: #2c3e50; color: white; padding: 20px; min-height: 100vh; }
            .content { flex: 1; padding: 20px; }
            table { width: 100%; border-collapse: collapse; margin: 20px 0; }
            th, td { border: 1px solid #ddd; padding: 10px; text-align: left; }
            th { background: #f2f2f2; }
            .stats { display: flex; gap: 20px; margin-bottom: 30px; }
            .stat-card { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); flex: 1; text-align: center; }
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
                        <h3>Banned Users</h3>
                        <p style="font-size: 24px;">0</p>
                    </div>
                    <div class="stat-card">
                        <h3>Verified Users</h3>
                        <p style="font-size: 24px;">0</p>
                    </div>
                    <div class="stat-card">
                        <h3>Active Bans</h3>
                        <p style="font-size: 24px;">0</p>
                    </div>
                </div>
                
                <h2>System Status</h2>
                <table>
                    <tr><th>Component</th><th>Status</th></tr>
                    <tr><td>Discord Bot</td><td style="color: green;">✅ Online</td></tr>
                    <tr><td>Website</td><td style="color: green;">✅ Running</td></tr>
                    <tr><td>Database</td><td style="color: orange;">⚠️ Not connected</td></tr>
                    <tr><td>IP Checking</td><td style="color: orange;">⚠️ Not configured</td></tr>
                </table>
                
                <h2>Next Steps</h2>
                <ol>
                    <li>Configure MongoDB database</li>
                    <li>Set up IP checking API</li>
                    <li>Add Discord webhook URLs</li>
                    <li>Configure Discord bot token</li>
                </ol>
            </div>
        </div>
    </body>
    </html>
    '''

@app.route('/admin/logout')
def admin_logout():
    session.clear()
    return redirect('/admin/login')

# ============= SIMPLE DISCORD BOT =============
class SimpleBot(commands.Bot):
    def __init__(self):
        intents = discord.Intents.default()
        intents.members = True
        intents.message_content = True
        super().__init__(command_prefix="!", intents=intents)
        
    async def on_ready(self):
        print(f'✅ Bot logged in as {self.user}')
        
    async def on_message(self, message):
        if message.author == self.user:
            return
            
        if message.content.startswith('!setup'):
            if message.author.guild_permissions.administrator:
                embed = discord.Embed(
                    title="🔐 Verification System Setup",
                    description="**Verification is now active!**",
                    color=discord.Color.green()
                )
                await message.channel.send(embed=embed)
                
        if message.content.startswith('!ban'):
            if message.author.guild_permissions.ban_members:
                # Simple ban command
                parts = message.content.split()
                if len(parts) > 1:
                    await message.channel.send(f"Ban command received. In production, this would ban {parts[1]}")

def run_bot():
    if not DISCORD_TOKEN or DISCORD_TOKEN == 'your_token_here':
        print("❌ Please set DISCORD_TOKEN in .env file!")
        print("Get token from: https://discord.com/developers/applications")
        return
        
    bot = SimpleBot()
    bot.run(DISCORD_TOKEN)

# ============= MAIN =============
if __name__ == "__main__":
    print("🚀 Starting Discord Verification System...")
    print("=" * 50)
    print("🌐 Website: https://koalahub.onrender.com")
    print("🔐 Verify: https://koalahub.onrender.com")
    print("👑 Admin: https://koalahub.onrender.com/admin/login")
    print("=" * 50)
    
    # Check .env file
    if not os.path.exists('.env'):
        with open('.env', 'w') as f:
            f.write('DISCORD_TOKEN=your_token_here\n')
        print("📁 Created .env file. Please edit it with your Discord token!")
    
    # Start bot in background
    import threading
    bot_thread = threading.Thread(target=run_bot, daemon=True)
    bot_thread.start()
    
    # Start website
    app.run(debug=True, port=PORT, use_reloader=False)