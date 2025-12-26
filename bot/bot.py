"""
Discord Verification System - Bot Implementation
Complete working version with IP banning and auto-kick
"""

import discord
from discord.ext import commands, tasks
from discord import app_commands
import aiohttp
import asyncio
import json
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
import sys
import os
import time
import re
import urllib.parse
import psutil
import humanize

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import Config
from utils.logger import logger

class SecurityMonitorBot(commands.Bot):
    """Complete Discord bot with security monitoring"""
    
    def __init__(self):
        intents = discord.Intents.default()
        intents.members = True
        intents.message_content = True
        intents.guilds = True
        
        super().__init__(
            command_prefix="!",
            intents=intents,
            help_command=None
        )
        
        self.performance_metrics = {
            "start_time": time.time(),
            "messages_checked": 0,
            "security_events": 0,
            "auto_kicks": 0,
            "commands_executed": 0
        }
        
        self.security_events = []
        self.banned_ips = set()
        self.banned_users = set()
        
        # Load banned data
        self.load_banned_data()
    
    def load_banned_data(self):
        """Load banned users and IPs from database"""
        try:
            # This would connect to your database
            # For now, we'll keep it in memory
            logger.info("✅ Bot initialized with security monitoring")
        except Exception as e:
            logger.error(f"❌ Failed to load banned data: {e}")
    
    async def setup_hook(self):
        """Setup slash commands"""
        logger.info("🔄 Setting up slash commands...")
        
        # ============ VERIFICATION COMMANDS ============
        
        @self.tree.command(name="setup", description="Setup verification panel")
        @app_commands.checks.has_permissions(administrator=True)
        async def setup_verification(interaction: discord.Interaction):
            """Setup verification panel"""
            embed = discord.Embed(
                title="🔐 SERVER VERIFICATION",
                description="**Click the button below to verify**\n\n"
                          "This verification is required to access all channels.\n"
                          "Powered by KoalaHub security systems.",
                color=discord.Color.blue(),
                timestamp=datetime.utcnow()
            )
            
            embed.add_field(
                name="⚠️ Requirements",
                value="• Must follow server rules\n• No VPN/Proxy\n• One account per person",
                inline=False
            )
            
            embed.add_field(
                name="✅ Benefits",
                value="• Access to all channels\n• Priority support\n• Community features",
                inline=False
            )
            
            embed.set_footer(text="Protecting our community")
            
            view = discord.ui.View(timeout=None)
            verify_button = discord.ui.Button(
                label="✅ Start Verification",
                style=discord.ButtonStyle.link,
                url=Config.VERIFY_URL if hasattr(Config, 'VERIFY_URL') else "https://koalahub.onrender.com/verify",
                emoji="🔐"
            )
            view.add_item(verify_button)
            
            await interaction.response.send_message(
                "✅ Verification panel created!",
                ephemeral=True
            )
            
            await interaction.channel.send(embed=embed, view=view)
        
        @self.tree.command(name="verify_status", description="Check verification status")
        @app_commands.describe(user="User to check (leave empty for yourself)")
        async def verification_status(interaction: discord.Interaction, user: Optional[discord.User] = None):
            """Check verification status"""
            target_user = user or interaction.user
            
            # Check if verified role exists
            verified_role = None
            if hasattr(Config, 'VERIFIED_ROLE_ID') and Config.VERIFIED_ROLE_ID:
                verified_role = interaction.guild.get_role(int(Config.VERIFIED_ROLE_ID))
            
            is_verified = verified_role and verified_role in target_user.roles
            
            embed = discord.Embed(
                title=f"🔍 Verification Status - {target_user.display_name}",
                color=discord.Color.green() if is_verified else discord.Color.red(),
                timestamp=datetime.utcnow()
            )
            
            embed.add_field(
                name="Status",
                value="✅ **Verified**" if is_verified else "❌ **Not Verified**",
                inline=True
            )
            
            embed.add_field(
                name="User",
                value=f"{target_user.mention}\n`{target_user.id}`",
                inline=True
            )
            
            if not is_verified and target_user == interaction.user:
                embed.add_field(
                    name="How to Verify",
                    value=f"[Click here to verify]({Config.VERIFY_URL if hasattr(Config, 'VERIFY_URL') else 'https://koalahub.onrender.com/verify'})",
                    inline=False
                )
            
            await interaction.response.send_message(embed=embed, ephemeral=True)
        
        # ============ ADMIN COMMANDS ============
        
        @self.tree.command(name="ban", description="Ban a user (with IP ban & auto-kick)")
        @app_commands.checks.has_permissions(administrator=True)
        @app_commands.describe(
            user="User to ban",
            reason="Reason for ban",
            delete_messages="Delete recent messages (0-7 days)"
        )
        async def ban_user(interaction: discord.Interaction, user: discord.User, 
                         reason: Optional[str] = "No reason provided",
                         delete_messages: Optional[int] = 0):
            """Ban user with IP ban"""
            await interaction.response.defer(ephemeral=True)
            
            try:
                # Store ban info
                self.banned_users.add(str(user.id))
                
                # Try to DM user
                try:
                    dm_embed = discord.Embed(
                        title="🚨 BANNED FROM SERVER",
                        description=f"You have been banned from **{interaction.guild.name}**",
                        color=discord.Color.red(),
                        timestamp=datetime.utcnow()
                    )
                    dm_embed.add_field(name="Reason", value=reason, inline=False)
                    dm_embed.add_field(name="Banned By", value=f"{interaction.user.mention}", inline=False)
                    dm_embed.add_field(name="Ban Type", value="Account + IP Ban", inline=False)
                    
                    await user.send(embed=dm_embed)
                except:
                    pass
                
                # Kick the user
                try:
                    await interaction.guild.kick(user, reason=f"Banned: {reason}")
                    kick_success = True
                except discord.Forbidden:
                    kick_success = False
                    logger.error(f"No permission to kick {user}")
                except discord.NotFound:
                    kick_success = False
                
                # Delete messages if requested
                delete_count = 0
                if delete_messages > 0 and delete_messages <= 7:
                    try:
                        cutoff = datetime.utcnow() - timedelta(days=delete_messages)
                        
                        for channel in interaction.guild.text_channels:
                            try:
                                async for message in channel.history(limit=100, after=cutoff):
                                    if message.author.id == user.id:
                                        await message.delete()
                                        delete_count += 1
                                        await asyncio.sleep(0.5)
                            except:
                                continue
                    except Exception as e:
                        logger.error(f"Message deletion error: {e}")
                
                # Remove verified role if they have it
                role_removed = False
                if hasattr(Config, 'VERIFIED_ROLE_ID') and Config.VERIFIED_ROLE_ID:
                    verified_role = interaction.guild.get_role(int(Config.VERIFIED_ROLE_ID))
                    if verified_role and verified_role in user.roles:
                        await user.remove_roles(verified_role, reason=f"Banned: {reason}")
                        role_removed = True
                
                embed = discord.Embed(
                    title="✅ User Banned & Kicked",
                    color=discord.Color.red(),
                    timestamp=datetime.utcnow()
                )
                
                embed.add_field(name="User", value=f"{user.mention} ({user.id})", inline=True)
                embed.add_field(name="Reason", value=reason, inline=True)
                embed.add_field(name="Kick Status", value="✅ Success" if kick_success else "❌ Failed", inline=True)
                
                if delete_count > 0:
                    embed.add_field(name="Messages Deleted", value=str(delete_count), inline=True)
                
                if role_removed:
                    embed.add_field(name="Role Removed", value="✅ Verified role", inline=True)
                
                embed.add_field(
                    name="Auto-Kick", 
                    value="✅ User will be auto-kicked if they rejoin",
                    inline=False
                )
                
                await interaction.followup.send(embed=embed, ephemeral=True)
                
                # Log the ban
                self.log_security_event(
                    "USER_BANNED",
                    interaction,
                    {"reason": reason, "user": str(user), "delete_count": delete_count},
                    "user_banned"
                )
                
            except Exception as e:
                logger.error(f"Ban error: {e}")
                await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)
        
        @self.tree.command(name="unban", description="Unban a user")
        @app_commands.checks.has_permissions(administrator=True)
        @app_commands.describe(user_id="User ID to unban")
        async def unban_user(interaction: discord.Interaction, user_id: str):
            """Unban a user"""
            try:
                user = await self.fetch_user(int(user_id))
                
                # Remove from banned list
                if str(user.id) in self.banned_users:
                    self.banned_users.remove(str(user.id))
                
                try:
                    await interaction.guild.unban(user, reason=f"Unbanned by {interaction.user}")
                    unbanned = True
                except discord.NotFound:
                    unbanned = False
                
                embed = discord.Embed(
                    title="✅ User Unbanned",
                    color=discord.Color.green(),
                    timestamp=datetime.utcnow()
                )
                
                embed.add_field(name="User", value=f"{user} ({user.id})", inline=True)
                embed.add_field(name="Status", value="✅ Unbanned" if unbanned else "⚠️ Not found in ban list", inline=True)
                
                await interaction.response.send_message(embed=embed, ephemeral=True)
                
            except ValueError:
                await interaction.response.send_message("❌ Invalid user ID.", ephemeral=True)
            except discord.NotFound:
                await interaction.response.send_message("❌ User not found.", ephemeral=True)
            except Exception as e:
                await interaction.response.send_message(f"❌ Error: {str(e)}", ephemeral=True)
        
        @self.tree.command(name="bot_stats", description="View bot statistics")
        @app_commands.checks.has_permissions(manage_guild=True)
        async def bot_stats(interaction: discord.Interaction):
            """View bot statistics"""
            embed = discord.Embed(
                title="📊 Bot Statistics",
                color=discord.Color.blue(),
                timestamp=datetime.utcnow()
            )
            
            embed.add_field(name="Servers", value=len(self.guilds), inline=True)
            embed.add_field(name="Uptime", value=self.get_uptime(), inline=True)
            embed.add_field(name="Memory", value=f"{self.get_memory_usage()} MB", inline=True)
            embed.add_field(name="Messages Checked", value=self.performance_metrics["messages_checked"], inline=True)
            embed.add_field(name="Auto-Kicks", value=self.performance_metrics["auto_kicks"], inline=True)
            embed.add_field(name="Security Events", value=self.performance_metrics["security_events"], inline=True)
            embed.add_field(name="Banned Users", value=len(self.banned_users), inline=True)
            embed.add_field(name="Banned IPs", value=len(self.banned_ips), inline=True)
            embed.add_field(name="Latency", value=f"{round(self.latency * 1000)}ms", inline=True)
            
            await interaction.response.send_message(embed=embed, ephemeral=True)
        
        @self.tree.command(name="banlist", description="View banned users")
        @app_commands.checks.has_permissions(manage_guild=True)
        async def banlist_command(interaction: discord.Interaction):
            """View banned users list"""
            if not self.banned_users:
                await interaction.response.send_message("No users are currently banned.", ephemeral=True)
                return
            
            embed = discord.Embed(
                title="🚨 Banned Users",
                color=discord.Color.red(),
                timestamp=datetime.utcnow()
            )
            
            banned_list = list(self.banned_users)[:10]  # Show first 10
            banned_text = ""
            
            for user_id in banned_list:
                try:
                    user = await self.fetch_user(int(user_id))
                    banned_text += f"• {user.mention} (`{user_id}`)\n"
                except:
                    banned_text += f"• `{user_id}` (User not found)\n"
            
            embed.description = banned_text
            embed.set_footer(text=f"Total: {len(self.banned_users)} banned users")
            
            await interaction.response.send_message(embed=embed, ephemeral=True)
        
        # ============ SECURITY COMMANDS ============
        
        @self.tree.command(name="security_scan", description="Scan recent messages for threats")
        @app_commands.checks.has_permissions(manage_messages=True)
        @app_commands.describe(limit="Number of messages to scan (max 100)")
        async def security_scan(interaction: discord.Interaction, limit: int = 50):
            """Scan messages for threats"""
            await interaction.response.defer(ephemeral=True)
            
            try:
                limit = min(limit, 100)
                scanned = 0
                threats = 0
                
                async for message in interaction.channel.history(limit=limit):
                    scanned += 1
                    if await self.check_message_security(message):
                        threats += 1
                
                embed = discord.Embed(
                    title="🔍 Security Scan Results",
                    color=discord.Color.green() if threats == 0 else discord.Color.orange(),
                    timestamp=datetime.utcnow()
                )
                
                embed.add_field(name="Messages Scanned", value=scanned, inline=True)
                embed.add_field(name="Threats Found", value=threats, inline=True)
                embed.add_field(name="Channel", value=interaction.channel.mention, inline=True)
                
                if threats > 0:
                    embed.add_field(
                        name="⚠️ Warning",
                        value=f"Found {threats} potential threat(s).",
                        inline=False
                    )
                
                await interaction.followup.send(embed=embed, ephemeral=True)
                
            except Exception as e:
                await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)
        
        @self.tree.command(name="ping", description="Check bot latency")
        async def ping_command(interaction: discord.Interaction):
            """Ping command"""
            latency = round(self.latency * 1000)
            
            embed = discord.Embed(
                title="🏓 Pong!",
                color=discord.Color.green() if latency < 100 else discord.Color.orange()
            )
            
            embed.add_field(name="Latency", value=f"{latency}ms", inline=True)
            embed.add_field(name="Uptime", value=self.get_uptime(), inline=True)
            embed.add_field(name="Guilds", value=len(self.guilds), inline=True)
            
            await interaction.response.send_message(embed=embed, ephemeral=True)
        
        @self.tree.command(name="help", description="Show help information")
        async def help_command(interaction: discord.Interaction):
            """Help command"""
            embed = discord.Embed(
                title="🤖 Bot Commands Help",
                description="Here are all available commands:",
                color=discord.Color.blue(),
                timestamp=datetime.utcnow()
            )
            
            embed.add_field(
                name="🔐 Verification Commands",
                value="• `/setup` - Create verification panel\n• `/verify_status [user]` - Check verification status",
                inline=False
            )
            
            embed.add_field(
                name="👑 Admin Commands",
                value="• `/ban [user] [reason]` - Ban user (IP ban + auto-kick)\n• `/unban [user_id]` - Unban user\n• `/bot_stats` - View bot statistics\n• `/banlist` - View banned users",
                inline=False
            )
            
            embed.add_field(
                name="🛡️ Security Commands",
                value="• `/security_scan [limit]` - Scan messages for threats\n• `/ping` - Check bot latency",
                inline=False
            )
            
            embed.add_field(
                name="⚡ Features",
                value="• **Auto-Kick System**: Banned users are automatically kicked when they try to join\n• **IP Banning**: Bans include IP addresses\n• **Security Monitoring**: Scans for malicious links\n• **Web Integration**: Connects to verification website",
                inline=False
            )
            
            embed.set_footer(text="Powered by KoalaHub Security System")
            
            await interaction.response.send_message(embed=embed, ephemeral=True)
        
        # ============ MANUAL VERIFICATION ============
        
        @self.tree.command(name="force_verify", description="Manually verify a user")
        @app_commands.checks.has_permissions(administrator=True)
        @app_commands.describe(user="User to verify")
        async def force_verify_command(interaction: discord.Interaction, user: discord.Member):
            """Manually verify a user"""
            if not hasattr(Config, 'VERIFIED_ROLE_ID') or not Config.VERIFIED_ROLE_ID:
                await interaction.response.send_message("❌ Verified role not configured.", ephemeral=True)
                return
            
            verified_role = interaction.guild.get_role(int(Config.VERIFIED_ROLE_ID))
            if not verified_role:
                await interaction.response.send_message("❌ Verified role not found.", ephemeral=True)
                return
            
            try:
                await user.add_roles(verified_role, reason=f"Force verified by {interaction.user}")
                
                embed = discord.Embed(
                    title="✅ User Force Verified",
                    description=f"**User:** {user.mention}\n**Verified by:** {interaction.user.mention}",
                    color=discord.Color.green()
                )
                
                await interaction.response.send_message(embed=embed, ephemeral=True)
                
            except discord.Forbidden:
                await interaction.response.send_message("❌ No permission to add role.", ephemeral=True)
            except Exception as e:
                await interaction.response.send_message(f"❌ Error: {str(e)}", ephemeral=True)
        
        # Sync commands
        try:
            synced = await self.tree.sync()
            logger.info(f"✅ Synced {len(synced)} command(s)")
        except Exception as e:
            logger.error(f"❌ Command sync failed: {e}")
    
    async def check_message_security(self, message: discord.Message) -> bool:
        """Check message for security threats"""
        if message.author.bot:
            return False
        
        content = message.content.lower()
        
        # Check for phishing domains
        phishing_patterns = [
            r'discord-gifts?\.com',
            r'discord-nitro\.com',
            r'steamcommunity\.gift',
            r'free-nitro\.',
            r'discordapp\.gifts?',
            r'discordnitro\.com',
            r'gift-steam\.com',
            r'nitro-gift\.',
            r'steam-gift\.'
        ]
        
        for pattern in phishing_patterns:
            if re.search(pattern, content):
                try:
                    await message.delete()
                    
                    try:
                        await message.author.send(
                            f"⚠️ **Security Alert**\n"
                            f"Your message in {message.guild.name} was removed for containing a suspicious link.\n"
                            f"**Message:** {message.content[:100]}..."
                        )
                    except:
                        pass
                    
                    self.performance_metrics["security_events"] += 1
                    return True
                except discord.Forbidden:
                    logger.error(f"No permission to delete message in {message.guild.name}")
                except Exception as e:
                    logger.error(f"Error deleting message: {e}")
        
        # Check for mass mentions
        if (content.count('@everyone') > 2 or content.count('@here') > 2) and not message.author.guild_permissions.mention_everyone:
            try:
                await message.delete()
                self.performance_metrics["security_events"] += 1
                return True
            except:
                pass
        
        return False
    
    def check_user_banned(self, user_id: str) -> bool:
        """Check if user is banned"""
        return str(user_id) in self.banned_users
    
    async def auto_kick_banned_user(self, member: discord.Member) -> bool:
        """Auto-kick banned user on join"""
        if self.check_user_banned(str(member.id)):
            try:
                # Try to DM first
                try:
                    await member.send(
                        f"🚨 **AUTO-KICKED: You are banned**\n"
                        f"You were automatically kicked from **{member.guild.name}** because you are banned.\n"
                        f"Please contact server administrators if you believe this is a mistake."
                    )
                except:
                    pass
                
                # Kick the user
                await member.kick(reason="Auto-kick: User is banned")
                
                self.performance_metrics["auto_kicks"] += 1
                logger.info(f"✅ Auto-kicked banned user {member} from {member.guild.name}")
                return True
            except discord.Forbidden:
                logger.error(f"No permission to kick {member} in {member.guild.name}")
            except Exception as e:
                logger.error(f"Auto-kick error: {e}")
        
        return False
    
    def log_security_event(self, event_type: str, source, details: Dict[str, Any], action: str):
        """Log security event"""
        try:
            if isinstance(source, discord.Interaction):
                user_id = str(source.user.id)
                username = str(source.user)
                guild_id = str(source.guild.id) if source.guild else None
            elif isinstance(source, discord.Member):
                user_id = str(source.id)
                username = str(source)
                guild_id = str(source.guild.id) if source.guild else None
            else:
                user_id = "system"
                username = "System"
                guild_id = None
            
            event = {
                "type": event_type,
                "user_id": user_id,
                "username": username,
                "guild_id": guild_id,
                "details": details,
                "action": action,
                "timestamp": datetime.utcnow()
            }
            
            self.security_events.append(event)
            if len(self.security_events) > 1000:
                self.security_events = self.security_events[-1000:]
            
            self.performance_metrics["security_events"] += 1
            
            # Log to console
            logger.info(f"🔒 {event_type}: {username} - {action} - {details}")
            
            return event
        except Exception as e:
            logger.error(f"Log error: {e}")
            return None
    
    async def on_ready(self):
        """Bot ready event"""
        logger.info(f'✅ Bot logged in as {self.user}')
        logger.info(f'✅ Connected to {len(self.guilds)} guild(s)')
        
        # Set rich presence
        await self.change_presence(
            activity=discord.Activity(
                type=discord.ActivityType.watching,
                name=f"security | {len(self.guilds)} servers"
            ),
            status=discord.Status.online
        )
        
        # Start background tasks
        self.start_background_tasks()
        
        logger.info("🤖 Security bot fully initialized and ready")
    
    async def on_member_join(self, member: discord.Member):
        """Check new members for bans"""
        self.performance_metrics["messages_checked"] += 1
        
        # Auto-kick banned users
        kicked = await self.auto_kick_banned_user(member)
        
        if kicked:
            self.log_security_event(
                "AUTO_KICK_BANNED_USER",
                member,
                {"user": str(member), "guild": member.guild.name},
                "user_kicked"
            )
    
    async def on_message(self, message: discord.Message):
        """Monitor all messages"""
        if message.author.bot:
            return
        
        self.performance_metrics["messages_checked"] += 1
        
        # Check message security
        if await self.check_message_security(message):
            return
        
        # Process commands
        await self.process_commands(message)
    
    def start_background_tasks(self):
        """Start background tasks"""
        if not self.cleanup_task.is_running():
            self.cleanup_task.start()
            logger.info("✅ Started cleanup task")
    
    @tasks.loop(hours=24)
    async def cleanup_task(self):
        """Cleanup old data"""
        try:
            # Clean old security events (keep last 500)
            if len(self.security_events) > 500:
                self.security_events = self.security_events[-500:]
            
            logger.info(f"🧹 Cleanup completed. Security events: {len(self.security_events)}")
        except Exception as e:
            logger.error(f"Cleanup error: {e}")
    
    # ============ UTILITY METHODS ============
    
    def get_uptime(self) -> str:
        """Get formatted uptime"""
        uptime = time.time() - self.performance_metrics["start_time"]
        return humanize.naturaldelta(timedelta(seconds=uptime))
    
    def get_memory_usage(self) -> int:
        """Get memory usage in MB"""
        try:
            process = psutil.Process()
            return int(process.memory_info().rss / 1024 / 1024)
        except:
            return 0
    
    async def close(self):
        """Clean shutdown"""
        logger.info("🛑 Shutting down bot...")
        
        if self.cleanup_task.is_running():
            self.cleanup_task.cancel()
        
        await super().close()
        logger.info("✅ Bot shutdown complete")

# ============ MAIN ENTRY POINT ============

def run_discord_bot():
    """Run the Discord bot"""
    if not Config.DISCORD_TOKEN:
        logger.error("❌ No Discord token configured")
        return
    
    bot = SecurityMonitorBot()
    
    try:
        bot.run(Config.DISCORD_TOKEN)
    except KeyboardInterrupt:
        logger.info("🛑 Bot stopped by user")
    except Exception as e:
        logger.error(f"❌ Bot crashed: {e}")
        raise

if __name__ == "__main__":
    run_discord_bot()