"""
Discord Verification System - Bot Implementation
With IP banning and auto-kick
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
import hashlib
import random
import re
import urllib.parse
from motor.motor_asyncio import AsyncIOMotorClient
import redis.asyncio as redis
import psutil
import humanize

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import Config
from utils.logger import logger

# ============ COMMAND GROUPS ============

class VerificationGroup(commands.Group):
    """Verification commands"""
    
    def __init__(self, bot):
        super().__init__(name="verify", description="Verification commands")
        self.bot = bot
    
    @app_commands.command(name="setup", description="Setup verification panel")
    @app_commands.checks.has_permissions(administrator=True)
    async def setup_verification(self, interaction: discord.Interaction):
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
            value="• Must follow server rules",
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
    
    @app_commands.command(name="status", description="Check verification status")
    @app_commands.describe(user="User to check (leave empty for yourself)")
    async def verification_status(self, interaction: discord.Interaction, user: Optional[discord.User] = None):
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

class AdminGroup(commands.Group):
    """Admin commands"""
    
    def __init__(self, bot):
        super().__init__(name="admin", description="Administration commands")
        self.bot = bot
    
    @app_commands.command(name="ban", description="Ban a user from verification (includes IP ban)")
    @app_commands.checks.has_permissions(administrator=True)
    @app_commands.describe(
        user="User to ban",
        reason="Reason for ban",
        delete_messages="Delete user's recent messages (days, 0-7)"
    )
    async def ban_user(self, interaction: discord.Interaction, user: discord.User, 
                      reason: Optional[str] = "No reason provided", 
                      delete_messages: Optional[int] = 0):
        """Ban user with IP ban and auto-kick"""
        await interaction.response.defer(ephemeral=True)
        
        try:
            # 1. First, check if we have this user's IP in database
            user_ip = None
            if self.bot.db is not None:
                user_data = await self.bot.db.users.find_one({"discord_id": str(user.id)})
                if user_data and user_data.get("ip_address"):
                    user_ip = user_data["ip_address"]
                    
                    # Ban the IP address
                    await self.bot.db.banned_ips.insert_one({
                        "ip_address": user_ip,
                        "discord_id": str(user.id),
                        "username": str(user),
                        "reason": reason,
                        "banned_by": str(interaction.user.id),
                        "banned_at": datetime.utcnow(),
                        "is_active": True,
                        "type": "full_ban",
                        "guild_id": str(interaction.guild.id)
                    })
            
            # 2. Add to banned users collection
            if self.bot.db is not None:
                await self.bot.db.banned_users.insert_one({
                    "discord_id": str(user.id),
                    "username": str(user),
                    "ip_address": user_ip,
                    "reason": reason,
                    "banned_by": str(interaction.user.id),
                    "banned_at": datetime.utcnow(),
                    "is_active": True,
                    "type": "full_ban",
                    "guild_id": str(interaction.guild.id)
                })
            
            # 3. Kick user from server
            try:
                # Try to DM user first
                try:
                    dm_embed = discord.Embed(
                        title="🚨 BANNED FROM SERVER",
                        description=f"You have been banned from **{interaction.guild.name}**",
                        color=discord.Color.red(),
                        timestamp=datetime.utcnow()
                    )
                    dm_embed.add_field(name="Reason", value=reason, inline=False)
                    dm_embed.add_field(name="Banned By", value=f"{interaction.user.mention} ({interaction.user})", inline=False)
                    dm_embed.add_field(name="Ban Includes", value="• Account ban\n• IP ban (if IP was recorded)\n• Auto-kick on rejoin", inline=False)
                    dm_embed.set_footer(text="This ban is permanent unless appealed")
                    
                    await user.send(embed=dm_embed)
                except:
                    pass  # User has DMs disabled
                
                # Kick the user
                await interaction.guild.kick(user, reason=f"Banned: {reason}")
                kick_success = True
            except discord.Forbidden:
                kick_success = False
                logger.error(f"No permission to kick {user} in {interaction.guild.name}")
            except discord.NotFound:
                kick_success = False
                logger.error(f"User {user} not found in guild {interaction.guild.name}")
            
            # 4. Delete recent messages if requested
            delete_count = 0
            if delete_messages > 0 and delete_messages <= 7:
                try:
                    cutoff = datetime.utcnow() - timedelta(days=delete_messages)
                    
                    # Delete messages from all channels
                    for channel in interaction.guild.text_channels:
                        try:
                            async for message in channel.history(limit=200, after=cutoff):
                                if message.author.id == user.id:
                                    await message.delete()
                                    delete_count += 1
                                    await asyncio.sleep(0.5)  # Rate limit
                        except discord.Forbidden:
                            continue
                        except Exception as e:
                            logger.error(f"Error deleting messages in {channel.name}: {e}")
                except Exception as e:
                    logger.error(f"Message deletion error: {e}")
            
            # 5. Remove verified role if they have it
            role_removed = False
            if hasattr(Config, 'VERIFIED_ROLE_ID') and Config.VERIFIED_ROLE_ID:
                verified_role = interaction.guild.get_role(int(Config.VERIFIED_ROLE_ID))
                if verified_role and verified_role in user.roles:
                    await user.remove_roles(verified_role, reason=f"Banned: {reason}")
                    role_removed = True
            
            # 6. Create response embed
            embed = discord.Embed(
                title="✅ User Banned & Kicked",
                color=discord.Color.red(),
                timestamp=datetime.utcnow()
            )
            
            embed.add_field(name="User", value=f"{user.mention} (`{user}`)", inline=True)
            embed.add_field(name="ID", value=f"`{user.id}`", inline=True)
            embed.add_field(name="Banned By", value=f"{interaction.user.mention}", inline=True)
            embed.add_field(name="Reason", value=reason, inline=False)
            
            if user_ip:
                embed.add_field(name="IP Banned", value=f"`{user_ip}`", inline=True)
            else:
                embed.add_field(name="IP Banned", value="❌ No IP recorded", inline=True)
            
            embed.add_field(name="Kick Status", value="✅ Success" if kick_success else "❌ Failed (no permission)", inline=True)
            embed.add_field(name="Messages Deleted", value=f"{delete_count} messages", inline=True)
            
            if role_removed:
                embed.add_field(name="Role Removed", value="✅ Verified role removed", inline=True)
            
            embed.add_field(
                name="Auto-Kick", 
                value="✅ User will be auto-kicked if they try to rejoin",
                inline=False
            )
            
            await interaction.followup.send(embed=embed, ephemeral=True)
            
            # 7. Log to security channel
            await self.bot.log_security_event(
                "USER_BANNED",
                interaction,
                {
                    "severity": "critical",
                    "details": f"User {user} banned with IP ban",
                    "reason": reason,
                    "ip_banned": bool(user_ip),
                    "messages_deleted": delete_count
                },
                action_taken="user_kicked_and_ip_banned"
            )
            
        except Exception as e:
            logger.error(f"Ban error: {e}")
            await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)
    
    @app_commands.command(name="ipban", description="Ban an IP address directly")
    @app_commands.checks.has_permissions(administrator=True)
    @app_commands.describe(
        ip_address="IP address to ban",
        reason="Reason for ban"
    )
    async def ban_ip_command(self, interaction: discord.Interaction, ip_address: str, 
                           reason: Optional[str] = "No reason provided"):
        """Ban an IP address directly"""
        # Validate IP format
        import ipaddress
        try:
            ipaddress.ip_address(ip_address)
        except ValueError:
            await interaction.response.send_message("❌ Invalid IP address format.", ephemeral=True)
            return
        
        try:
            if self.bot.db is not None:
                # Check if IP is already banned
                existing = await self.bot.db.banned_ips.find_one({
                    "ip_address": ip_address,
                    "is_active": True
                })
                
                if existing:
                    await interaction.response.send_message(
                        f"❌ IP `{ip_address}` is already banned.", 
                        ephemeral=True
                    )
                    return
                
                # Add to banned IPs
                await self.bot.db.banned_ips.insert_one({
                    "ip_address": ip_address,
                    "discord_id": None,
                    "username": "Direct IP ban",
                    "reason": reason,
                    "banned_by": str(interaction.user.id),
                    "banned_at": datetime.utcnow(),
                    "is_active": True,
                    "type": "ip_ban",
                    "guild_id": str(interaction.guild.id)
                })
                
                # Find and kick any users with this IP
                users_with_ip = await self.bot.db.users.find({"ip_address": ip_address}).to_list(length=10)
                kicked_users = []
                
                for user_data in users_with_ip:
                    try:
                        member = interaction.guild.get_member(int(user_data["discord_id"]))
                        if member:
                            await member.kick(reason=f"IP banned: {reason}")
                            kicked_users.append(member.name)
                    except:
                        pass
                
                embed = discord.Embed(
                    title="✅ IP Address Banned",
                    color=discord.Color.red(),
                    timestamp=datetime.utcnow()
                )
                
                embed.add_field(name="IP Address", value=f"`{ip_address}`", inline=True)
                embed.add_field(name="Reason", value=reason, inline=True)
                embed.add_field(name="Banned By", value=f"{interaction.user.mention}", inline=True)
                
                if kicked_users:
                    embed.add_field(name="Kicked Users", value=", ".join(kicked_users), inline=False)
                else:
                    embed.add_field(name="Affected Users", value="No users found with this IP", inline=False)
                
                embed.add_field(
                    name="Auto-Kick", 
                    value="✅ Anyone with this IP will be auto-kicked",
                    inline=False
                )
                
                await interaction.response.send_message(embed=embed, ephemeral=True)
                
            else:
                await interaction.response.send_message("❌ Database not available.", ephemeral=True)
                
        except Exception as e:
            logger.error(f"IP ban error: {e}")
            await interaction.response.send_message(f"❌ Error: {str(e)}", ephemeral=True)
    
    @app_commands.command(name="unban", description="Unban a user or IP")
    @app_commands.checks.has_permissions(administrator=True)
    @app_commands.describe(
        identifier="User ID, username, or IP address",
        identifier_type="Type of identifier (user/ip)"
    )
    async def unban_command(self, interaction: discord.Interaction, identifier: str,
                          identifier_type: Optional[str] = "user"):
        """Unban a user or IP"""
        try:
            if identifier_type.lower() == "user":
                # Try to find user by ID or username
                try:
                    user_id = int(identifier)
                    # Update banned users
                    if self.bot.db is not None:
                        result = await self.bot.db.banned_users.update_one(
                            {"discord_id": identifier, "is_active": True},
                            {"$set": {"is_active": False, "unbanned_at": datetime.utcnow(), "unbanned_by": str(interaction.user.id)}}
                        )
                        
                        if result.modified_count > 0:
                            await interaction.response.send_message(
                                f"✅ User with ID `{identifier}` has been unbanned.",
                                ephemeral=True
                            )
                        else:
                            await interaction.response.send_message(
                                f"❌ No active ban found for user ID `{identifier}`.",
                                ephemeral=True
                            )
                except ValueError:
                    # Try username
                    if self.bot.db is not None:
                        result = await self.bot.db.banned_users.update_many(
                            {"username": {"$regex": identifier, "$options": "i"}, "is_active": True},
                            {"$set": {"is_active": False, "unbanned_at": datetime.utcnow(), "unbanned_by": str(interaction.user.id)}}
                        )
                        
                        if result.modified_count > 0:
                            await interaction.response.send_message(
                                f"✅ {result.modified_count} user(s) with username containing `{identifier}` have been unbanned.",
                                ephemeral=True
                            )
                        else:
                            await interaction.response.send_message(
                                f"❌ No active bans found for username containing `{identifier}`.",
                                ephemeral=True
                            )
            
            elif identifier_type.lower() == "ip":
                # Unban IP
                if self.bot.db is not None:
                    result = await self.bot.db.banned_ips.update_one(
                        {"ip_address": identifier, "is_active": True},
                        {"$set": {"is_active": False, "unbanned_at": datetime.utcnow(), "unbanned_by": str(interaction.user.id)}}
                    )
                    
                    if result.modified_count > 0:
                        await interaction.response.send_message(
                            f"✅ IP `{identifier}` has been unbanned.",
                            ephemeral=True
                        )
                    else:
                        await interaction.response.send_message(
                            f"❌ No active ban found for IP `{identifier}`.",
                            ephemeral=True
                        )
            
            else:
                await interaction.response.send_message(
                    "❌ Invalid identifier type. Use 'user' or 'ip'.",
                    ephemeral=True
                )
                
        except Exception as e:
            logger.error(f"Unban error: {e}")
            await interaction.response.send_message(f"❌ Error: {str(e)}", ephemeral=True)
    
    @app_commands.command(name="banlist", description="View banned users and IPs")
    @app_commands.checks.has_permissions(manage_guild=True)
    async def banlist_command(self, interaction: discord.Interaction):
        """View list of banned users and IPs"""
        await interaction.response.defer(ephemeral=True)
        
        try:
            if self.bot.db is not None:
                # Get banned users
                banned_users = await self.bot.db.banned_users.find({
                    "is_active": True,
                    "guild_id": str(interaction.guild.id)
                }).sort("banned_at", -1).limit(20).to_list(length=20)
                
                # Get banned IPs
                banned_ips = await self.bot.db.banned_ips.find({
                    "is_active": True,
                    "guild_id": str(interaction.guild.id)
                }).sort("banned_at", -1).limit(20).to_list(length=20)
                
                embed = discord.Embed(
                    title="🚨 Ban List",
                    color=discord.Color.red(),
                    timestamp=datetime.utcnow()
                )
                
                # Banned users section
                if banned_users:
                    users_text = ""
                    for ban in banned_users[:10]:  # Show first 10
                        timestamp = ban.get("banned_at", datetime.utcnow()).strftime("%m/%d")
                        users_text += f"`{timestamp}` **{ban.get('username', 'Unknown')}** - {ban.get('reason', 'No reason')}\n"
                    
                    if len(banned_users) > 10:
                        users_text += f"\n... and {len(banned_users) - 10} more"
                    
                    embed.add_field(name="👤 Banned Users", value=users_text or "None", inline=False)
                else:
                    embed.add_field(name="👤 Banned Users", value="No users banned", inline=False)
                
                # Banned IPs section
                if banned_ips:
                    ips_text = ""
                    for ip_ban in banned_ips[:10]:  # Show first 10
                        timestamp = ip_ban.get("banned_at", datetime.utcnow()).strftime("%m/%d")
                        user = ip_ban.get('username', 'Unknown')
                        ips_text += f"`{timestamp}` **{ip_ban['ip_address']}** - {user}\n"
                    
                    if len(banned_ips) > 10:
                        ips_text += f"\n... and {len(banned_ips) - 10} more"
                    
                    embed.add_field(name="🌐 Banned IPs", value=ips_text or "None", inline=False)
                else:
                    embed.add_field(name="🌐 Banned IPs", value="No IPs banned", inline=False)
                
                embed.set_footer(text=f"Total: {len(banned_users)} users, {len(banned_ips)} IPs")
                
                await interaction.followup.send(embed=embed, ephemeral=True)
            else:
                await interaction.followup.send("❌ Database not available.", ephemeral=True)
                
        except Exception as e:
            logger.error(f"Banlist error: {e}")
            await interaction.followup.send("❌ Error fetching ban list.", ephemeral=True)
    
    @app_commands.command(name="stats", description="View detailed bot statistics")
    @app_commands.checks.has_permissions(manage_guild=True)
    async def admin_stats(self, interaction: discord.Interaction):
        """View detailed bot statistics"""
        embed = discord.Embed(
            title="📊 Bot Statistics",
            color=discord.Color.blue(),
            timestamp=datetime.utcnow()
        )
        
        # Basic stats
        embed.add_field(name="Servers", value=len(self.bot.guilds), inline=True)
        embed.add_field(name="Uptime", value=self.bot.get_uptime(), inline=True)
        embed.add_field(name="Memory", value=f"{self.bot.get_memory_usage()} MB", inline=True)
        
        # Performance stats
        embed.add_field(name="Messages Checked", value=self.bot.performance_metrics["messages_checked"], inline=True)
        embed.add_field(name="Security Events", value=self.bot.performance_metrics["security_events"], inline=True)
        embed.add_field(name="Blocks", value=self.bot.performance_metrics["malicious_blocks"], inline=True)
        
        # Database stats
        if self.bot.db is not None:
            try:
                total_users = await self.bot.db.users.count_documents({})
                verified_users = await self.bot.db.users.count_documents({"verified_at": {"$exists": True}})
                banned_users = await self.bot.db.banned_users.count_documents({"is_active": True}) if hasattr(self.bot.db, 'banned_users') else 0
                banned_ips = await self.bot.db.banned_ips.count_documents({"is_active": True})
                
                embed.add_field(name="Total Users", value=total_users, inline=True)
                embed.add_field(name="Verified Users", value=verified_users, inline=True)
                embed.add_field(name="Banned Users", value=banned_users, inline=True)
                embed.add_field(name="Banned IPs", value=banned_ips, inline=True)
            except Exception as e:
                logger.error(f"Database stats error: {e}")
        
        await interaction.response.send_message(embed=embed, ephemeral=True)

class SecurityGroup(commands.Group):
    """Security commands"""
    
    def __init__(self, bot):
        super().__init__(name="security", description="Security monitoring commands")
        self.bot = bot
    
    @app_commands.command(name="scan", description="Scan recent messages for threats")
    @app_commands.checks.has_permissions(manage_messages=True)
    @app_commands.describe(limit="Number of messages to scan (max 100)")
    async def scan_messages(self, interaction: discord.Interaction, limit: int = 50):
        """Scan recent messages for security threats"""
        await interaction.response.defer(ephemeral=True)
        
        try:
            limit = min(limit, 100)
            threats_found = 0
            scanned = 0
            
            async for message in interaction.channel.history(limit=limit):
                scanned += 1
                security_check = await self.bot.check_message_security(message)
                
                if not security_check['safe']:
                    threats_found += 1
            
            embed = discord.Embed(
                title="🔍 Security Scan Results",
                color=discord.Color.green() if threats_found == 0 else discord.Color.orange(),
                timestamp=datetime.utcnow()
            )
            
            embed.add_field(name="Messages Scanned", value=scanned, inline=True)
            embed.add_field(name="Threats Found", value=threats_found, inline=True)
            embed.add_field(name="Channel", value=interaction.channel.mention, inline=True)
            
            if threats_found > 0:
                embed.add_field(
                    name="⚠️ Warning",
                    value=f"Found {threats_found} potential threat(s). Consider checking security logs.",
                    inline=False
                )
            
            await interaction.followup.send(embed=embed, ephemeral=True)
            
        except Exception as e:
            await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

# ============ BOT IMPLEMENTATION ============

class SecurityMonitorBot(commands.Bot):
    """Enhanced Discord bot with security monitoring and IP banning"""
    
    def __init__(self):
        # Configure intents
        intents = discord.Intents.default()
        intents.members = True
        intents.message_content = True
        intents.guilds = True
        
        super().__init__(
            command_prefix="!",
            intents=intents,
            help_command=None,
            case_insensitive=True
        )
        
        # Database connections
        self.db_client = None
        self.db = None
        self.redis_client = None
        self.cache_enabled = False
        
        # Security monitoring
        self.suspicious_patterns = {
            'phishing_domains': [
                r'discord-gifts\.com',
                r'discord-nitro\.com',
                r'steamcommunity\.gift',
                r'free-nitro\.xyz',
                r'discordapp\.gifts',
                r'discordnitro\.com',
                r'gift-steam\.com'
            ],
            'malicious_keywords': [
                'free nitro',
                'free steam',
                'click here',
                'limited time',
                'exclusive offer',
                'get free',
                'won a prize'
            ],
            'suspicious_url_patterns': [
                r'discord[^\.]*\.(?:com|gg|io|xyz|tk|ml|ga|cf)',
                r'steam[^\.]*\.(?:com|gg|io|xyz|tk|ml|ga|cf)',
                r'nitro[^\.]*\.(?:com|gg|io|xyz|tk|ml|ga|cf)'
            ]
        }
        
        # Performance tracking
        self.performance_metrics = {
            "start_time": time.time(),
            "commands_executed": 0,
            "security_events": 0,
            "messages_checked": 0,
            "malicious_blocks": 0,
            "errors": 0,
            "auto_kicks": 0
        }
        
        # Security events tracking
        self.security_events = []
        
        # Allowed domains
        self.allowed_domains = {
            'discord.com', 'discord.gg', 'github.com', 'youtube.com',
            'twitch.tv', 'twitter.com', 'reddit.com', 'wikipedia.org',
            'google.com', 'youtu.be'
        }
    
    async def setup_databases(self):
        """Initialize database connections"""
        try:
            # MongoDB
            self.db_client = AsyncIOMotorClient(
                Config.MONGODB_URI,
                maxPoolSize=50,
                minPoolSize=10,
                serverSelectionTimeoutMS=5000
            )
            
            await self.db_client.admin.command('ping')
            self.db = self.db_client[Config.DATABASE_NAME]
            
            logger.info("✅ Bot connected to MongoDB")
            
            # Create indexes
            await self.create_indexes()
            
            # Redis for caching
            redis_url = getattr(Config, 'REDIS_URL', None)
            if redis_url:
                self.redis_client = redis.from_url(
                    redis_url,
                    decode_responses=True,
                    socket_timeout=5
                )
                await self.redis_client.ping()
                self.cache_enabled = True
                logger.info("✅ Redis connected")
                
        except Exception as e:
            logger.error(f"❌ Database setup failed: {e}")
            self.db = None
    
    async def create_indexes(self):
        """Create database indexes"""
        if self.db is None:
            return
        
        try:
            # Users collection
            await self.db.users.create_index("discord_id", unique=True)
            await self.db.users.create_index("ip_address")
            await self.db.users.create_index("verified_at")
            await self.db.users.create_index("is_banned")
            
            # Banned collections
            await self.db.banned_users.create_index("discord_id")
            await self.db.banned_users.create_index("is_active")
            await self.db.banned_users.create_index("guild_id")
            
            await self.db.banned_ips.create_index("ip_address", unique=True)
            await self.db.banned_ips.create_index("is_active")
            await self.db.banned_ips.create_index("guild_id")
            
            # Security logs
            await self.db.security_logs.create_index("timestamp")
            await self.db.security_logs.create_index("guild_id")
            await self.db.security_logs.create_index("user_id")
            
            logger.info("✅ Database indexes created")
            
        except Exception as e:
            logger.error(f"Failed to create indexes: {e}")
    
    # ============ SECURITY METHODS ============
    
    async def check_message_security(self, message: discord.Message) -> Dict[str, Any]:
        """Check message for security threats"""
        if message.author.bot:
            return {"safe": True, "threats": []}
        
        threats = []
        content = message.content.lower()
        
        # Check for @everyone/@here spam
        if (content.count('@everyone') > 2 or content.count('@here') > 2) and not message.author.guild_permissions.mention_everyone:
            threats.append({
                "type": "mass_mention",
                "severity": "high",
                "details": f"Excessive @everyone/@here mentions"
            })
        
        # Check for suspicious keywords
        for keyword in self.suspicious_patterns['malicious_keywords']:
            if keyword in content:
                threats.append({
                    "type": "suspicious_keyword",
                    "severity": "medium",
                    "details": f"Contains suspicious keyword: {keyword}"
                })
        
        # Check URLs
        urls = re.findall(r'https?://[^\s]+', message.content)
        for url in urls:
            threat = await self.check_url_threat(url, message.guild.id if message.guild else None)
            if threat:
                threats.append(threat)
        
        return {
            "safe": len(threats) == 0,
            "threats": threats,
            "message_id": str(message.id),
            "author_id": str(message.author.id),
            "channel_id": str(message.channel.id),
            "guild_id": str(message.guild.id) if message.guild else None
        }
    
    async def check_url_threat(self, url: str, guild_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Check if URL is malicious"""
        try:
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc.lower()
            
            # Remove port and www
            domain = domain.replace('www.', '').split(':')[0]
            
            # Check against phishing domains
            for pattern in self.suspicious_patterns['phishing_domains']:
                if re.search(pattern, domain):
                    return {
                        "type": "phishing_domain",
                        "severity": "critical",
                        "details": f"Phishing domain detected: {domain}",
                        "url": url,
                        "domain": domain
                    }
            
            return None
            
        except Exception as e:
            logger.error(f"URL check error: {e}")
            return None
    
    async def handle_malicious_message(self, message: discord.Message, threats: List[Dict[str, Any]]):
        """Handle malicious message"""
        try:
            # Delete the message
            await message.delete()
            
            # Send warning to user
            try:
                warning_embed = discord.Embed(
                    title="⚠️ Message Removed - Security Alert",
                    description="Your message was removed for security reasons.",
                    color=discord.Color.orange(),
                    timestamp=datetime.utcnow()
                )
                
                warning_embed.add_field(
                    name="Reason",
                    value="\n".join([f"• {t['details']}" for t in threats[:3]]),
                    inline=False
                )
                
                await message.author.send(embed=warning_embed)
            except discord.Forbidden:
                pass  # User has DMs disabled
            
            self.performance_metrics["malicious_blocks"] += 1
            return True
            
        except discord.Forbidden:
            logger.error(f"No permission to delete message in {message.guild.name}")
            return False
        except Exception as e:
            logger.error(f"Error handling malicious message: {e}")
            return False
    
    async def check_and_kick_banned_users(self, member: discord.Member):
        """Check if member is banned and kick them"""
        try:
            # Check if user is banned
            if self.db is not None:
                user_ban = await self.db.banned_users.find_one({
                    "discord_id": str(member.id),
                    "is_active": True,
                    "guild_id": str(member.guild.id)
                })
                
                if user_ban:
                    # Kick the user
                    await member.kick(reason=f"Banned: {user_ban.get('reason', 'No reason provided')}")
                    
                    # Try to DM them
                    try:
                        dm_embed = discord.Embed(
                            title="🚨 AUTO-KICKED: You are banned",
                            description=f"You were automatically kicked from **{member.guild.name}** because you are banned.",
                            color=discord.Color.red()
                        )
                        dm_embed.add_field(name="Reason", value=user_ban.get('reason', 'No reason provided'), inline=False)
                        dm_embed.add_field(name="Ban Type", value="Account ban", inline=False)
                        dm_embed.set_footer(text="This ban is permanent unless appealed to server staff")
                        
                        await member.send(embed=dm_embed)
                    except:
                        pass
                    
                    self.performance_metrics["auto_kicks"] += 1
                    return True
                
                # Check if IP is banned
                user_data = await self.db.users.find_one({"discord_id": str(member.id)})
                if user_data and user_data.get("ip_address"):
                    ip_ban = await self.db.banned_ips.find_one({
                        "ip_address": user_data["ip_address"],
                        "is_active": True,
                        "guild_id": str(member.guild.id)
                    })
                    
                    if ip_ban:
                        # Kick the user
                        await member.kick(reason=f"IP Banned: {ip_ban.get('reason', 'No reason provided')}")
                        
                        # Try to DM them
                        try:
                            dm_embed = discord.Embed(
                                title="🚨 AUTO-KICKED: Your IP is banned",
                                description=f"You were automatically kicked from **{member.guild.name}** because your IP address is banned.",
                                color=discord.Color.red()
                            )
                            dm_embed.add_field(name="Reason", value=ip_ban.get('reason', 'No reason provided'), inline=False)
                            dm_embed.add_field(name="Ban Type", value="IP ban", inline=False)
                            dm_embed.add_field(name="Your IP", value=f"`{user_data['ip_address']}`", inline=False)
                            dm_embed.set_footer(text="This ban is permanent unless appealed to server staff")
                            
                            await member.send(embed=dm_embed)
                        except:
                            pass
                        
                        self.performance_metrics["auto_kicks"] += 1
                        return True
            
            return False
            
        except discord.Forbidden:
            logger.error(f"No permission to kick {member} in {member.guild.name}")
            return False
        except Exception as e:
            logger.error(f"Auto-kick error for {member}: {e}")
            return False
    
    async def log_security_event(self, event_type: str, source, 
                               details: Dict[str, Any], action_taken: str = "none"):
        """Log security event"""
        try:
            if isinstance(source, discord.Interaction):
                user_id = str(source.user.id)
                username = str(source.user)
                guild_id = str(source.guild.id) if source.guild else None
                channel_id = str(source.channel.id) if source.channel else None
            elif isinstance(source, discord.Message):
                user_id = str(source.author.id)
                username = str(source.author)
                guild_id = str(source.guild.id) if source.guild else None
                channel_id = str(source.channel.id)
            elif isinstance(source, (discord.Member, discord.User)):
                user_id = str(source.id)
                username = str(source)
                guild_id = str(source.guild.id) if isinstance(source, discord.Member) and source.guild else None
                channel_id = None
            else:
                # Default
                user_id = "system"
                username = "System"
                guild_id = None
                channel_id = None
            
            event = {
                "type": event_type,
                "user_id": user_id,
                "username": username,
                "guild_id": guild_id,
                "channel_id": channel_id,
                "message_id": None,
                "message_content": None,
                "details": details,
                "action_taken": action_taken,
                "timestamp": datetime.utcnow(),
                "bot_version": "2.0.0"
            }
            
            # Store in memory buffer
            self.security_events.append(event)
            if len(self.security_events) > 1000:
                self.security_events = self.security_events[-1000:]
            
            # Store in database
            if self.db is not None:
                try:
                    await self.db.security_logs.insert_one(event)
                except Exception as e:
                    logger.error(f"Failed to log security event: {e}")
            
            self.performance_metrics["security_events"] += 1
            
            return event
            
        except Exception as e:
            logger.error(f"Log security event error: {e}")
            return None
    
    # ============ BOT EVENTS ============
    
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
        
        # Setup databases
        await self.setup_databases()
        
        # Sync commands
        try:
            synced = await self.tree.sync()
            logger.info(f"✅ Synced {len(synced)} command(s)")
        except Exception as e:
            logger.error(f"❌ Command sync failed: {e}")
        
        # Start background tasks
        self.start_background_tasks()
        
        logger.info("🤖 Security bot fully initialized and ready")
    
    async def on_member_join(self, member: discord.Member):
        """Check new members for bans and auto-kick"""
        # Check if member is banned
        kicked = await self.check_and_kick_banned_users(member)
        
        if kicked:
            # Log the auto-kick
            await self.log_security_event(
                "AUTO_KICK_BANNED_USER",
                member,
                {
                    "severity": "high",
                    "details": f"Auto-kicked banned user {member} on join",
                    "reason": "User or IP is banned"
                },
                action_taken="user_kicked"
            )
    
    async def on_message(self, message: discord.Message):
        """Monitor all messages for security threats"""
        # Don't process bot messages
        if message.author.bot:
            return
        
        self.performance_metrics["messages_checked"] += 1
        
        # Check message security
        security_check = await self.check_message_security(message)
        
        if not security_check['safe'] and security_check['threats']:
            # Handle malicious message
            await self.handle_malicious_message(message, security_check['threats'])
        
        # Process commands
        await self.process_commands(message)
    
    # ============ BACKGROUND TASKS ============
    
    def start_background_tasks(self):
        """Start all background tasks"""
        tasks_to_start = [
            self.security_report,
            self.cleanup_old_logs
        ]
        
        for task in tasks_to_start:
            if not task.is_running():
                task.start()
                logger.info(f"✅ Started background task: {task.__name__}")
    
    @tasks.loop(hours=1)
    async def security_report(self):
        """Send hourly security report"""
        try:
            report = {
                "period": "1 hour",
                "messages_checked": self.performance_metrics["messages_checked"],
                "security_events": self.performance_metrics["security_events"],
                "malicious_blocks": self.performance_metrics["malicious_blocks"],
                "auto_kicks": self.performance_metrics["auto_kicks"],
                "guilds_monitored": len(self.guilds),
                "timestamp": datetime.utcnow().isoformat()
            }
            
            # Reset counters
            self.performance_metrics["messages_checked"] = 0
            self.performance_metrics["security_events"] = 0
            self.performance_metrics["malicious_blocks"] = 0
            self.performance_metrics["auto_kicks"] = 0
            
            logger.info(f"📊 Hourly Report: {report}")
            
        except Exception as e:
            logger.error(f"Security report error: {e}")
    
    @tasks.loop(hours=24)
    async def cleanup_old_logs(self):
        """Cleanup old security logs"""
        try:
            if self.db is not None:
                # Keep logs for 30 days
                cutoff = datetime.utcnow() - timedelta(days=30)
                
                result = await self.db.security_logs.delete_many({
                    "timestamp": {"$lt": cutoff}
                })
                
                if result.deleted_count > 0:
                    logger.info(f"🧹 Cleaned {result.deleted_count} old security logs")
        
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
    
    async def setup_hook(self):
        """Setup slash commands"""
        # Add command groups
        self.tree.add_command(VerificationGroup(self))
        self.tree.add_command(AdminGroup(self))
        self.tree.add_command(SecurityGroup(self))
        
        # Add individual commands
        @self.tree.command(name="ping", description="Check bot latency")
        async def ping_command(interaction: discord.Interaction):
            """Check bot latency"""
            latency = round(self.latency * 1000)
            
            embed = discord.Embed(
                title="🏓 Pong!",
                color=discord.Color.green() if latency < 100 else discord.Color.orange()
            )
            
            embed.add_field(name="Bot Latency", value=f"{latency}ms", inline=True)
            embed.add_field(name="Uptime", value=self.get_uptime(), inline=True)
            embed.add_field(name="Auto-Kicks", value=self.performance_metrics["auto_kicks"], inline=True)
            embed.add_field(name="Security Events", value=self.performance_metrics["security_events"], inline=True)
            embed.add_field(name="Messages Checked", value=self.performance_metrics["messages_checked"], inline=True)
            embed.add_field(name="Guilds", value=len(self.guilds), inline=True)
            
            await interaction.response.send_message(embed=embed, ephemeral=True)
        
        @self.tree.command(name="help", description="Show help information")
        async def help_command(interaction: discord.Interaction):
            """Show help"""
            embed = discord.Embed(
                title="🤖 Bot Help & Commands",
                description="Here are all available commands:",
                color=discord.Color.blue(),
                timestamp=datetime.utcnow()
            )
            
            # Verification commands
            embed.add_field(
                name="🔐 Verification Commands",
                value="• `/verify setup` - Setup verification panel\n"
                      "• `/verify status [user]` - Check verification status",
                inline=False
            )
            
            # Admin commands
            embed.add_field(
                name="👑 Admin Commands",
                value="• `/admin ban <user> [reason]` - Ban user (with IP ban & auto-kick)\n"
                      "• `/admin ipban <ip> [reason]` - Ban IP address directly\n"
                      "• `/admin unban <identifier>` - Unban user or IP\n"
                      "• `/admin banlist` - View banned users and IPs\n"
                      "• `/admin stats` - View bot statistics",
                inline=False
            )
            
            # Security commands
            embed.add_field(
                name="🛡️ Security Commands",
                value="• `/security scan [limit]` - Scan messages for threats\n"
                      "• `/ping` - Check bot latency\n"
                      "• `/help` - Show this help",
                inline=False
            )
            
            embed.add_field(
                name="⚡ Auto-Kick Feature",
                value="Users who are banned (by account or IP) will be automatically kicked when they try to join the server.",
                inline=False
            )
            
            embed.set_footer(text="Powered by KoalaHub Security | Auto-Kick System Active")
            
            await interaction.response.send_message(embed=embed, ephemeral=True)
    
    async def close(self):
        """Clean shutdown"""
        logger.info("🛑 Shutting down bot...")
        
        # Stop background tasks
        tasks = [
            self.security_report,
            self.cleanup_old_logs
        ]
        
        for task in tasks:
            if task.is_running():
                task.cancel()
        
        # Close database connections
        if self.db_client:
            self.db_client.close()
        
        if self.redis_client:
            await self.redis_client.close()
        
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