"""
Discord Verification System - Bot Implementation
Simplified version without monetization
"""

import discord
from discord.ext import commands, tasks
from discord import app_commands
from discord.ui import View, Button
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
import string
from motor.motor_asyncio import AsyncIOMotorClient
import redis.asyncio as redis
import psutil
import humanize

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import Config
from utils.logger import logger
from utils.password import PasswordManager

# ============ BOT IMPLEMENTATION ============

class VerificationBot(commands.Bot):
    """Simplified Discord bot without monetization"""
    
    def __init__(self):
        # Configure intents
        intents = discord.Intents.default()
        intents.members = True
        intents.message_content = True
        intents.guilds = True
        
        super().__init__(
            command_prefix="/",
            intents=intents,
            help_command=None,
            case_insensitive=True
        )
        
        # Database connections
        self.db_client = None
        self.db = None
        self.redis_client = None
        self.cache_enabled = False
        
        # Performance tracking
        self.performance_metrics = {
            "start_time": time.time(),
            "commands_executed": 0,
            "verifications_processed": 0,
            "roles_assigned": 0,
            "errors": 0
        }
        
        # Security tracking
        self.security_events = []
        
        # Pending verifications
        self.pending_verifications = {}
        self.failed_attempts = {}
        
        # Setup databases
        asyncio.create_task(self.setup_databases())
    
    async def setup_databases(self):
        """Initialize database connections"""
        try:
            # MongoDB
            self.db_client = AsyncIOMotorClient(
                Config.MONGODB_URI,
                maxPoolSize=100,
                minPoolSize=10,
                serverSelectionTimeoutMS=5000
            )
            
            await self.db_client.admin.command('ping')
            self.db = self.db_client[Config.DATABASE_NAME]
            
            logger.info("✅ Bot connected to MongoDB")
            
            # Create indexes
            await self.create_indexes()
            
            # Redis for caching
            try:
                redis_url = getattr(Config, 'REDIS_URL', None)
                if redis_url:
                    # Use redis.asyncio instead of aioredis
                    self.redis_client = redis.from_url(
                        redis_url,
                        decode_responses=True,
                        socket_timeout=5,
                        socket_connect_timeout=5
                    )
                    await self.redis_client.ping()
                    self.cache_enabled = True
                    logger.info("✅ Redis connected")
                else:
                    logger.info("ℹ️ Redis not configured")
            except Exception as e:
                logger.warning(f"⚠️ Redis connection failed: {e}")
                self.cache_enabled = False
                
        except Exception as e:
            logger.error(f"❌ Database setup failed: {e}")
            self.db = None
    
    async def create_indexes(self):
        """Create database indexes for performance"""
        if self.db is None:
            return
        
        indexes = [
            ("users", [("discord_id", 1)], {"unique": True}),
            ("users", [("verified_at", -1)]),
            ("users", [("is_banned", 1)]),
            ("verification_logs", [("timestamp", -1)]),
            ("verification_logs", [("discord_id", 1)]),
            ("security_logs", [("timestamp", -1)]),
            ("banned_ips", [("ip_address", 1)], {"unique": True})
        ]
        
        for collection, keys, *options in indexes:
            try:
                opts = options[0] if options else {}
                await self.db[collection].create_index(keys, **opts)
            except Exception as e:
                logger.error(f"Failed to create index on {collection}: {e}")
    
    # ============ CACHE METHODS ============
    
    async def cache_get(self, key: str):
        """Get value from cache"""
        if not self.cache_enabled or not self.redis_client:
            return None
        
        try:
            value = await self.redis_client.get(key)
            if value:
                try:
                    return json.loads(value)
                except:
                    return value
            return None
        except Exception as e:
            logger.warning(f"Cache get error: {e}")
            return None
    
    async def cache_set(self, key: str, value, expire: int = 300):
        """Set value in cache"""
        if not self.cache_enabled or not self.redis_client:
            return False
        
        try:
            if isinstance(value, (dict, list)):
                value = json.dumps(value)
            await self.redis_client.setex(key, expire, value)
            return True
        except Exception as e:
            logger.warning(f"Cache set error: {e}")
            return False
    
    async def cache_delete(self, key: str):
        """Delete value from cache"""
        if not self.cache_enabled or not self.redis_client:
            return False
        
        try:
            await self.redis_client.delete(key)
            return True
        except Exception as e:
            logger.warning(f"Cache delete error: {e}")
            return False
    
    # ============ SECURITY METHODS ============
    
    async def log_security_event(self, event_type: str, user_id: str = None, 
                               guild_id: str = None, details: str = "", level: str = "INFO"):
        """Log security event"""
        event = {
            "type": event_type,
            "user_id": user_id,
            "guild_id": guild_id,
            "details": details[:500],
            "level": level,
            "timestamp": datetime.utcnow()
        }
        
        # Store in memory buffer
        self.security_events.append(event)
        if len(self.security_events) > 1000:
            self.security_events = self.security_events[-1000:]
        
        # Store in database
        if self.db:
            try:
                await self.db.security_logs.insert_one(event)
            except Exception as e:
                logger.error(f"Failed to log security event: {e}")
        
        # Local logging
        log_msg = f"SECURITY {level}: {event_type} - User: {user_id} - Details: {details}"
        if level == "ERROR":
            logger.error(log_msg)
        elif level == "WARNING":
            logger.warning(log_msg)
        else:
            logger.info(log_msg)
    
    async def send_webhook(self, embed: discord.Embed, webhook_url: str):
        """Send embed to webhook"""
        if not webhook_url:
            return
        
        try:
            async with aiohttp.ClientSession() as session:
                webhook = discord.Webhook.from_url(webhook_url, session=session)
                await webhook.send(embed=embed)
        except Exception as e:
            logger.error(f"Webhook error: {e}")
    
    # ============ BOT EVENTS ============
    
    async def on_ready(self):
        """Bot ready event"""
        logger.info(f'✅ Bot logged in as {self.user}')
        logger.info(f'✅ Connected to {len(self.guilds)} guild(s)')
        
        # Set status
        await self.change_presence(
            activity=discord.Activity(
                type=discord.ActivityType.watching,
                name=f"verifications | {len(self.guilds)} servers"
            ),
            status=discord.Status.online
        )
        
        # Sync commands
        try:
            synced = await self.tree.sync()
            logger.info(f"✅ Synced {len(synced)} command(s)")
        except Exception as e:
            logger.error(f"❌ Command sync failed: {e}")
        
        # Start background tasks
        self.start_background_tasks()
        
        logger.info("🤖 Bot fully initialized and ready")
    
    def start_background_tasks(self):
        """Start all background tasks"""
        tasks_to_start = [
            self.check_verifications,
            self.cleanup_pending,
            self.update_status,
            self.performance_monitor
        ]
        
        for task in tasks_to_start:
            if not task.is_running():
                task.start()
                logger.info(f"✅ Started background task: {task.__name__}")
    
    async def on_guild_join(self, guild: discord.Guild):
        """Bot added to new guild"""
        logger.info(f"✅ Joined new guild: {guild.name} (ID: {guild.id}, Members: {guild.member_count})")
        
        # Send welcome message
        embed = discord.Embed(
            title="🎉 Thanks for adding Verification Bot!",
            description="I'll help you manage server verifications with advanced security features.",
            color=discord.Color.green()
        )
        
        embed.add_field(name="Quick Start", value="Use `/setup` to create verification panel", inline=False)
        embed.add_field(name="Features", value="• Advanced security checks\n• VPN detection\n• Rate limiting\n• Admin dashboard", inline=False)
        
        # Find system channel or first text channel
        channel = guild.system_channel
        if not channel:
            for ch in guild.text_channels:
                if ch.permissions_for(guild.me).send_messages:
                    channel = ch
                    break
        
        if channel:
            try:
                await channel.send(embed=embed)
            except:
                pass
        
        # Log to webhook
        alert_embed = discord.Embed(
            title="➕ Bot Added to Server",
            description=f"**Server:** {guild.name}\n**ID:** {guild.id}\n**Members:** {guild.member_count}",
            color=discord.Color.blue(),
            timestamp=datetime.utcnow()
        )
        
        await self.send_webhook(alert_embed, Config.LOGS_WEBHOOK)
    
    async def on_member_join(self, member: discord.Member):
        """Member joined server - check if already verified"""
        await self.check_existing_verification(member)
    
    async def check_existing_verification(self, member: discord.Member):
        """Check if new member is already verified"""
        if not self.db or not Config.VERIFIED_ROLE_ID:
            return
        
        try:
            user_data = await self.db.users.find_one({
                "discord_id": str(member.id),
                "verified_at": {"$exists": True},
                "is_banned": {"$ne": True}
            })
            
            if user_data and not user_data.get('role_added', False):
                verified_role = member.guild.get_role(int(Config.VERIFIED_ROLE_ID))
                if verified_role and verified_role not in member.roles:
                    await member.add_roles(verified_role)
                    
                    # Update database
                    await self.db.users.update_one(
                        {"discord_id": str(member.id)},
                        {"$set": {
                            "role_added": True,
                            "role_added_at": datetime.utcnow(),
                            "last_seen": datetime.utcnow()
                        }}
                    )
                    
                    logger.info(f"✅ Auto-verified rejoining member: {member.name}")
                    
                    # Clear from pending
                    if str(member.id) in self.pending_verifications:
                        del self.pending_verifications[str(member.id)]
        
        except Exception as e:
            logger.error(f"Auto-verification error: {e}")
    
    # ============ BACKGROUND TASKS ============
    
    @tasks.loop(seconds=30)
    async def check_verifications(self):
        """Check and process pending verifications"""
        if not self.db or not Config.VERIFIED_ROLE_ID:
            return
        
        try:
            # Get pending verifications
            cursor = self.db.users.find({
                "verified_at": {"$exists": True},
                "role_added": {"$ne": True},
                "is_banned": {"$ne": True}
            }).limit(50)
            
            unprocessed_users = await cursor.to_list(length=50)
            
            processed = 0
            failed = 0
            
            for user in unprocessed_users:
                success = await self.process_verification(user)
                if success:
                    processed += 1
                else:
                    failed += 1
                
                # Rate limiting
                await asyncio.sleep(0.1)
            
            if processed > 0:
                logger.info(f"✅ Processed {processed} verifications ({failed} failed)")
                self.performance_metrics["verifications_processed"] += processed
            
        except Exception as e:
            logger.error(f"Verification check error: {e}")
            self.performance_metrics["errors"] += 1
    
    async def process_verification(self, user: Dict) -> bool:
        """Process single user verification"""
        discord_id = user.get('discord_id')
        
        for guild in self.guilds:
            try:
                member = await guild.fetch_member(int(discord_id))
                if member:
                    verified_role = guild.get_role(int(Config.VERIFIED_ROLE_ID))
                    if verified_role and verified_role not in member.roles:
                        await member.add_roles(verified_role)
                        
                        # Update database
                        await self.db.users.update_one(
                            {"discord_id": discord_id},
                            {"$set": {
                                "role_added": True,
                                "role_added_at": datetime.utcnow(),
                                "last_seen": datetime.utcnow()
                            }}
                        )
                        
                        # Send DM notification
                        await self.send_verification_dm(member)
                        
                        # Log success
                        self.performance_metrics["roles_assigned"] += 1
                        
                        # Clear from pending
                        if discord_id in self.pending_verifications:
                            del self.pending_verifications[discord_id]
                        
                        return True
                        
            except discord.NotFound:
                continue
            except discord.Forbidden:
                logger.error(f"❌ No permission to add role in {guild.name}")
                continue
            except Exception as e:
                logger.error(f"❌ Error processing user: {e}")
                continue
        
        return False
    
    async def send_verification_dm(self, member: discord.Member):
        """Send verification complete DM"""
        try:
            embed = discord.Embed(
                title="✅ Verification Complete!",
                description="Your verification has been processed successfully.",
                color=discord.Color.green(),
                timestamp=datetime.utcnow()
            )
            
            embed.add_field(name="Username", value=member.name, inline=True)
            embed.add_field(name="Server", value=member.guild.name, inline=True)
            embed.set_footer(text="Thank you for verifying!")
            
            await member.send(embed=embed)
            
        except discord.Forbidden:
            pass  # User has DMs disabled
        except Exception as e:
            logger.warning(f"Failed to send DM to {member}: {e}")
    
    @tasks.loop(minutes=10)
    async def cleanup_pending(self):
        """Cleanup old pending verifications"""
        current_time = time.time()
        
        # Clean old pending verifications (7 days)
        expired = [
            uid for uid, data in self.pending_verifications.items()
            if current_time - data.get("first_attempt", current_time) > 604800
        ]
        
        for uid in expired:
            username = self.pending_verifications[uid].get("username", "Unknown")
            logger.info(f"🗑️  Cleaning old pending verification: {username} ({uid})")
            
            if self.db:
                await self.db.users.update_one(
                    {"discord_id": uid},
                    {"$set": {
                        "is_blacklisted": True,
                        "blacklist_reason": "Never joined after 7 days"
                    }}
                )
            
            del self.pending_verifications[uid]
    
    @tasks.loop(minutes=5)
    async def update_status(self):
        """Update bot status"""
        try:
            servers = len(self.guilds)
            verifications = self.performance_metrics["verifications_processed"]
            
            statuses = [
                f"{servers} servers",
                f"{verifications} verifications",
                "Verification System"
            ]
            
            current_status = statuses[int(time.time() / 60) % len(statuses)]
            
            await self.change_presence(
                activity=discord.Activity(
                    type=discord.ActivityType.watching,
                    name=current_status
                )
            )
            
        except Exception as e:
            logger.error(f"Status update error: {e}")
    
    @tasks.loop(minutes=5)
    async def performance_monitor(self):
        """Monitor performance"""
        try:
            metrics = {
                "uptime": self.get_uptime(),
                "memory_mb": self.get_memory_usage(),
                "guilds": len(self.guilds),
                "commands": self.performance_metrics["commands_executed"],
                "verifications": self.performance_metrics["verifications_processed"],
                "roles": self.performance_metrics["roles_assigned"],
                "errors": self.performance_metrics["errors"]
            }
            
            # Log every 30 minutes
            if int(time.time()) % 1800 == 0:
                logger.info(f"📊 Performance: {metrics}")
        
        except Exception as e:
            logger.error(f"Performance monitor error: {e}")
    
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
        """Setup all slash commands"""
        await self.load_commands()
        logger.info("✅ Commands loaded successfully")
    
    async def load_commands(self):
        """Load all slash commands"""
        
        # ============ HELP COMMAND ============
        
        @self.tree.command(name="help", description="Show help for all commands")
        async def help_command(interaction: discord.Interaction, category: Optional[str] = None):
            """Help command"""
            categories = {
                "🔐 Verification": [
                    ("/setup", "Setup verification system", "admin"),
                    ("/verifyinfo", "Check verification status", "mod"),
                    ("/force_verify", "Force verify user", "admin")
                ],
                "👑 Administration": [
                    ("/stats", "View statistics", "admin"),
                    ("/remove_all_verify", "Remove all verify roles", "admin"),
                    ("/banip", "Ban IP address", "admin"),
                    ("/unban", "Unban user", "admin")
                ],
                "🛡️ Moderation": [
                    ("/ban", "Ban user and IP", "mod"),
                    ("/warn", "Warn user", "mod"),
                    ("/kick", "Kick user", "mod")
                ],
                "🔧 Utility": [
                    ("/ping", "Check bot latency", "all"),
                    ("/serverinfo", "Server information", "all"),
                    ("/userinfo", "User information", "all")
                ],
                "🚨 Security": [
                    ("/audit", "View audit logs", "admin"),
                    ("/security", "Security dashboard", "admin")
                ]
            }
            
            embed = discord.Embed(
                title="🤖 Verification Bot Help",
                description="**Categories:**\n" + "\n".join([f"• {cat}" for cat in categories.keys()]),
                color=discord.Color.blue(),
                timestamp=datetime.utcnow()
            )
            
            if category:
                if category in categories:
                    commands_list = categories[category]
                    embed.title = f"📚 {category} Commands"
                    embed.description = None
                    
                    for cmd, desc, perm in commands_list:
                        embed.add_field(
                            name=cmd,
                            value=f"{desc}\n*Permission: {perm}*",
                            inline=False
                        )
                else:
                    embed = discord.Embed(
                        title="❌ Category not found",
                        description=f"Available categories: {', '.join(categories.keys())}",
                        color=discord.Color.red()
                    )
            else:
                for cat_name, commands_list in categories.items():
                    cmds = "\n".join([f"`{cmd}`" for cmd, _, _ in commands_list[:3]])
                    embed.add_field(name=cat_name, value=cmds, inline=True)
            
            embed.set_footer(text=f"Total commands: {len(self.tree.get_commands())}")
            embed.set_thumbnail(url=self.user.display_avatar.url)
            
            await interaction.response.send_message(embed=embed, ephemeral=True)
        
        # ============ SETUP COMMAND ============
        
        @self.tree.command(name="setup", description="Setup verification system")
        @app_commands.checks.has_permissions(administrator=True)
        async def setup_verification(interaction: discord.Interaction):
            """Setup verification embed"""
            # Create setup panel
            embed = discord.Embed(
                title="🔐 SERVER VERIFICATION",
                description="**Click the button below to start verification**\n\n"
                          "This verification is required to access all channels in the server.\n"
                          "Powered by advanced security systems.",
                color=discord.Color.blue(),
                timestamp=datetime.utcnow()
            )
            
            embed.add_field(
                name="⚠️ Rules & Requirements",
                value="• No VPN/Proxy (automatic ban)\n• One account per person\n• Must follow server rules",
                inline=False
            )
            
            embed.add_field(
                name="✅ Benefits",
                value="• Access to all channels\n• Priority support\n• Community features",
                inline=False
            )
            
            embed.set_footer(text="Protecting our community")
            embed.set_thumbnail(url="https://cdn.discordapp.com/attachments/1200387647512776704/1200387721230815232/koala.png")
            
            # Create view with buttons
            view = discord.ui.View(timeout=None)
            
            # Verification button
            verify_button = discord.ui.Button(
                label="✅ Start Verification",
                style=discord.ButtonStyle.green,
                url=Config.VERIFY_URL,
                emoji="🔐"
            )
            view.add_item(verify_button)
            
            # Send setup
            await interaction.response.send_message(
                "✅ Verification panel has been created!",
                ephemeral=True
            )
            
            await interaction.channel.send(embed=embed, view=view)
            
            # Log setup
            await self.log_security_event(
                "VERIFICATION_SETUP",
                str(interaction.user.id),
                str(interaction.guild.id),
                f"Channel: #{interaction.channel.name}"
            )
        
        # ============ STATS COMMAND ============
        
        @self.tree.command(name="stats", description="View detailed statistics")
        @app_commands.checks.has_permissions(manage_guild=True)
        async def stats_command(interaction: discord.Interaction):
            """Statistics command"""
            await interaction.response.defer(ephemeral=True)
            
            try:
                # Get stats
                guild = interaction.guild
                stats = {
                    "server_members": guild.member_count,
                    "verified_members": 0,
                    "uptime": self.get_uptime(),
                    "memory_usage": self.get_memory_usage()
                }
                
                if self.db:
                    # Count verified members
                    verified_count = 0
                    for member in guild.members:
                        user_data = await self.db.users.find_one({"discord_id": str(member.id)})
                        if user_data and user_data.get("verified_at"):
                            verified_count += 1
                    
                    stats["verified_members"] = verified_count
                    
                    # Get total verified
                    stats["total_verified"] = await self.db.users.count_documents({"verified_at": {"$exists": True}})
                    
                    # Get today's verifications
                    today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
                    stats["today_verifications"] = await self.db.verification_logs.count_documents({
                        "timestamp": {"$gte": today},
                        "success": True
                    })
                
                embed = discord.Embed(
                    title="📊 Statistics",
                    color=discord.Color.blue(),
                    timestamp=datetime.utcnow()
                )
                
                embed.add_field(name="Server Members", value=str(stats["server_members"]), inline=True)
                embed.add_field(name="Verified Members", value=str(stats["verified_members"]), inline=True)
                embed.add_field(name="Bot Uptime", value=stats["uptime"], inline=True)
                
                if "total_verified" in stats:
                    embed.add_field(name="Total Verified", value=str(stats["total_verified"]), inline=True)
                    embed.add_field(name="Today's Verifications", value=str(stats["today_verifications"]), inline=True)
                
                embed.add_field(name="Memory Usage", value=f"{stats['memory_usage']} MB", inline=True)
                
                await interaction.followup.send(embed=embed, ephemeral=True)
                
            except Exception as e:
                logger.error(f"Stats command error: {e}")
                await interaction.followup.send("❌ Error fetching statistics.", ephemeral=True)
        
        # ============ PING COMMAND ============
        
        @self.tree.command(name="ping", description="Check bot latency")
        async def ping_command(interaction: discord.Interaction):
            """Check bot latency"""
            latency = round(self.latency * 1000)
            
            embed = discord.Embed(
                title="🏓 Pong!",
                color=discord.Color.green() if latency < 100 else discord.Color.orange()
            )
            
            embed.add_field(name="Bot Latency", value=f"{latency}ms", inline=True)
            embed.add_field(name="Database", value="Online ✅" if self.db else "Offline ❌", inline=True)
            
            await interaction.response.send_message(embed=embed, ephemeral=True)
        
        # ============ SERVERINFO COMMAND ============
        
        @self.tree.command(name="serverinfo", description="Get server information")
        async def serverinfo_command(interaction: discord.Interaction):
            """Get server information"""
            guild = interaction.guild
            
            embed = discord.Embed(
                title=f"📊 {guild.name}",
                color=discord.Color.blue(),
                timestamp=datetime.utcnow()
            )
            
            # Basic info
            embed.add_field(name="👑 Owner", value=guild.owner.mention, inline=True)
            embed.add_field(name="🆔 ID", value=guild.id, inline=True)
            embed.add_field(name="📅 Created", value=guild.created_at.strftime("%Y-%m-%d"), inline=True)
            
            # Member stats
            total = guild.member_count
            online = sum(1 for m in guild.members if m.status != discord.Status.offline)
            bots = sum(1 for m in guild.members if m.bot)
            
            embed.add_field(name="👥 Members", value=f"Total: {total}\nOnline: {online}\nBots: {bots}", inline=True)
            
            if guild.icon:
                embed.set_thumbnail(url=guild.icon.url)
            
            embed.set_footer(text=f"Requested by {interaction.user.name}")
            
            await interaction.response.send_message(embed=embed, ephemeral=True)
        
        # ============ USERINFO COMMAND ============
        
        @self.tree.command(name="userinfo", description="Get user information")
        async def userinfo_command(interaction: discord.Interaction, user: Optional[discord.Member] = None):
            """Get user information"""
            target = user or interaction.user
            
            embed = discord.Embed(
                title=f"👤 {target.name}",
                color=target.color if target.color != discord.Color.default() else discord.Color.blue(),
                timestamp=datetime.utcnow()
            )
            
            # Basic info
            embed.add_field(name="🆔 ID", value=target.id, inline=True)
            embed.add_field(name="🤖 Bot", value="Yes" if target.bot else "No", inline=True)
            embed.add_field(name="📅 Joined", value=target.joined_at.strftime("%Y-%m-%d") if target.joined_at else "Unknown", inline=True)
            
            # Account age
            account_age = (datetime.utcnow() - target.created_at).days
            embed.add_field(name="🎂 Account Age", value=f"{account_age} days", inline=True)
            
            # Verification status
            verified_role = interaction.guild.get_role(int(Config.VERIFIED_ROLE_ID)) if Config.VERIFIED_ROLE_ID else None
            is_verified = verified_role in target.roles if verified_role else False
            
            embed.add_field(name="✅ Verified", value="Yes" if is_verified else "No", inline=True)
            
            embed.set_thumbnail(url=target.display_avatar.url)
            embed.set_footer(text=f"Requested by {interaction.user.name}")
            
            await interaction.response.send_message(embed=embed, ephemeral=True)
        
        # ============ BAN COMMAND ============
        
        @self.tree.command(name="ban", description="Ban a user and their IP")
        @app_commands.checks.has_permissions(ban_members=True)
        @app_commands.describe(
            user="User to ban",
            reason="Reason for ban",
            delete_messages="Delete messages (days)"
        )
        async def ban_command(
            interaction: discord.Interaction,
            user: discord.Member,
            reason: str = "No reason provided",
            delete_messages: app_commands.Range[int, 0, 7] = 0
        ):
            """Ban command"""
            if user == interaction.user:
                await interaction.response.send_message("❌ Cannot ban yourself.", ephemeral=True)
                return
            
            if user.guild_permissions.administrator:
                await interaction.response.send_message("❌ Cannot ban administrators.", ephemeral=True)
                return
            
            await interaction.response.defer(ephemeral=True)
            
            try:
                # Get user IP from database
                user_ip = "Unknown"
                if self.db:
                    user_data = await self.db.users.find_one({"discord_id": str(user.id)})
                    if user_data:
                        user_ip = user_data.get('ip_address', 'Unknown')
                        
                        # Ban IP
                        await self.db.banned_ips.insert_one({
                            "ip_address": user_ip,
                            "discord_id": str(user.id),
                            "username": str(user),
                            "reason": reason,
                            "banned_by": str(interaction.user),
                            "banned_at": datetime.utcnow(),
                            "type": "manual"
                        })
                
                # Discord ban
                try:
                    await user.ban(reason=reason, delete_message_days=delete_messages)
                    
                    # Log ban
                    await self.log_security_event(
                        "USER_BANNED",
                        str(user.id),
                        str(interaction.guild.id),
                        f"Reason: {reason}, IP: {user_ip}",
                        "WARNING"
                    )
                    
                    # Send confirmation
                    embed = discord.Embed(
                        title="✅ User Banned",
                        description=f"**User:** {user.mention}\n**Reason:** {reason}",
                        color=discord.Color.red()
                    )
                    
                    await interaction.followup.send(embed=embed, ephemeral=True)
                    
                except discord.Forbidden:
                    await interaction.followup.send("❌ Missing permissions to ban this user.", ephemeral=True)
                
            except Exception as e:
                logger.error(f"Ban command error: {e}")
                await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)
        
        # ============ KICK COMMAND ============
        
        @self.tree.command(name="kick", description="Kick a user")
        @app_commands.checks.has_permissions(kick_members=True)
        @app_commands.describe(
            user="User to kick",
            reason="Reason for kick"
        )
        async def kick_command(
            interaction: discord.Interaction,
            user: discord.Member,
            reason: str = "No reason provided"
        ):
            """Kick command"""
            if user == interaction.user:
                await interaction.response.send_message("❌ Cannot kick yourself.", ephemeral=True)
                return
            
            if user.guild_permissions.administrator:
                await interaction.response.send_message("❌ Cannot kick administrators.", ephemeral=True)
                return
            
            try:
                await user.kick(reason=reason)
                
                embed = discord.Embed(
                    title="✅ User Kicked",
                    description=f"**User:** {user.mention}\n**Reason:** {reason}",
                    color=discord.Color.orange()
                )
                
                await interaction.response.send_message(embed=embed, ephemeral=True)
                
            except discord.Forbidden:
                await interaction.response.send_message("❌ Missing permissions to kick this user.", ephemeral=True)
            except Exception as e:
                logger.error(f"Kick command error: {e}")
                await interaction.response.send_message(f"❌ Error: {str(e)}", ephemeral=True)
        
        # ============ WARN COMMAND ============
        
        @self.tree.command(name="warn", description="Warn a user")
        @app_commands.checks.has_permissions(moderate_members=True)
        @app_commands.describe(
            user="User to warn",
            reason="Reason for warning"
        )
        async def warn_command(interaction: discord.Interaction, user: discord.Member, reason: str):
            """Warn a user"""
            if user == interaction.user:
                await interaction.response.send_message("❌ Cannot warn yourself.", ephemeral=True)
                return
            
            if user.guild_permissions.administrator:
                await interaction.response.send_message("❌ Cannot warn administrators.", ephemeral=True)
                return
            
            # Create warning
            warning_data = {
                "user_id": str(user.id),
                "moderator_id": str(interaction.user.id),
                "reason": reason,
                "timestamp": datetime.utcnow(),
                "guild_id": str(interaction.guild.id)
            }
            
            if self.db:
                await self.db.warnings.insert_one(warning_data)
            
            # Send DM to user
            try:
                embed = discord.Embed(
                    title="⚠️ You have been warned",
                    description=f"**Server:** {interaction.guild.name}\n**Reason:** {reason}",
                    color=discord.Color.orange(),
                    timestamp=datetime.utcnow()
                )
                
                await user.send(embed=embed)
                
            except discord.Forbidden:
                pass  # User has DMs disabled
            
            # Send confirmation
            embed = discord.Embed(
                title="✅ User Warned",
                description=f"**User:** {user.mention}\n**Reason:** {reason}",
                color=discord.Color.green()
            )
            
            await interaction.response.send_message(embed=embed, ephemeral=True)
    
    # ============ ERROR HANDLING ============
    
    async def on_app_command_error(self, interaction: discord.Interaction, error: app_commands.AppCommandError):
        """Handle slash command errors"""
        if isinstance(error, app_commands.MissingPermissions):
            await interaction.response.send_message(
                "❌ You don't have permission to use this command.",
                ephemeral=True
            )
        elif isinstance(error, app_commands.BotMissingPermissions):
            await interaction.response.send_message(
                "❌ I don't have permission to execute this command.",
                ephemeral=True
            )
        else:
            logger.error(f"Command error: {error}", exc_info=True)
            
            try:
                if interaction.response.is_done():
                    await interaction.followup.send(
                        "❌ An error occurred while executing this command.",
                        ephemeral=True
                    )
                else:
                    await interaction.response.send_message(
                        "❌ An error occurred while executing this command.",
                        ephemeral=True
                    )
            except:
                pass
    
    async def close(self):
        """Clean shutdown"""
        logger.info("🛑 Shutting down bot...")
        
        # Stop all background tasks
        tasks = [
            self.check_verifications,
            self.cleanup_pending,
            self.update_status,
            self.performance_monitor
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
    
    bot = VerificationBot()
    
    try:
        bot.run(Config.DISCORD_TOKEN)
    except KeyboardInterrupt:
        logger.info("🛑 Bot stopped by user")
    except Exception as e:
        logger.error(f"❌ Bot crashed: {e}")
        raise

if __name__ == "__main__":
    run_discord_bot()