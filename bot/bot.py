"""
Discord Verification System - Bot Implementation
Enhanced with security monitoring and malicious link detection
"""

import discord
from discord.ext import commands, tasks
from discord import app_commands
from discord.ui import View, Button, Modal, TextInput
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
from utils.password import PasswordManager
from utils.rate_limiter import rate_limiter

# ============ BOT IMPLEMENTATION ============

class SecurityMonitorBot(commands.Bot):
    """Enhanced Discord bot with security monitoring"""
    
    def __init__(self):
        # Configure intents
        intents = discord.Intents.default()
        intents.members = True
        intents.message_content = True
        intents.guilds = True
        intents.presences = True
        
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
            "errors": 0
        }
        
        # Security events tracking
        self.security_events = []
        
        # Allowed domains (server-specific)
        self.allowed_domains = {
            'discord.com',
            'discord.gg',
            'github.com',
            'youtube.com',
            'twitch.tv',
            'twitter.com',
            'reddit.com',
            'wikipedia.org',
            'google.com',
            'youtu.be'
        }
        
        # Don't setup databases here - wait for async context
        # We'll do this in setup_hook
    
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
        
        indexes = [
            ("users", [("discord_id", 1)], {"unique": True}),
            ("users", [("verified_at", -1)]),
            ("users", [("is_banned", 1)]),
            ("security_logs", [("timestamp", -1)]),
            ("security_logs", [("guild_id", 1)]),
            ("security_logs", [("user_id", 1)]),
            ("malicious_links", [("domain", 1)]),
            ("malicious_links", [("detected_at", -1)]),
        ]
        
        for collection, keys, *options in indexes:
            try:
                opts = options[0] if options else {}
                await self.db[collection].create_index(keys, **opts)
            except Exception as e:
                logger.error(f"Failed to create index on {collection}: {e}")
    
    # ============ SECURITY MONITORING METHODS ============
    
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
        
        # Check for invite spam
        discord_invites = re.findall(r'(discord\.(?:gg|com)/[a-zA-Z0-9-]+)', message.content)
        if len(discord_invites) > 3:
            threats.append({
                "type": "invite_spam",
                "severity": "high",
                "details": f"Multiple Discord invites detected: {len(discord_invites)}"
            })
        
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
            
            # Check against suspicious patterns
            for pattern in self.suspicious_patterns['suspicious_url_patterns']:
                if re.search(pattern, domain):
                    return {
                        "type": "suspicious_domain",
                        "severity": "high",
                        "details": f"Suspicious domain pattern: {domain}",
                        "url": url,
                        "domain": domain
                    }
            
            # Check if domain is in allowed list
            if guild_id and self.db:
                # Get guild-specific allowed domains
                guild_settings = await self.db.guild_settings.find_one({"guild_id": guild_id})
                allowed_domains = set(self.allowed_domains)
                if guild_settings and 'allowed_domains' in guild_settings:
                    allowed_domains.update(guild_settings['allowed_domains'])
                
                if domain not in allowed_domains:
                    return {
                        "type": "unapproved_domain",
                        "severity": "medium",
                        "details": f"Domain not in approved list: {domain}",
                        "url": url,
                        "domain": domain
                    }
            
            return None
            
        except Exception as e:
            logger.error(f"URL check error: {e}")
            return None
    
    async def log_security_event(self, event_type: str, message: discord.Message, 
                               details: Dict[str, Any], action_taken: str = "none"):
        """Log security event to database and Discord"""
        event = {
            "type": event_type,
            "user_id": str(message.author.id),
            "username": str(message.author),
            "guild_id": str(message.guild.id) if message.guild else None,
            "channel_id": str(message.channel.id),
            "message_id": str(message.id),
            "message_content": message.content[:500],
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
        
        # Send to webhook for critical events
        if details.get('severity') in ['high', 'critical']:
            await self.send_security_alert(event, message)
        
        self.performance_metrics["security_events"] += 1
        
        return event
    
    async def send_security_alert(self, event: Dict[str, Any], message: discord.Message):
        """Send security alert to Discord"""
        color = {
            "critical": 0xff0000,
            "high": 0xff6b00,
            "medium": 0xffd700,
            "low": 0x3498db
        }.get(event['details'].get('severity', 'medium'), 0xff0000)
        
        embed = discord.Embed(
            title=f"🚨 Security Alert - {event['type'].replace('_', ' ').title()}",
            color=color,
            timestamp=datetime.utcnow()
        )
        
        embed.add_field(name="User", value=f"{message.author.mention} (`{message.author}`)", inline=True)
        embed.add_field(name="Channel", value=f"<#{message.channel.id}>", inline=True)
        embed.add_field(name="Severity", value=event['details'].get('severity', 'unknown').upper(), inline=True)
        
        if 'details' in event['details']:
            embed.add_field(name="Details", value=event['details']['details'], inline=False)
        
        if 'url' in event['details']:
            embed.add_field(name="URL", value=f"||{event['details']['url']}||", inline=False)
        
        embed.add_field(name="Action Taken", value=event['action_taken'].title(), inline=True)
        embed.add_field(name="Message", value=f"[Jump to Message]({message.jump_url})", inline=True)
        
        embed.set_footer(text=f"Security System • {message.guild.name if message.guild else 'Unknown'}")
        
        # Send to webhook
        if Config.ALERTS_WEBHOOK:
            await self.send_webhook(embed, Config.ALERTS_WEBHOOK)
    
    async def handle_malicious_message(self, message: discord.Message, threats: List[Dict[str, Any]]):
        """Handle malicious message with appropriate actions"""
        try:
            # Delete the message
            await message.delete()
            
            # Log the event
            for threat in threats:
                await self.log_security_event(
                    threat['type'],
                    message,
                    threat,
                    action_taken="message_deleted"
                )
            
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
                
                warning_embed.add_field(
                    name="Note",
                    value="Repeated violations may result in moderation action.",
                    inline=False
                )
                
                await message.author.send(embed=warning_embed)
            except discord.Forbidden:
                pass  # User has DMs disabled
            
            # Store in malicious links database
            if self.db is not None:
                for threat in threats:
                    if 'url' in threat and 'domain' in threat:
                        await self.db.malicious_links.update_one(
                            {"domain": threat['domain']},
                            {
                                "$set": {
                                    "last_detected": datetime.utcnow(),
                                    "threat_type": threat['type']
                                },
                                "$inc": {"detection_count": 1},
                                "$addToSet": {
                                    "detected_by": str(message.author.id),
                                    "guilds": str(message.guild.id) if message.guild else None
                                }
                            },
                            upsert=True
                        )
            
            self.performance_metrics["malicious_blocks"] += 1
            return True
            
        except discord.Forbidden:
            logger.error(f"No permission to delete message in {message.guild.name}")
            return False
        except Exception as e:
            logger.error(f"Error handling malicious message: {e}")
            return False
    
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
        
        # Sync commands
        try:
            synced = await self.tree.sync()
            logger.info(f"✅ Synced {len(synced)} command(s)")
        except Exception as e:
            logger.error(f"❌ Command sync failed: {e}")
        
        # Start background tasks
        self.start_background_tasks()
        
        logger.info("🤖 Security bot fully initialized and ready")
    
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
    
    async def on_message_edit(self, before: discord.Message, after: discord.Message):
        """Check edited messages for security threats"""
        if after.author.bot:
            return
        
        # Check if content changed
        if before.content != after.content:
            security_check = await self.check_message_security(after)
            
            if not security_check['safe'] and security_check['threats']:
                await self.handle_malicious_message(after, security_check['threats'])
    
    async def on_member_join(self, member: discord.Member):
        """Check new members for suspicious accounts"""
        account_age = (datetime.utcnow() - member.created_at).days
        
        if account_age < 7:  # Account less than 7 days old
            await self.log_security_event(
                "new_account_join",
                await member.guild.system_channel.send(f"{member.mention} joined") if member.guild.system_channel else None,
                {
                    "severity": "low",
                    "details": f"New account joined (age: {account_age} days)",
                    "account_age": account_age
                },
                action_taken="monitored"
            )
    
    # ============ BACKGROUND TASKS ============
    
    def start_background_tasks(self):
        """Start all background tasks"""
        tasks_to_start = [
            self.security_report,
            self.cleanup_old_logs,
            self.update_threat_intelligence
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
                "guilds_monitored": len(self.guilds),
                "timestamp": datetime.utcnow().isoformat()
            }
            
            # Reset counters
            self.performance_metrics["messages_checked"] = 0
            self.performance_metrics["security_events"] = 0
            self.performance_metrics["malicious_blocks"] = 0
            
            # Send report to webhook
            if Config.LOGS_WEBHOOK and (report['security_events'] > 0 or report['malicious_blocks'] > 0):
                embed = discord.Embed(
                    title="📊 Hourly Security Report",
                    color=discord.Color.blue(),
                    timestamp=datetime.utcnow()
                )
                
                embed.add_field(name="Messages Checked", value=report['messages_checked'], inline=True)
                embed.add_field(name="Security Events", value=report['security_events'], inline=True)
                embed.add_field(name="Blocks", value=report['malicious_blocks'], inline=True)
                embed.add_field(name="Servers", value=report['guilds_monitored'], inline=True)
                embed.add_field(name="Uptime", value=self.get_uptime(), inline=True)
                embed.add_field(name="Memory", value=f"{self.get_memory_usage()} MB", inline=True)
                
                await self.send_webhook(embed, Config.LOGS_WEBHOOK)
                
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
    
    @tasks.loop(hours=6)
    async def update_threat_intelligence(self):
        """Update threat intelligence from external sources"""
        try:
            # You can add API calls to threat intelligence feeds here
            # For now, we'll just log it
            logger.info("🔄 Updating threat intelligence...")
            
        except Exception as e:
            logger.error(f"Threat intelligence update error: {e}")
    
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
    
    async def setup_hook(self):
        """Setup all slash commands"""
        # Setup databases first
        await self.setup_databases()
        await self.load_commands()
        logger.info("✅ Commands loaded successfully")
    
    async def load_commands(self):
        """Load all slash commands"""
        
        # ============ SECURITY COMMANDS ============
        
        @self.tree.command(name="security", description="Security dashboard")
        @app_commands.checks.has_permissions(administrator=True)
        async def security_command(interaction: discord.Interaction):
            """Security dashboard"""
            await interaction.response.defer(ephemeral=True)
            
            try:
                if self.db is not None:
                    # Get security stats for this guild
                    day_ago = datetime.utcnow() - timedelta(days=1)
                    
                    stats = {
                        "today_events": await self.db.security_logs.count_documents({
                            "guild_id": str(interaction.guild.id),
                            "timestamp": {"$gte": day_ago}
                        }),
                        "total_blocks": await self.db.security_logs.count_documents({
                            "guild_id": str(interaction.guild.id),
                            "action_taken": "message_deleted"
                        }),
                        "top_threats": [],
                        "recent_events": []
                    }
                    
                    # Get top threat types
                    pipeline = [
                        {"$match": {"guild_id": str(interaction.guild.id)}},
                        {"$group": {
                            "_id": "$type",
                            "count": {"$sum": 1}
                        }},
                        {"$sort": {"count": -1}},
                        {"$limit": 5}
                    ]
                    
                    threat_counts = await self.db.security_logs.aggregate(pipeline).to_list(length=5)
                    stats["top_threats"] = threat_counts
                    
                    # Get recent events
                    recent_events = await self.db.security_logs.find({
                        "guild_id": str(interaction.guild.id)
                    }).sort("timestamp", -1).limit(5).to_list(length=5)
                    
                    embed = discord.Embed(
                        title="🚨 Security Dashboard",
                        description=f"**Server:** {interaction.guild.name}",
                        color=discord.Color.blue(),
                        timestamp=datetime.utcnow()
                    )
                    
                    # Stats
                    embed.add_field(
                        name="📊 Statistics (Last 24h)",
                        value=f"**Security Events:** {stats['today_events']}\n"
                              f"**Blocks:** {stats['total_blocks']}\n"
                              f"**Messages Checked:** {self.performance_metrics['messages_checked']}\n"
                              f"**Bot Uptime:** {self.get_uptime()}",
                        inline=False
                    )
                    
                    # Top threats
                    if stats['top_threats']:
                        threats_text = "\n".join([f"• {t['_id']}: {t['count']}" for t in stats['top_threats']])
                        embed.add_field(name="🔝 Top Threats", value=threats_text, inline=False)
                    
                    # Recent events
                    if recent_events:
                        events_text = ""
                        for event in recent_events:
                            time = event["timestamp"].strftime("%H:%M")
                            user = event.get("username", "Unknown")
                            events_text += f"`{time}` **{event['type']}** - {user}\n"
                        
                        embed.add_field(name="🕐 Recent Events", value=events_text, inline=False)
                    
                    # System status
                    embed.add_field(
                        name="🛡️ Protection Status",
                        value="✅ **Active**\n"
                              "🔗 **Link Scanning:** Enabled\n"
                              "👥 **Mass Mention:** Enabled\n"
                              "📊 **Logging:** Enabled",
                        inline=True
                    )
                    
                    embed.set_footer(text="Security System v2.0")
                    
                    await interaction.followup.send(embed=embed, ephemeral=True)
                    
                else:
                    await interaction.followup.send("Database not available.", ephemeral=True)
                    
            except Exception as e:
                logger.error(f"Security command error: {e}")
                await interaction.followup.send("❌ Error fetching security data.", ephemeral=True)
        
        @self.tree.command(name="allow_domain", description="Add a domain to allowed list")
        @app_commands.checks.has_permissions(administrator=True)
        @app_commands.describe(domain="Domain to allow (e.g., example.com)")
        async def allow_domain_command(interaction: discord.Interaction, domain: str):
            """Add domain to allowed list"""
            # Clean domain
            domain = domain.lower().replace('www.', '').split('/')[0].split(':')[0]
            
            if self.db is not None:
                await self.db.guild_settings.update_one(
                    {"guild_id": str(interaction.guild.id)},
                    {"$addToSet": {"allowed_domains": domain}},
                    upsert=True
                )
            
            # Update in-memory cache
            self.allowed_domains.add(domain)
            
            embed = discord.Embed(
                title="✅ Domain Allowed",
                description=f"**Domain:** `{domain}`\nAdded to allowed list for this server.",
                color=discord.Color.green(),
                timestamp=datetime.utcnow()
            )
            
            await interaction.response.send_message(embed=embed, ephemeral=True)
        
        @self.tree.command(name="block_domain", description="Add a domain to block list")
        @app_commands.checks.has_permissions(administrator=True)
        @app_commands.describe(domain="Domain to block (e.g., malicious.com)")
        async def block_domain_command(interaction: discord.Interaction, domain: str):
            """Add domain to block list"""
            domain = domain.lower().replace('www.', '').split('/')[0].split(':')[0]
            
            if self.db is not None:
                await self.db.guild_settings.update_one(
                    {"guild_id": str(interaction.guild.id)},
                    {"$addToSet": {"blocked_domains": domain}},
                    upsert=True
                )
            
            embed = discord.Embed(
                title="✅ Domain Blocked",
                description=f"**Domain:** `{domain}`\nAdded to block list for this server.",
                color=discord.Color.red(),
                timestamp=datetime.utcnow()
            )
            
            await interaction.response.send_message(embed=embed, ephemeral=True)
        
        @self.tree.command(name="security_logs", description="View security logs")
        @app_commands.checks.has_permissions(moderate_members=True)
        @app_commands.describe(
            user="Filter by user",
            limit="Number of logs to show (max 20)",
            days="Days to look back (max 30)"
        )
        async def security_logs_command(
            interaction: discord.Interaction,
            user: Optional[discord.User] = None,
            limit: Optional[int] = 10,
            days: Optional[int] = 7
        ):
            """View security logs"""
            await interaction.response.defer(ephemeral=True)
            
            try:
                query = {"guild_id": str(interaction.guild.id)}
                
                if user:
                    query["user_id"] = str(user.id)
                
                days = min(days or 7, 30)
                limit = min(limit or 10, 20)
                
                cutoff = datetime.utcnow() - timedelta(days=days)
                query["timestamp"] = {"$gte": cutoff}
                
                if self.db is not None:
                    cursor = self.db.security_logs.find(query) \
                        .sort("timestamp", -1) \
                        .limit(limit)
                    
                    logs = await cursor.to_list(length=limit)
                    
                    if not logs:
                        await interaction.followup.send("No security logs found.", ephemeral=True)
                        return
                    
                    embed = discord.Embed(
                        title="📋 Security Logs",
                        color=discord.Color.blue(),
                        timestamp=datetime.utcnow()
                    )
                    
                    for log in logs:
                        timestamp = log["timestamp"].strftime("%m/%d %H:%M")
                        user_mention = f"<@{log['user_id']}>" if log.get('user_id') else "Unknown"
                        
                        embed.add_field(
                            name=f"{timestamp} - {log.get('type', 'Unknown').replace('_', ' ').title()}",
                            value=f"**User:** {user_mention}\n"
                                  f"**Action:** {log.get('action_taken', 'None')}\n"
                                  f"**Details:** {log.get('details', {}).get('details', 'N/A')[:50]}",
                            inline=False
                        )
                    
                    embed.set_footer(text=f"Showing {len(logs)} logs from last {days} days")
                    
                    await interaction.followup.send(embed=embed, ephemeral=True)
                else:
                    await interaction.followup.send("Database not available.", ephemeral=True)
                    
            except Exception as e:
                logger.error(f"Security logs error: {e}")
                await interaction.followup.send("❌ Error fetching security logs.", ephemeral=True)
        
        # ============ VERIFICATION COMMANDS ============
        
        @self.tree.command(name="setup_verification", description="Setup verification panel")
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
                style=discord.ButtonStyle.green,
                url=Config.VERIFY_URL,
                emoji="🔐"
            )
            view.add_item(verify_button)
            
            await interaction.response.send_message(
                "✅ Verification panel created!",
                ephemeral=True
            )
            
            await interaction.channel.send(embed=embed, view=view)
        
        @self.tree.command(name="force_verify", description="Force verify a user")
        @app_commands.checks.has_permissions(administrator=True)
        @app_commands.describe(user="User to verify")
        async def force_verify_command(interaction: discord.Interaction, user: discord.Member):
            """Force verify a user"""
            if not Config.VERIFIED_ROLE_ID:
                await interaction.response.send_message("❌ Verified role not configured.", ephemeral=True)
                return
            
            verified_role = interaction.guild.get_role(int(Config.VERIFIED_ROLE_ID))
            if not verified_role:
                await interaction.response.send_message("❌ Verified role not found.", ephemeral=True)
                return
            
            try:
                await user.add_roles(verified_role, reason=f"Force verified by {interaction.user}")
                
                # Update database
                if self.db is not None:
                    await self.db.users.update_one(
                        {"discord_id": str(user.id)},
                        {"$set": {
                            "verified_at": datetime.utcnow(),
                            "role_added": True,
                            "username": str(user)
                        }},
                        upsert=True
                    )
                
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
        
        # ============ UTILITY COMMANDS ============
        
        @self.tree.command(name="ping", description="Check bot latency")
        async def ping_command(interaction: discord.Interaction):
            """Check bot latency"""
            latency = round(self.latency * 1000)
            
            embed = discord.Embed(
                title="🏓 Pong!",
                color=discord.Color.green() if latency < 100 else discord.Color.orange()
            )
            
            embed.add_field(name="Bot Latency", value=f"{latency}ms", inline=True)
            embed.add_field(name="Security Checks", value=f"{self.performance_metrics['messages_checked']}", inline=True)
            embed.add_field(name="Blocks", value=f"{self.performance_metrics['malicious_blocks']}", inline=True)
            
            await interaction.response.send_message(embed=embed, ephemeral=True)
        
        @self.tree.command(name="stats", description="View bot statistics")
        @app_commands.checks.has_permissions(manage_guild=True)
        async def stats_command(interaction: discord.Interaction):
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
            embed.add_field(name="Security Events", value=self.performance_metrics["security_events"], inline=True)
            embed.add_field(name="Blocks", value=self.performance_metrics["malicious_blocks"], inline=True)
            
            if self.db is not None:
                total_users = await self.db.users.count_documents({})
                verified_users = await self.db.users.count_documents({"verified_at": {"$exists": True}})
                
                embed.add_field(name="Total Users", value=total_users, inline=True)
                embed.add_field(name="Verified Users", value=verified_users, inline=True)
                embed.add_field(name="Database", value="✅ Connected", inline=True)
            
            await interaction.response.send_message(embed=embed, ephemeral=True)
    
    async def close(self):
        """Clean shutdown"""
        logger.info("🛑 Shutting down bot...")
        
        # Stop background tasks
        tasks = [
            self.security_report,
            self.cleanup_old_logs,
            self.update_threat_intelligence
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