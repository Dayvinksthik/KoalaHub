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
import traceback

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import Config
from utils.logger import logger
from database.connection import db_manager

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
            "commands_executed": 0,
            "roles_assigned": 0
        }
        
        self.security_events: List[Dict[str, Any]] = []
        self.banned_ips = set()
        self.banned_users = set()
        
        # Load banned data
        self.load_banned_data()
    
    def load_banned_data(self):
        """Load banned users and IPs from database"""
        try:
            logger.info("✅ Bot initialized with security monitoring")
        except Exception as e:
            logger.error(f"❌ Failed to load banned data: {e}")

    async def send_webhook(self, webhook_url: str, embed_data: Dict[str, Any], webhook_name: str = "Bot Webhook") -> bool:
        """Send embed to Discord webhook"""
        if not webhook_url:
            logger.warning(f"No webhook URL provided for {webhook_name}")
            return False
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(webhook_url, json={"embeds": [embed_data]}, timeout=10) as response:
                    if response.status in [200, 204]:
                        logger.info(f"✅ Bot webhook sent to {webhook_name}")
                        return True
                    else:
                        logger.error(f"❌ Bot webhook {webhook_name} failed: {response.status} - {await response.text()}")
                        return False
        except asyncio.TimeoutError:
            logger.error(f"⏱️ Bot webhook {webhook_name} timeout")
            return False
        except aiohttp.ClientError as e:
            logger.error(f"🔌 Bot webhook {webhook_name} connection error: {e}")
            return False
        except Exception as e:
            logger.error(f"⚠️ Bot webhook {webhook_name} error: {e}")
            return False

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
                description=(
                    "This verification is required to access all channels.\n"
                    "Powered by KoalaHub security systems."
                ),
                color=discord.Color.blue(),
                timestamp=datetime.utcnow()
            )

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
            
            is_verified = verified_role and verified_role in getattr(target_user, "roles", [])
            
            # Check database status
            db_verified = False
            if db_manager.db is not None:
                user_data = db_manager.get_user(str(target_user.id))
                if user_data and user_data.get("verified_at"):
                    db_verified = True
            
            embed = discord.Embed(
                title=f"🔍 Verification Status - {getattr(target_user, 'display_name', str(target_user))}",
                color=discord.Color.green() if is_verified else discord.Color.red(),
                timestamp=datetime.utcnow()
            )
            
            embed.add_field(
                name="Role Status",
                value="✅ **Has Verified Role**" if is_verified else "❌ **No Verified Role**",
                inline=True
            )
            
            embed.add_field(
                name="Database Status",
                value="✅ **Verified in DB**" if db_verified else "❌ **Not in DB**",
                inline=True
            )
            
            embed.add_field(
                name="User",
                value=f"{getattr(target_user, 'mention', str(target_user))}\n`{getattr(target_user, 'id', 'unknown')}`",
                inline=False
            )
            
            if not is_verified and target_user == interaction.user:
                embed.add_field(
                    name="How to Verify",
                    value=f"[Click here to verify]({Config.VERIFY_URL if hasattr(Config, 'VERIFY_URL') else 'https://koalahub.onrender.com/verify'})",
                    inline=False
                )
            
            if is_verified and not db_verified:
                embed.add_field(
                    name="⚠️ Warning",
                    value="User has role but not in database. Use `/sync_roles` to fix.",
                    inline=False
                )
            
            if db_verified and not is_verified:
                embed.add_field(
                    name="ℹ️ Information",
                    value="User is verified in database but missing role. Role will be assigned automatically.",
                    inline=False
                )
            
            await interaction.response.send_message(embed=embed, ephemeral=True)
        
        # ============ ROLE ASSIGNMENT COMMANDS ============
        
        @self.tree.command(name="assign_roles", description="Manually assign verified roles to all verified users")
        @app_commands.checks.has_permissions(administrator=True)
        async def assign_roles_command(interaction: discord.Interaction):
            """Manually assign verified roles to all verified users"""
            await interaction.response.defer(ephemeral=True)
            
            try:
                if not hasattr(Config, 'VERIFIED_ROLE_ID') or not Config.VERIFIED_ROLE_ID:
                    await interaction.followup.send("❌ Verified role not configured.", ephemeral=True)
                    return
                
                verified_role = interaction.guild.get_role(int(Config.VERIFIED_ROLE_ID))
                if not verified_role:
                    await interaction.followup.send("❌ Verified role not found.", ephemeral=True)
                    return
                
                if db_manager.db is None:
                    await interaction.followup.send("❌ Database not connected.", ephemeral=True)
                    return
                
                # Get all verified users from database
                users = list(db_manager.db.users.find({
                    "verified_at": {"$ne": None},
                    "is_banned": False
                }))
                
                if not users:
                    await interaction.followup.send("✅ No verified users found in database.", ephemeral=True)
                    return
                
                assigned_count = 0
                failed_count = 0
                already_has_role = 0
                
                embed = discord.Embed(
                    title="🔄 Assigning Verified Roles",
                    description=f"Processing {len(users)} verified users...",
                    color=discord.Color.blue(),
                    timestamp=datetime.utcnow()
                )
                
                await interaction.followup.send(embed=embed, ephemeral=True)
                
                for user in users:
                    discord_id = user.get("discord_id")
                    if not discord_id:
                        continue
                    
                    try:
                        member = await interaction.guild.fetch_member(int(discord_id))
                        
                        # Check if member already has the role
                        if verified_role in member.roles:
                            already_has_role += 1
                            # Update database anyway
                            db_manager.db.users.update_one(
                                {"discord_id": discord_id},
                                {"$set": {"role_added": True}}
                            )
                            continue
                        
                        # Add the role
                        await member.add_roles(
                            verified_role, 
                            reason="Manual role assignment by admin"
                        )
                        
                        # Update database
                        db_manager.db.users.update_one(
                            {"discord_id": discord_id},
                            {"$set": {"role_added": True}}
                        )
                        
                        assigned_count += 1
                        
                        # Send DM notification
                        try:
                            dm_embed = discord.Embed(
                                title="✅ Verified Role Assigned",
                                description=f"Your verified role has been manually assigned in **{interaction.guild.name}**.",
                                color=discord.Color.green(),
                                timestamp=datetime.utcnow()
                            )
                            dm_embed.add_field(
                                name="Role",
                                value=f"**{verified_role.name}**",
                                inline=False
                            )
                            dm_embed.add_field(
                                name="Assigned By",
                                value=f"{interaction.user.mention}",
                                inline=False
                            )
                            dm_embed.set_footer(text="Powered by KoalaHub Security System")
                            
                            await member.send(embed=dm_embed)
                        except discord.Forbidden:
                            pass  # Can't DM user
                        
                        # Small delay to avoid rate limiting
                        await asyncio.sleep(0.5)
                        
                    except discord.NotFound:
                        logger.warning(f"Member {discord_id} not found in guild")
                        failed_count += 1
                    except discord.Forbidden:
                        logger.error(f"No permission to add role to {discord_id}")
                        failed_count += 1
                    except Exception as e:
                        logger.error(f"Error assigning role to {discord_id}: {e}")
                        failed_count += 1
                
                # Send result
                result_embed = discord.Embed(
                    title="✅ Role Assignment Complete",
                    color=discord.Color.green(),
                    timestamp=datetime.utcnow()
                )
                
                result_embed.add_field(name="Total Verified Users", value=str(len(users)), inline=True)
                result_embed.add_field(name="New Roles Assigned", value=str(assigned_count), inline=True)
                result_embed.add_field(name="Already Had Role", value=str(already_has_role), inline=True)
                result_embed.add_field(name="Failed", value=str(failed_count), inline=True)
                
                if assigned_count > 0:
                    result_embed.add_field(
                        name="Success", 
                        value=f"✅ Successfully assigned verified role to {assigned_count} user(s)",
                        inline=False
                    )
                
                await interaction.edit_original_response(embed=result_embed)
                
                # Log the action
                self.log_security_event(
                    "MANUAL_ROLE_ASSIGNMENT",
                    interaction,
                    {"assigned": assigned_count, "failed": failed_count, "total": len(users)},
                    "role_assignment"
                )
                
                # Send webhook notification
                webhook_url = os.getenv('DISCORD_LOGS_WEBHOOK')
                if webhook_url and assigned_count > 0:
                    webhook_embed = {
                        "title": "✅ Manual Role Assignment Complete",
                        "description": f"Admin {interaction.user} manually assigned verified roles",
                        "color": 0x00ff00,
                        "fields": [
                            {"name": "Admin", "value": f"{interaction.user.mention}", "inline": True},
                            {"name": "New Roles Assigned", "value": str(assigned_count), "inline": True},
                            {"name": "Total Processed", "value": str(len(users)), "inline": True},
                            {"name": "Already Had Role", "value": str(already_has_role), "inline": True},
                            {"name": "Failed", "value": str(failed_count), "inline": True}
                        ],
                        "timestamp": datetime.utcnow().isoformat(),
                        "footer": {"text": "Manual Role Assignment"}
                    }
                    await self.send_webhook(webhook_url, webhook_embed, "Role Assignment Webhook")
                
            except Exception as e:
                logger.error(f"Error in assign_roles command: {e}")
                await interaction.followup.send(f"❌ Error: {str(e)[:100]}", ephemeral=True)
        
        @self.tree.command(name="sync_roles", description="Sync database with current role holders")
        @app_commands.checks.has_permissions(administrator=True)
        async def sync_roles_command(interaction: discord.Interaction):
            """Sync database with current role holders"""
            await interaction.response.defer(ephemeral=True)
            
            try:
                if not hasattr(Config, 'VERIFIED_ROLE_ID') or not Config.VERIFIED_ROLE_ID:
                    await interaction.followup.send("❌ Verified role not configured.", ephemeral=True)
                    return
                
                verified_role = interaction.guild.get_role(int(Config.VERIFIED_ROLE_ID))
                if not verified_role:
                    await interaction.followup.send("❌ Verified role not found.", ephemeral=True)
                    return
                
                if db_manager.db is None:
                    await interaction.followup.send("❌ Database not connected.", ephemeral=True)
                    return
                
                # Get all members with the verified role
                members_with_role = []
                async for member in interaction.guild.fetch_members(limit=None):
                    if verified_role in member.roles:
                        members_with_role.append(str(member.id))
                
                # Update database for users with role
                updated_count = 0
                for discord_id in members_with_role:
                    user_data = db_manager.get_user(discord_id)
                    if user_data:
                        # Update role_added flag
                        db_manager.db.users.update_one(
                            {"discord_id": discord_id},
                            {"$set": {"role_added": True}}
                        )
                        updated_count += 1
                    else:
                        # User has role but not in database - create entry
                        user_data = {
                            "discord_id": discord_id,
                            "username": f"Synced User {discord_id}",
                            "ip_address": "0.0.0.0",
                            "user_agent": "Role Sync",
                            "verified_at": datetime.utcnow(),
                            "last_seen": datetime.utcnow(),
                            "is_banned": False,
                            "is_vpn": False,
                            "attempts": 1,
                            "role_added": True,
                            "guild_id": str(interaction.guild.id)
                        }
                        db_manager.add_user(user_data)
                        updated_count += 1
                
                embed = discord.Embed(
                    title="✅ Role Sync Complete",
                    color=discord.Color.green(),
                    timestamp=datetime.utcnow()
                )
                
                embed.add_field(name="Role", value=verified_role.name, inline=True)
                embed.add_field(name="Members With Role", value=str(len(members_with_role)), inline=True)
                embed.add_field(name="Database Updated", value=str(updated_count), inline=True)
                
                embed.add_field(
                    name="Note",
                    value="Database has been synced with current role holders.",
                    inline=False
                )
                
                await interaction.followup.send(embed=embed, ephemeral=True)
                
                logger.info(f"✅ Role sync completed by {interaction.user}: {len(members_with_role)} members with role")
                
            except Exception as e:
                logger.error(f"Error in sync_roles command: {e}")
                await interaction.followup.send(f"❌ Error: {str(e)[:100]}", ephemeral=True)
        
        # ============ UNVERIFY COMMAND ============
        
        @self.tree.command(name="unverify", description="Remove verification from a user")
        @app_commands.checks.has_permissions(administrator=True)
        @app_commands.describe(
            user="User to unverify",
            reason="Reason for unverification"
        )
        async def unverify_command(interaction: discord.Interaction, user: discord.Member, 
                                 reason: Optional[str] = "Manual unverification"):
            """Remove verification from a user"""
            await interaction.response.defer(ephemeral=True)
            
            try:
                if not hasattr(Config, 'VERIFIED_ROLE_ID') or not Config.VERIFIED_ROLE_ID:
                    await interaction.followup.send("❌ Verified role not configured.", ephemeral=True)
                    return
                
                verified_role = interaction.guild.get_role(int(Config.VERIFIED_ROLE_ID))
                if not verified_role:
                    await interaction.followup.send("❌ Verified role not found.", ephemeral=True)
                    return
                
                # Check if user has the role
                if verified_role in user.roles:
                    # Remove the role
                    await user.remove_roles(verified_role, reason=f"Unverified: {reason}")
                    role_removed = True
                else:
                    role_removed = False
                
                # Try to update database if available
                db_updated = False
                try:
                    # Try to send API request to website to update database
                    website_url = getattr(Config, 'WEBSITE_URL', '')
                    if website_url:
                        api_url = f"{website_url}/api/unverify"
                        async with aiohttp.ClientSession() as session:
                            data = {
                                "discord_id": str(user.id),
                                "reason": reason,
                                "admin": str(interaction.user.id)
                            }
                            async with session.post(api_url, json=data, timeout=5) as response:
                                if response.status == 200:
                                    db_updated = True
                                else:
                                    db_updated = False
                    else:
                        db_updated = False
                except Exception as e:
                    logger.error(f"Database update error: {e}")
                    db_updated = False
                
                # Send DM to user
                try:
                    dm_embed = discord.Embed(
                        title="🔓 Verification Removed",
                        description=f"Your verification has been removed from **{interaction.guild.name}**",
                        color=discord.Color.orange(),
                        timestamp=datetime.utcnow()
                    )
                    dm_embed.add_field(name="Reason", value=reason, inline=False)
                    dm_embed.add_field(name="Removed By", value=f"{interaction.user.mention}", inline=False)
                    
                    await user.send(embed=dm_embed)
                except Exception:
                    pass  # Can't DM user
                
                embed = discord.Embed(
                    title="✅ User Unverified",
                    color=discord.Color.orange(),
                    timestamp=datetime.utcnow()
                )
                
                embed.add_field(name="User", value=f"{user.mention} ({user.id})", inline=True)
                embed.add_field(name="Reason", value=reason, inline=True)
                embed.add_field(name="Role Removed", value="✅ Yes" if role_removed else "❌ Not had role", inline=True)
                embed.add_field(name="Database Updated", value="✅ Yes" if db_updated else "❌ Failed", inline=True)
                
                embed.add_field(
                    name="Note", 
                    value="User will need to verify again to access verified channels.",
                    inline=False
                )
                
                await interaction.followup.send(embed=embed, ephemeral=True)
                
                # Log the unverification
                self.log_security_event(
                    "USER_UNVERIFIED",
                    interaction,
                    {"reason": reason, "user": str(user)},
                    "user_unverified"
                )
                
                # Send alert to webhook
                webhook_url = os.getenv('DISCORD_ALERTS_WEBHOOK')
                if webhook_url:
                    webhook_embed = {
                        "title": "🔓 User Unverified",
                        "description": f"**{user}** has been unverified",
                        "color": 0xffa500,  # Orange
                        "fields": [
                            {"name": "User", "value": f"{user.mention} ({user.id})", "inline": True},
                            {"name": "Reason", "value": reason, "inline": True},
                            {"name": "Unverified By", "value": f"{interaction.user.mention}", "inline": True},
                            {"name": "Role Removed", "value": "Yes" if role_removed else "No", "inline": True}
                        ],
                        "timestamp": datetime.utcnow().isoformat(),
                        "footer": {"text": "Security System"}
                    }
                    await self.send_webhook(webhook_url, webhook_embed, "Alerts Webhook")
                
            except Exception as e:
                logger.error(f"Unverify error: {e}")
                await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)
        
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
                except Exception:
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
                if delete_messages and delete_messages > 0 and delete_messages <= 7:
                    try:
                        cutoff = datetime.utcnow() - timedelta(days=delete_messages)
                        
                        for channel in interaction.guild.text_channels:
                            try:
                                async for message in channel.history(limit=100, after=cutoff):
                                    if message.author.id == user.id:
                                        await message.delete()
                                        delete_count += 1
                                        await asyncio.sleep(0.5)
                            except Exception:
                                continue
                    except Exception as e:
                        logger.error(f"Message deletion error: {e}")
                
                # Remove verified role if they have it
                role_removed = False
                if hasattr(Config, 'VERIFIED_ROLE_ID') and Config.VERIFIED_ROLE_ID:
                    verified_role = interaction.guild.get_role(int(Config.VERIFIED_ROLE_ID))
                    member_obj = None
                    try:
                        member_obj = await interaction.guild.fetch_member(user.id)
                    except Exception:
                        member_obj = None
                    if verified_role and member_obj and verified_role in member_obj.roles:
                        try:
                            await member_obj.remove_roles(verified_role, reason=f"Banned: {reason}")
                            role_removed = True
                        except Exception:
                            role_removed = False
                
                embed = discord.Embed(
                    title="✅ User Banned & Kicked",
                    color=discord.Color.red(),
                    timestamp=datetime.utcnow()
                )
                
                embed.add_field(name="User", value=f"{getattr(user, 'mention', str(user))} ({user.id})", inline=True)
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

                # Send alert to webhook if configured
                webhook_url = os.getenv('DISCORD_ALERTS_WEBHOOK')
                if webhook_url:
                    webhook_embed = {
                        "title": "🚨 User Banned",
                        "description": f"**{user}** has been banned from the server",
                        "color": 0xff0000,
                        "fields": [
                            {"name": "User", "value": f"{getattr(user, 'mention', str(user))} ({user.id})", "inline": True},
                            {"name": "Reason", "value": reason, "inline": True},
                            {"name": "Banned By", "value": f"{interaction.user.mention}", "inline": True},
                            {"name": "Messages Deleted", "value": str(delete_count), "inline": True},
                            {"name": "Auto-Kick", "value": "✅ Enabled", "inline": True}
                        ],
                        "timestamp": datetime.utcnow().isoformat(),
                        "footer": {"text": "Security System"}
                    }
                    await self.send_webhook(webhook_url, webhook_embed, "Alerts Webhook")
                
            except Exception as e:
                logger.error(f"Ban error: {e}")
                try:
                    await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)
                except Exception:
                    pass
        
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
            embed.add_field(name="Roles Assigned", value=self.performance_metrics["roles_assigned"], inline=True)
            embed.add_field(name="Banned Users", value=len(self.banned_users), inline=True)
            embed.add_field(name="Latency", value=f"{round(self.latency * 1000)}ms", inline=True)
            
            # Add database stats if available
            if db_manager.db is not None:
                try:
                    total_users = db_manager.db.users.count_documents({})
                    verified_users = db_manager.db.users.count_documents({"verified_at": {"$ne": None}})
                    roles_added = db_manager.db.users.count_documents({"role_added": True})
                    
                    embed.add_field(name="Total Users (DB)", value=total_users, inline=True)
                    embed.add_field(name="Verified Users (DB)", value=verified_users, inline=True)
                    embed.add_field(name="Roles Added (DB)", value=roles_added, inline=True)
                except Exception as e:
                    logger.error(f"Error getting DB stats: {e}")
            
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
                    banned_text += f"• {getattr(user, 'mention', str(user))} (`{user_id}`)\n"
                except Exception:
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
                value="• `/setup` - Create verification panel\n• `/verify_status [user]` - Check verification status\n• `/force_verify [user]` - Manually verify a user\n• `/unverify [user]` - Remove verification from a user",
                inline=False
            )
            
            embed.add_field(
                name="👑 Admin Commands",
                value="• `/ban [user] [reason]` - Ban user (IP ban + auto-kick)\n• `/unban [user_id]` - Unban user\n• `/bot_stats` - View bot statistics\n• `/banlist` - View banned users\n• `/assign_roles` - Assign verified roles to all verified users\n• `/sync_roles` - Sync database with current role holders",
                inline=False
            )
            
            embed.add_field(
                name="🛡️ Security Commands",
                value="• `/security_scan [limit]` - Scan messages for threats\n• `/ping` - Check bot latency",
                inline=False
            )
            
            embed.add_field(
                name="⚡ Features",
                value="• **Auto-Kick System**: Banned users are automatically kicked when they try to join\n• **IP Banning**: Bans include IP addresses\n• **Security Monitoring**: Scans for malicious links\n• **Web Integration**: Connects to verification website\n• **Auto-Role Assignment**: Automatically assigns verified role to verified users",
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
                # Add the role
                await user.add_roles(verified_role, reason=f"Force verified by {interaction.user}")
                
                # Update database
                if db_manager.db is not None:
                    user_data = {
                        "discord_id": str(user.id),
                        "username": str(user),
                        "ip_address": "0.0.0.0",
                        "user_agent": "Bot Force Verify",
                        "verified_at": datetime.utcnow(),
                        "last_seen": datetime.utcnow(),
                        "is_banned": False,
                        "is_vpn": False,
                        "attempts": 1,
                        "role_added": True,
                        "guild_id": str(interaction.guild.id)
                    }
                    db_manager.add_user(user_data)
                
                embed = discord.Embed(
                    title="✅ User Force Verified",
                    description=f"**User:** {user.mention}\n**Verified by:** {interaction.user.mention}",
                    color=discord.Color.green()
                )
                
                await interaction.response.send_message(embed=embed, ephemeral=True)
                
                # Update website database if possible
                try:
                    website_url = getattr(Config, 'WEBSITE_URL', '')
                    if website_url:
                        api_url = f"{website_url}/api/force_verify"
                        async with aiohttp.ClientSession() as session:
                            data = {
                                "discord_id": str(user.id),
                                "username": str(user),
                                "admin": str(interaction.user.id)
                            }
                            async with session.post(api_url, json=data, timeout=5):
                                pass
                except Exception as e:
                    logger.error(f"Force verify website update error: {e}")
                
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
                    except Exception:
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
            except Exception:
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
                except Exception:
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
    
    @tasks.loop(minutes=1)
    async def assign_verified_roles_task(self):
        """Background task to assign verified roles to verified users"""
        try:
            if not hasattr(Config, 'GUILD_ID') or not Config.GUILD_ID:
                return
            
            if not hasattr(Config, 'VERIFIED_ROLE_ID') or not Config.VERIFIED_ROLE_ID:
                return
            
            guild = self.get_guild(int(Config.GUILD_ID))
            if not guild:
                logger.error(f"Guild with ID {Config.GUILD_ID} not found")
                return
            
            verified_role = guild.get_role(int(Config.VERIFIED_ROLE_ID))
            if not verified_role:
                logger.error(f"Verified role with ID {Config.VERIFIED_ROLE_ID} not found")
                return
            
            if db_manager.db is None:
                logger.error("Database not connected")
                return
            
            # Get verified users who don't have role_added flag
            users = list(db_manager.db.users.find({
                "verified_at": {"$ne": None},
                "role_added": False,
                "is_banned": False
            }).limit(50))  # Process 50 at a time
            
            if not users:
                return
            
            assigned_count = 0
            error_count = 0
            
            for user in users:
                try:
                    discord_id = user.get("discord_id")
                    if not discord_id:
                        continue
                    
                    # Try to get member
                    try:
                        member = await guild.fetch_member(int(discord_id))
                    except discord.NotFound:
                        logger.warning(f"Member {discord_id} not found in guild, skipping")
                        # Mark as processed anyway
                        db_manager.db.users.update_one(
                            {"discord_id": discord_id},
                            {"$set": {"role_added": True}}
                        )
                        continue
                    except discord.HTTPException as e:
                        logger.error(f"Error fetching member {discord_id}: {e}")
                        error_count += 1
                        continue
                    
                    # Check if member already has the role
                    if verified_role in member.roles:
                        logger.info(f"Member {member} already has verified role")
                        db_manager.db.users.update_one(
                            {"discord_id": discord_id},
                            {"$set": {"role_added": True}}
                        )
                        continue
                    
                    # Add the role
                    try:
                        await member.add_roles(
                            verified_role, 
                            reason="Auto-verified through KoalaHub system"
                        )
                        
                        # Update database
                        db_manager.db.users.update_one(
                            {"discord_id": discord_id},
                            {"$set": {"role_added": True}}
                        )
                        
                        # Send DM to user
                        try:
                            dm_embed = discord.Embed(
                                title="✅ Verification Complete!",
                                description=f"You have been verified in **{guild.name}**!",
                                color=discord.Color.green(),
                                timestamp=datetime.utcnow()
                            )
                            dm_embed.add_field(
                                name="Role Granted",
                                value=f"**{verified_role.name}** role has been added to your account.",
                                inline=False
                            )
                            dm_embed.add_field(
                                name="Access",
                                value="You now have access to all verified channels.",
                                inline=False
                            )
                            dm_embed.set_footer(text="Powered by KoalaHub Security System")
                            
                            await member.send(embed=dm_embed)
                            logger.info(f"✅ Sent verification DM to {member}")
                        except discord.Forbidden:
                            logger.warning(f"Could not send DM to {member}")
                        except Exception as e:
                            logger.error(f"Error sending DM to {member}: {e}")
                        
                        assigned_count += 1
                        self.performance_metrics["roles_assigned"] += 1
                        logger.info(f"✅ Assigned verified role to {member} ({discord_id})")
                        
                        # Small delay to avoid rate limiting
                        await asyncio.sleep(1)
                        
                    except discord.Forbidden:
                        logger.error(f"No permission to add role to {member}")
                        error_count += 1
                    except discord.HTTPException as e:
                        logger.error(f"Error adding role to {member}: {e}")
                        error_count += 1
                        
                except Exception as e:
                    logger.error(f"Error processing user {user.get('discord_id', 'unknown')}: {e}")
                    error_count += 1
                    continue
            
            if assigned_count > 0:
                logger.info(f"✅ Auto-assigned verified roles to {assigned_count} user(s)")
                logger.info(f"❌ Failed to assign roles to {error_count} user(s)")
                
                # Send webhook notification
                webhook_url = os.getenv('DISCORD_LOGS_WEBHOOK')
                if webhook_url and assigned_count > 0:
                    webhook_embed = {
                        "title": "✅ Auto Role Assignment",
                        "description": f"Automatically assigned verified roles to {assigned_count} user(s)",
                        "color": 0x00ff00,
                        "fields": [
                            {"name": "Success", "value": str(assigned_count), "inline": True},
                            {"name": "Failed", "value": str(error_count), "inline": True},
                            {"name": "Guild", "value": guild.name, "inline": True}
                        ],
                        "timestamp": datetime.utcnow().isoformat(),
                        "footer": {"text": "Auto-Role System"}
                    }
                    await self.send_webhook(webhook_url, webhook_embed, "Role Assignment")
        
        except Exception as e:
            logger.error(f"Error in assign_verified_roles_task: {e}")
            logger.error(traceback.format_exc())
    
    async def check_and_assign_role(self, member: discord.Member) -> bool:
        """Check if member should have verified role and assign it"""
        try:
            if not hasattr(Config, 'VERIFIED_ROLE_ID') or not Config.VERIFIED_ROLE_ID:
                return False
            
            if db_manager.db is None:
                return False
            
            # Check if user is verified in database
            user_data = db_manager.get_user(str(member.id))
            if not user_data or not user_data.get("verified_at") or user_data.get("is_banned"):
                return False
            
            verified_role = member.guild.get_role(int(Config.VERIFIED_ROLE_ID))
            if not verified_role:
                return False
            
            # Check if already has role
            if verified_role in member.roles:
                return True
            
            # Add the role
            await member.add_roles(
                verified_role,
                reason="Auto-assigned: User is verified in database"
            )
            
            # Update database
            db_manager.db.users.update_one(
                {"discord_id": str(member.id)},
                {"$set": {"role_added": True}}
            )
            
            logger.info(f"✅ Auto-assigned verified role to {member}")
            self.performance_metrics["roles_assigned"] += 1
            
            # Send welcome DM
            try:
                dm_embed = discord.Embed(
                    title="✅ Welcome to the Server!",
                    description=f"Welcome to **{member.guild.name}**!",
                    color=discord.Color.green(),
                    timestamp=datetime.utcnow()
                )
                dm_embed.add_field(
                    name="Verification Complete",
                    value="Your verification has been processed and your role has been assigned.",
                    inline=False
                )
                dm_embed.add_field(
                    name="Role",
                    value=f"**{verified_role.name}**",
                    inline=False
                )
                dm_embed.add_field(
                    name="Access",
                    value="You now have access to all verified channels.",
                    inline=False
                )
                dm_embed.set_footer(text="Powered by KoalaHub Security System")
                
                await member.send(embed=dm_embed)
            except discord.Forbidden:
                pass  # Can't DM user
            
            return True
            
        except discord.Forbidden:
            logger.error(f"No permission to add role to {member}")
        except Exception as e:
            logger.error(f"Error assigning role to {member}: {e}")
        
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
        try:
            await self.change_presence(
                activity=discord.Activity(
                    type=discord.ActivityType.watching,
                    name=f"security | {len(self.guilds)} servers"
                ),
                status=discord.Status.online
            )
        except Exception:
            pass
        
        # Start background tasks
        self.start_background_tasks()
        
        logger.info("🤖 Security bot fully initialized and ready")
    
    async def on_member_join(self, member: discord.Member):
        """Check new members for bans and assign verified role if already verified"""
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
            return
        
        # Check if user is already verified and assign role
        role_assigned = await self.check_and_assign_role(member)
        if role_assigned:
            self.log_security_event(
                "AUTO_ROLE_ASSIGNED_ON_JOIN",
                member,
                {"user": str(member), "guild": member.guild.name},
                "role_assigned"
            )
    
    async def on_member_update(self, before: discord.Member, after: discord.Member):
        """Monitor role changes"""
        # Check if verified role was removed
        if not hasattr(Config, 'VERIFIED_ROLE_ID') or not Config.VERIFIED_ROLE_ID:
            return
        
        verified_role_id = int(Config.VERIFIED_ROLE_ID)
        
        before_roles = {role.id for role in before.roles}
        after_roles = {role.id for role in after.roles}
        
        # Check if verified role was removed
        if verified_role_id in before_roles and verified_role_id not in after_roles:
            logger.info(f"⚠️ Verified role removed from {after}")
            
            # Update database
            if db_manager.db is not None:
                db_manager.db.users.update_one(
                    {"discord_id": str(after.id)},
                    {"$set": {"role_added": False}}
                )
            
            # Send alert
            webhook_url = os.getenv('DISCORD_ALERTS_WEBHOOK')
            if webhook_url:
                webhook_embed = {
                    "title": "⚠️ Verified Role Removed",
                    "description": f"Verified role was removed from **{after}**",
                    "color": 0xffa500,  # Orange
                    "fields": [
                        {"name": "User", "value": f"{after.mention} ({after.id})", "inline": True},
                        {"name": "Action", "value": "Role Removed", "inline": True}
                    ],
                    "timestamp": datetime.utcnow().isoformat(),
                    "footer": {"text": "Security System"}
                }
                await self.send_webhook(webhook_url, webhook_embed, "Alerts Webhook")
    
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
        try:
            if not self.cleanup_task.is_running():
                self.cleanup_task.start()
                logger.info("✅ Started cleanup task")
        except Exception:
            # If task isn't yet bound or another error, attempt to start safely
            try:
                self.cleanup_task.start()
                logger.info("✅ Started cleanup task")
            except Exception as e:
                logger.error(f"Failed to start cleanup task: {e}")
        
        try:
            if not self.assign_verified_roles_task.is_running():
                self.assign_verified_roles_task.start()
                logger.info("✅ Started verified role assignment task")
        except Exception as e:
            logger.error(f"Failed to start role assignment task: {e}")
    
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
        except Exception:
            return 0
    
    async def close(self):
        """Clean shutdown"""
        logger.info("🛑 Shutting down bot...")
        
        try:
            if self.cleanup_task.is_running():
                self.cleanup_task.cancel()
        except Exception:
            pass
        
        try:
            if self.assign_verified_roles_task.is_running():
                self.assign_verified_roles_task.cancel()
        except Exception:
            pass
        
        await super().close()


if __name__ == "__main__":
    # Instantiate and run the bot
    TOKEN = os.getenv("DISCORD_BOT_TOKEN") or getattr(Config, "BOT_TOKEN", None)
    if not TOKEN:
        logger.error("❌ No bot token found. Set DISCORD_BOT_TOKEN in environment or Config.BOT_TOKEN.")
        raise SystemExit("Missing bot token")
    
    bot = SecurityMonitorBot()
    try:
        bot.run(TOKEN)
    except Exception as e:
        logger.error(f"Bot terminated with error: {e}")
        raise