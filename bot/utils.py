import aiohttp
import json
from config import Config
import logging

async def send_webhook(webhook_url, title, description, color):
    """Send webhook to Discord"""
    if not webhook_url:
        return
        
    embed = {
        "title": title,
        "description": description,
        "color": color,
        "timestamp": ""
    }
    
    payload = {
        "embeds": [embed]
    }
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(webhook_url, json=payload) as response:
                if response.status != 204:
                    logging.error(f"Webhook failed: {response.status}")
    except Exception as e:
        logging.error(f"Webhook error: {e}")

async def log_action(bot, guild_id, action):
    """Log action to webhook"""
    if Config.LOGS_WEBHOOK:
        guild = bot.get_guild(guild_id)
        guild_name = guild.name if guild else "Unknown"
        await send_webhook(Config.LOGS_WEBHOOK, "Action Log", f"**Guild:** {guild_name}\n**Action:** {action}", 0x00ff00)