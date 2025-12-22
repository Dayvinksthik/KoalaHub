import requests
import json

def send_discord_webhook(webhook_url, title, description, color):
    """Send webhook to Discord (synchronous version)"""
    if not webhook_url:
        return
        
    embed = {
        "title": title,
        "description": description,
        "color": color
    }
    
    payload = {
        "embeds": [embed]
    }
    
    try:
        response = requests.post(webhook_url, json=payload)
        if response.status_code != 204:
            print(f"Webhook failed: {response.status_code}")
    except Exception as e:
        print(f"Webhook error: {e}")