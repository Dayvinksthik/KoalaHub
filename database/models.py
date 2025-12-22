from datetime import datetime
from bson import ObjectId
import json

class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        if isinstance(o, datetime):
            return o.isoformat()
        return super().default(o)

class User:
    def __init__(self, discord_id, username, ip_address, user_agent, is_vpn=False, is_banned=False):
        self.discord_id = str(discord_id)
        self.username = username
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.is_vpn = is_vpn
        self.is_banned = is_banned
        self.verification_date = datetime.utcnow()
        self.last_seen = datetime.utcnow()
        self.attempts = 1
        
    def to_dict(self):
        return {
            "discord_id": self.discord_id,
            "username": self.username,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "is_vpn": self.is_vpn,
            "is_banned": self.is_banned,
            "verification_date": self.verification_date,
            "last_seen": self.last_seen,
            "attempts": self.attempts
        }

class BannedIP:
    def __init__(self, ip_address, discord_id, username, reason, banned_by):
        self.ip_address = ip_address
        self.discord_id = str(discord_id)
        self.username = username
        self.reason = reason
        self.banned_by = banned_by
        self.banned_date = datetime.utcnow()
        self.is_active = True
        
    def to_dict(self):
        return {
            "ip_address": self.ip_address,
            "discord_id": self.discord_id,
            "username": self.username,
            "reason": self.reason,
            "banned_by": self.banned_by,
            "banned_date": self.banned_date,
            "is_active": self.is_active
        }