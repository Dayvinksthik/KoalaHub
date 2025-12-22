from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.errors import ConnectionFailure, DuplicateKeyError
from datetime import datetime, timedelta
import logging
from config import Config
from .models import User, BannedIP, JSONEncoder

class MongoDBHandler:
    def __init__(self):
        self.client = None
        self.db = None
        self.connect()
        
    def connect(self):
        try:
            self.client = MongoClient(Config.MONGODB_URI)
            self.db = self.client[Config.DATABASE_NAME]
            self.create_indexes()
            logging.info("Connected to MongoDB successfully")
        except ConnectionFailure as e:
            logging.error(f"Failed to connect to MongoDB: {e}")
            raise
            
    def create_indexes(self):
        # Create indexes for better performance
        self.db.users.create_index([("discord_id", ASCENDING)], unique=True)
        self.db.users.create_index([("ip_address", ASCENDING)])
        self.db.users.create_index([("is_banned", ASCENDING)])
        
        self.db.banned_ips.create_index([("ip_address", ASCENDING)], unique=True)
        self.db.banned_ips.create_index([("discord_id", ASCENDING)])
        self.db.banned_ips.create_index([("is_active", ASCENDING)])
        
        self.db.verification_logs.create_index([("discord_id", ASCENDING)])
        self.db.verification_logs.create_index([("timestamp", DESCENDING)])
        
    def add_user(self, user_data):
        try:
            user_dict = user_data.to_dict()
            result = self.db.users.insert_one(user_dict)
            return str(result.inserted_id)
        except DuplicateKeyError:
            # Update existing user
            self.db.users.update_one(
                {"discord_id": user_data.discord_id},
                {"$set": {
                    "username": user_data.username,
                    "ip_address": user_data.ip_address,
                    "user_agent": user_data.user_agent,
                    "is_vpn": user_data.is_vpn,
                    "last_seen": datetime.utcnow(),
                    "$inc": {"attempts": 1}
                }}
            )
            return "updated"
            
    def get_user(self, discord_id):
        return self.db.users.find_one({"discord_id": str(discord_id)})
        
    def get_user_by_ip(self, ip_address):
        return self.db.users.find_one({"ip_address": ip_address})
        
    def ban_user(self, discord_id, reason, banned_by):
        self.db.users.update_one(
            {"discord_id": str(discord_id)},
            {"$set": {"is_banned": True, "ban_reason": reason}}
        )
        
    def unban_user(self, discord_id):
        self.db.users.update_one(
            {"discord_id": str(discord_id)},
            {"$set": {"is_banned": False, "ban_reason": None}}
        )
        
    def add_banned_ip(self, banned_ip):
        try:
            banned_dict = banned_ip.to_dict()
            result = self.db.banned_ips.insert_one(banned_dict)
            return str(result.inserted_id)
        except DuplicateKeyError:
            # Update existing ban
            self.db.banned_ips.update_one(
                {"ip_address": banned_ip.ip_address},
                {"$set": {
                    "discord_id": banned_ip.discord_id,
                    "username": banned_ip.username,
                    "reason": banned_ip.reason,
                    "banned_by": banned_ip.banned_by,
                    "banned_date": datetime.utcnow(),
                    "is_active": True
                }}
            )
            return "updated"
            
    def is_ip_banned(self, ip_address):
        ban = self.db.banned_ips.find_one({
            "ip_address": ip_address,
            "is_active": True
        })
        return ban is not None
        
    def remove_ip_ban(self, ip_address):
        self.db.banned_ips.update_one(
            {"ip_address": ip_address},
            {"$set": {"is_active": False}}
        )
        
    def get_all_banned(self):
        return list(self.db.banned_ips.find({"is_active": True}))
        
    def get_all_verified(self, limit=100):
        return list(self.db.users.find({"is_banned": False}).sort("verification_date", DESCENDING).limit(limit))
        
    def add_verification_log(self, discord_id, username, ip_address, status, details):
        log = {
            "discord_id": str(discord_id),
            "username": username,
            "ip_address": ip_address,
            "status": status,
            "details": details,
            "timestamp": datetime.utcnow()
        }
        self.db.verification_logs.insert_one(log)
        
    def get_stats(self):
        total_users = self.db.users.count_documents({})
        banned_users = self.db.users.count_documents({"is_banned": True})
        total_bans = self.db.banned_ips.count_documents({"is_active": True})
        today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        today_verifications = self.db.verification_logs.count_documents({
            "timestamp": {"$gte": today},
            "status": "success"
        })
        
        return {
            "total_users": total_users,
            "banned_users": banned_users,
            "total_bans": total_bans,
            "today_verifications": today_verifications
        }
        
    def close(self):
        if self.client:
            self.client.close()