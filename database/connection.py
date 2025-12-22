from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.errors import ConnectionFailure
import redis
import threading
import time
import json
from datetime import datetime, timedelta
from config import Config
from utils.logger import logger


class DatabaseManager:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialize()
        return cls._instance

    def _initialize(self):
        """Initialize database connections with pooling"""
        self.mongo_client = None
        self.redis_client = None
        self.db = None
        self.cache_enabled = False
        self._start_time = time.time()

        self._connect_mongodb()
        self._connect_redis()

    # ================== MONGODB ==================

    def _connect_mongodb(self):
        try:
            self.mongo_client = MongoClient(
                Config.MONGODB_URI,
                maxPoolSize=100,
                minPoolSize=10,
                maxIdleTimeMS=30000,
                socketTimeoutMS=5000,
                connectTimeoutMS=5000,
                serverSelectionTimeoutMS=5000,
                retryWrites=True,
                retryReads=True
            )

            self.mongo_client.admin.command("ping")
            self.db = self.mongo_client[Config.DATABASE_NAME]

            self._create_indexes()
            logger.info("✅ MongoDB connected")

        except ConnectionFailure as e:
            logger.error(f"❌ MongoDB connection failed: {e}")
            self.mongo_client = None
            self.db = None

    def _create_indexes(self):
        if self.db is None:
            return

        try:
            self.db.users.create_index([("discord_id", ASCENDING)], unique=True)
            self.db.users.create_index([("ip_address", ASCENDING)])
            self.db.users.create_index([("verified_at", DESCENDING)])
            self.db.users.create_index([("is_banned", ASCENDING)])
            self.db.users.create_index([("last_seen", DESCENDING)])

            self.db.banned_ips.create_index([("ip_address", ASCENDING)], unique=True)
            self.db.banned_ips.create_index([("banned_at", DESCENDING)])
            self.db.banned_ips.create_index([("is_active", ASCENDING)])

            self.db.verification_logs.create_index([("timestamp", DESCENDING)])
            self.db.verification_logs.create_index([("discord_id", ASCENDING)])
            self.db.verification_logs.create_index([("ip_address", ASCENDING)])
            self.db.verification_logs.create_index([("success", ASCENDING)])

            self.db.security_logs.create_index([("timestamp", DESCENDING)])
            self.db.security_logs.create_index([("type", ASCENDING)])
            self.db.security_logs.create_index([("ip_address", ASCENDING)])

            self.db.users.create_index([
                ("is_banned", ASCENDING),
                ("verified_at", DESCENDING)
            ])

            self.db.banned_ips.create_index([
                ("is_active", ASCENDING),
                ("banned_at", DESCENDING)
            ])

            logger.info("✅ Database indexes created")

        except Exception as e:
            logger.error(f"❌ Index creation failed: {e}")

    # ================== REDIS ==================

    def _connect_redis(self):
        try:
            redis_url = getattr(Config, "REDIS_URL", None)
            if not redis_url:
                logger.info("ℹ️ Redis not configured")
                return

            self.redis_client = redis.from_url(
                redis_url,
                decode_responses=True,
                socket_timeout=5,
                socket_connect_timeout=5
            )
            self.redis_client.ping()
            self.cache_enabled = True
            logger.info("✅ Redis connected")

        except Exception as e:
            logger.warning(f"⚠️ Redis connection failed: {e}")
            self.cache_enabled = False

    # ================== CACHE ==================

    def cache_get(self, key):
        if not self.cache_enabled or self.redis_client is None:
            return None
        try:
            value = self.redis_client.get(key)
            if value is None:
                return None
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                return value
        except Exception:
            return None

    def cache_set(self, key, value, expire=300):
        if not self.cache_enabled or self.redis_client is None:
            return False
        try:
            if isinstance(value, (dict, list)):
                value = json.dumps(value)
            self.redis_client.setex(key, expire, value)
            return True
        except Exception:
            return False

    def cache_delete(self, key):
        if not self.cache_enabled or self.redis_client is None:
            return False
        try:
            self.redis_client.delete(key)
            return True
        except Exception:
            return False

    # ================== QUERIES ==================

    def get_user(self, discord_id, use_cache=True):
        cache_key = f"user:{discord_id}"

        if use_cache:
            cached = self.cache_get(cache_key)
            if cached:
                return cached

        if self.db is None:
            return None

        user = self.db.users.find_one({"discord_id": str(discord_id)})

        if user and use_cache:
            self.cache_set(cache_key, user, 300)

        return user

    def is_ip_banned(self, ip_address, use_cache=True):
        cache_key = f"banned_ip:{ip_address}"

        if use_cache:
            cached = self.cache_get(cache_key)
            if cached is not None:
                return cached

        if self.db is None:
            return False

        ban = self.db.banned_ips.find_one({
            "ip_address": ip_address,
            "is_active": True
        })

        is_banned = ban is not None

        if use_cache:
            self.cache_set(cache_key, is_banned, 300 if is_banned else 60)

        return is_banned

    def get_stats(self, use_cache=True):
        cache_key = "system_stats"

        if use_cache:
            cached = self.cache_get(cache_key)
            if cached:
                return cached

        if self.db is None:
            return {}

        stats = {
            "total_users": self.db.users.count_documents({}),
            "verified_users": self.db.users.count_documents({"verified_at": {"$exists": True}}),
            "banned_users": self.db.banned_ips.count_documents({"is_active": True}),
            "today_verifications": self._get_today_verifications(),
            "active_sessions": self._get_active_sessions(),
            "system_uptime": int(time.time() - self._start_time)
        }

        if use_cache:
            self.cache_set(cache_key, stats, 60)

        return stats

    def _get_today_verifications(self):
        if self.db is None:
            return 0

        today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        return self.db.verification_logs.count_documents({
            "timestamp": {"$gte": today},
            "success": True
        })

    def _get_active_sessions(self):
        if self.db is None:
            return 0

        last_15_minutes = datetime.utcnow() - timedelta(minutes=15)
        return self.db.users.count_documents({
            "last_seen": {"$gte": last_15_minutes},
            "is_banned": False
        })

    # ================== CLEANUP ==================

    def close(self):
        if self.mongo_client:
            self.mongo_client.close()
        if self.redis_client:
            self.redis_client.close()
        logger.info("Database connections closed")


# Global instance
db_manager = DatabaseManager()
