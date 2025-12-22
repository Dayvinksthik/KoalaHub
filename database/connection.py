from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.errors import ConnectionFailure
import redis
import threading
import time
from datetime import datetime
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
        
        self._connect_mongodb()
        self._connect_redis()
    
    def _connect_mongodb(self):
        """Connect to MongoDB with connection pooling"""
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
            
            # Test connection
            self.mongo_client.admin.command('ping')
            self.db = self.mongo_client[Config.DATABASE_NAME]
            
            # Create indexes for performance
            self._create_indexes()
            
            logger.info("✅ MongoDB connected with connection pooling")
            
        except ConnectionFailure as e:
            logger.error(f"❌ MongoDB connection failed: {e}")
            self.mongo_client = None
            self.db = None
    
    def _connect_redis(self):
        """Connect to Redis for caching"""
        try:
            # Try to get Redis URL from config
            redis_url = getattr(Config, 'REDIS_URL', None)
            if redis_url:
                self.redis_client = redis.from_url(
                    redis_url,
                    decode_responses=True,
                    socket_timeout=5,
                    socket_connect_timeout=5
                )
                self.redis_client.ping()
                self.cache_enabled = True
                logger.info("✅ Redis connected for caching")
            else:
                logger.info("ℹ️ Redis not configured, using memory cache")
                self.cache_enabled = False
                
        except Exception as e:
            logger.warning(f"⚠️ Redis connection failed: {e}")
            self.cache_enabled = False
    
    def _create_indexes(self):
        """Create database indexes for performance"""
        if not self.db:
            return
        
        try:
            # Users collection indexes
            self.db.users.create_index([("discord_id", ASCENDING)], unique=True)
            self.db.users.create_index([("ip_address", ASCENDING)])
            self.db.users.create_index([("verified_at", DESCENDING)])
            self.db.users.create_index([("is_banned", ASCENDING)])
            self.db.users.create_index([("last_seen", DESCENDING)])
            
            # Banned IPs indexes
            self.db.banned_ips.create_index([("ip_address", ASCENDING)], unique=True)
            self.db.banned_ips.create_index([("banned_at", DESCENDING)])
            self.db.banned_ips.create_index([("is_active", ASCENDING)])
            
            # Verification logs indexes
            self.db.verification_logs.create_index([("timestamp", DESCENDING)])
            self.db.verification_logs.create_index([("discord_id", ASCENDING)])
            self.db.verification_logs.create_index([("ip_address", ASCENDING)])
            self.db.verification_logs.create_index([("success", ASCENDING)])
            
            # Security logs indexes
            self.db.security_logs.create_index([("timestamp", DESCENDING)])
            self.db.security_logs.create_index([("type", ASCENDING)])
            self.db.security_logs.create_index([("ip_address", ASCENDING)])
            
            # Compound indexes for common queries
            self.db.users.create_index([
                ("is_banned", ASCENDING),
                ("verified_at", DESCENDING)
            ])
            
            self.db.banned_ips.create_index([
                ("is_active", ASCENDING),
                ("banned_at", DESCENDING)
            ])
            
            logger.info("✅ Database indexes created for performance")
            
        except Exception as e:
            logger.error(f"❌ Index creation failed: {e}")
    
    # ============ CACHING METHODS ============
    
    def cache_get(self, key: str):
        """Get value from cache"""
        if not self.cache_enabled or not self.redis_client:
            return None
        
        try:
            value = self.redis_client.get(key)
            if value:
                try:
                    return eval(value)  # For Python objects
                except:
                    return value  # For strings
            return None
        except Exception as e:
            logger.warning(f"Cache get error: {e}")
            return None
    
    def cache_set(self, key: str, value, expire: int = 300):
        """Set value in cache with expiration"""
        if not self.cache_enabled or not self.redis_client:
            return False
        
        try:
            if isinstance(value, (dict, list, tuple)):
                value = str(value)
            self.redis_client.setex(key, expire, value)
            return True
        except Exception as e:
            logger.warning(f"Cache set error: {e}")
            return False
    
    def cache_delete(self, key: str):
        """Delete value from cache"""
        if not self.cache_enabled or not self.redis_client:
            return False
        
        try:
            self.redis_client.delete(key)
            return True
        except Exception as e:
            logger.warning(f"Cache delete error: {e}")
            return False
    
    def cache_incr(self, key: str, amount: int = 1):
        """Increment cached counter"""
        if not self.cache_enabled or not self.redis_client:
            return None
        
        try:
            return self.redis_client.incrby(key, amount)
        except Exception as e:
            logger.warning(f"Cache incr error: {e}")
            return None
    
    # ============ QUERY METHODS WITH CACHING ============
    
    def get_user(self, discord_id: str, use_cache: bool = True):
        """Get user with optional caching"""
        cache_key = f"user:{discord_id}"
        
        if use_cache:
            cached = self.cache_get(cache_key)
            if cached:
                return cached
        
        if not self.db:
            return None
        
        user = self.db.users.find_one({"discord_id": str(discord_id)})
        
        if user and use_cache:
            # Cache for 5 minutes
            self.cache_set(cache_key, user, 300)
        
        return user
    
    def is_ip_banned(self, ip_address: str, use_cache: bool = True):
        """Check if IP is banned with caching"""
        cache_key = f"banned_ip:{ip_address}"
        
        if use_cache:
            cached = self.cache_get(cache_key)
            if cached is not None:
                return cached
        
        if not self.db:
            return False
        
        ban = self.db.banned_ips.find_one({
            "ip_address": ip_address,
            "is_active": True
        })
        
        is_banned = ban is not None
        
        if use_cache:
            # Cache negative results for 1 minute, positive for 5 minutes
            expire = 300 if is_banned else 60
            self.cache_set(cache_key, is_banned, expire)
        
        return is_banned
    
    def get_stats(self, use_cache: bool = True):
        """Get system statistics with caching"""
        cache_key = "system_stats"
        
        if use_cache:
            cached = self.cache_get(cache_key)
            if cached:
                return cached
        
        if not self.db:
            return {}
        
        try:
            stats = {
                "total_users": self.db.users.count_documents({}),
                "verified_users": self.db.users.count_documents({"verified_at": {"$exists": True}}),
                "banned_users": self.db.banned_ips.count_documents({"is_active": True}),
                "today_verifications": self._get_today_verifications(),
                "active_sessions": self._get_active_sessions(),
                "system_uptime": int(time.time() - self._start_time)
            }
            
            if use_cache:
                # Cache stats for 1 minute
                self.cache_set(cache_key, stats, 60)
            
            return stats
            
        except Exception as e:
            logger.error(f"Stats calculation error: {e}")
            return {}
    
    def _get_today_verifications(self):
        """Get today's verification count"""
        if not self.db:
            return 0
        
        today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        return self.db.verification_logs.count_documents({
            "timestamp": {"$gte": today},
            "success": True
        })
    
    def _get_active_sessions(self):
        """Get active user sessions"""
        if not self.db:
            return 0
        
        last_15_minutes = datetime.utcnow() - timedelta(minutes=15)
        return self.db.users.count_documents({
            "last_seen": {"$gte": last_15_minutes},
            "is_banned": False
        })
    
    # ============ BATCH OPERATIONS ============
    
    def bulk_update_users(self, updates: list):
        """Bulk update users for performance"""
        if not self.db:
            return False
        
        try:
            bulk_operations = []
            for update in updates:
                discord_id = update.get("discord_id")
                if discord_id:
                    bulk_operations.append({
                        "updateOne": {
                            "filter": {"discord_id": discord_id},
                            "update": {"$set": update},
                            "upsert": True
                        }
                    })
            
            if bulk_operations:
                result = self.db.users.bulk_write(bulk_operations)
                
                # Clear cache for updated users
                for update in updates:
                    discord_id = update.get("discord_id")
                    if discord_id:
                        self.cache_delete(f"user:{discord_id}")
                
                logger.info(f"Bulk updated {result.modified_count} users")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Bulk update error: {e}")
            return False
    
    # ============ MONITORING ============
    
    def get_performance_metrics(self):
        """Get database performance metrics"""
        metrics = {
            "cache_enabled": self.cache_enabled,
            "cache_hits": self._get_cache_hits(),
            "cache_misses": self._get_cache_misses(),
            "query_count": self._get_query_count(),
            "avg_query_time": self._get_avg_query_time()
        }
        
        return metrics
    
    def _get_cache_hits(self):
        """Get cache hit count"""
        if not self.cache_enabled or not self.redis_client:
            return 0
        
        try:
            return int(self.redis_client.get("stats:cache_hits") or 0)
        except:
            return 0
    
    def _get_cache_misses(self):
        """Get cache miss count"""
        if not self.cache_enabled or not self.redis_client:
            return 0
        
        try:
            return int(self.redis_client.get("stats:cache_misses") or 0)
        except:
            return 0
    
    def _get_query_count(self):
        """Get query count"""
        if not self.cache_enabled or not self.redis_client:
            return 0
        
        try:
            return int(self.redis_client.get("stats:query_count") or 0)
        except:
            return 0
    
    def _get_avg_query_time(self):
        """Get average query time"""
        if not self.cache_enabled or not self.redis_client:
            return 0
        
        try:
            total_time = float(self.redis_client.get("stats:query_total_time") or 0)
            count = float(self.redis_client.get("stats:query_count") or 1)
            return total_time / count if count > 0 else 0
        except:
            return 0
    
    def close(self):
        """Close database connections"""
        if self.mongo_client:
            self.mongo_client.close()
        
        if self.redis_client:
            self.redis_client.close()
        
        logger.info("Database connections closed")

# Global instance
db_manager = DatabaseManager()