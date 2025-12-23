"""
Database Connection Manager
Synchronous version for Flask website with connection pooling and caching
"""

from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.errors import ConnectionFailure, DuplicateKeyError
import redis
from datetime import datetime, timedelta
import time
import threading
import hashlib
import json
from typing import Optional, Dict, Any, List
import sys
import os

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import Config
from utils.logger import logger

class DatabaseManager:
    """Database manager with connection pooling and caching"""
    
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
        """Initialize database connections"""
        self.mongo_client = None
        self.redis_client = None
        self.db = None
        self.cache_enabled = False
        self._start_time = time.time()
        self._query_count = 0
        self._query_total_time = 0
        
        # Connection pooling metrics
        self.connection_stats = {
            "mongodb": {"status": "disconnected", "pool_size": 0},
            "redis": {"status": "disconnected"}
        }
        
        self._connect_mongodb()
        self._connect_redis()
    
    def _connect_mongodb(self):
        """Connect to MongoDB with advanced connection pooling"""
        try:
            # Parse MongoDB URI for advanced options
            connection_string = Config.MONGODB_URI
            
            self.mongo_client = MongoClient(
                connection_string,
                maxPoolSize=200,           # Maximum connections in pool
                minPoolSize=20,            # Minimum connections in pool
                maxIdleTimeMS=60000,       # Close idle connections after 60s
                socketTimeoutMS=10000,     # Socket timeout
                connectTimeoutMS=10000,    # Connection timeout
                serverSelectionTimeoutMS=10000,  # Server selection timeout
                waitQueueTimeoutMS=10000,  # Wait queue timeout
                retryWrites=True,
                retryReads=True,
                w="majority",              # Write concern
                journal=True,
                heartbeatFrequencyMS=10000,  # Heartbeat frequency
                serverMonitoringMode="stream"  # Stream monitoring
            )
            
            # Test connection
            self.mongo_client.admin.command('ping')
            self.db = self.mongo_client[Config.DATABASE_NAME]
            
            # Get connection pool stats
            server_info = self.mongo_client.server_info()
            self.connection_stats["mongodb"] = {
                "status": "connected",
                "pool_size": self.mongo_client.max_pool_size,
                "version": server_info.get('version', 'unknown'),
                "connections": server_info.get('connections', {}),
                "uptime": server_info.get('uptime', 0)
            }
            
            # Create indexes
            self._create_indexes()
            
            logger.info("✅ MongoDB connected with advanced connection pooling")
            
        except ConnectionFailure as e:
            logger.error(f"❌ MongoDB connection failed: {e}")
            self.mongo_client = None
            self.db = None
            self.connection_stats["mongodb"]["status"] = "disconnected"
    
    def _connect_redis(self):
        """Connect to Redis for caching with connection pooling"""
        try:
            redis_url = getattr(Config, 'REDIS_URL', None)
            if redis_url:
                # Use connection pooling
                self.redis_client = redis.ConnectionPool.from_url(
                    redis_url,
                    max_connections=50,
                    decode_responses=True,
                    socket_timeout=5,
                    socket_connect_timeout=5,
                    retry_on_timeout=True,
                    health_check_interval=30
                ).connection()
                
                self.redis_client.ping()
                self.cache_enabled = True
                
                # Get Redis info
                redis_info = self.redis_client.info()
                self.connection_stats["redis"] = {
                    "status": "connected",
                    "version": redis_info.get('redis_version', 'unknown'),
                    "uptime": redis_info.get('uptime_in_seconds', 0),
                    "connected_clients": redis_info.get('connected_clients', 0),
                    "used_memory": redis_info.get('used_memory_human', 'unknown')
                }
                
                logger.info("✅ Redis connected with connection pooling")
            else:
                logger.info("ℹ️ Redis not configured, using memory cache")
                self.cache_enabled = False
                
        except Exception as e:
            logger.warning(f"⚠️ Redis connection failed: {e}")
            self.cache_enabled = False
            self.connection_stats["redis"]["status"] = "disconnected"
    
    def _create_indexes(self):
        """Create comprehensive database indexes for performance"""
        if not self.db:
            return
        
        try:
            # Users collection
            self.db.users.create_index([("discord_id", ASCENDING)], unique=True, background=True)
            self.db.users.create_index([("ip_address", ASCENDING)], background=True)
            self.db.users.create_index([("hashed_ip", ASCENDING)], background=True)
            self.db.users.create_index([("verified_at", DESCENDING)], background=True)
            self.db.users.create_index([("is_banned", ASCENDING)], background=True)
            self.db.users.create_index([("last_seen", DESCENDING)], background=True)
            self.db.users.create_index([("username", ASCENDING)], background=True)
            self.db.users.create_index([("role_added", ASCENDING)], background=True)
            
            # Banned IPs
            self.db.banned_ips.create_index([("ip_address", ASCENDING)], unique=True, background=True)
            self.db.banned_ips.create_index([("discord_id", ASCENDING)], background=True)
            self.db.banned_ips.create_index([("banned_at", DESCENDING)], background=True)
            self.db.banned_ips.create_index([("is_active", ASCENDING)], background=True)
            self.db.banned_ips.create_index([("type", ASCENDING)], background=True)
            
            # Security logs
            self.db.security_logs.create_index([("timestamp", DESCENDING)], background=True)
            self.db.security_logs.create_index([("type", ASCENDING)], background=True)
            self.db.security_logs.create_index([("ip_address", ASCENDING)], background=True)
            self.db.security_logs.create_index([("user_id", ASCENDING)], background=True)
            self.db.security_logs.create_index([("level", ASCENDING)], background=True)
            
            # Verification logs
            self.db.verification_logs.create_index([("timestamp", DESCENDING)], background=True)
            self.db.verification_logs.create_index([("discord_id", ASCENDING)], background=True)
            self.db.verification_logs.create_index([("ip_address", ASCENDING)], background=True)
            self.db.verification_logs.create_index([("success", ASCENDING)], background=True)
            self.db.verification_logs.create_index([("hashed_ip", ASCENDING)], background=True)
            
            # Temp bans
            self.db.temp_bans.create_index([("ip_address", ASCENDING)], background=True)
            self.db.temp_bans.create_index([("expires_at", ASCENDING)], background=True)
            
            # VPN logs
            self.db.vpn_logs.create_index([("detected_at", DESCENDING)], background=True)
            self.db.vpn_logs.create_index([("ip_address", ASCENDING)], background=True)
            self.db.vpn_logs.create_index([("discord_id", ASCENDING)], background=True)
            
            # Warnings
            self.db.warnings.create_index([("timestamp", DESCENDING)], background=True)
            self.db.warnings.create_index([("user_id", ASCENDING)], background=True)
            self.db.warnings.create_index([("guild_id", ASCENDING)], background=True)
            
            # Settings
            self.db.settings.create_index([("key", ASCENDING)], unique=True, background=True)
            
            # Payments (for future use)
            self.db.payments.create_index([("payment_id", ASCENDING)], unique=True, background=True)
            self.db.payments.create_index([("user_id", ASCENDING)], background=True)
            self.db.payments.create_index([("status", ASCENDING)], background=True)
            self.db.payments.create_index([("created_at", DESCENDING)], background=True)
            
            # Audit logs
            self.db.audit_logs.create_index([("timestamp", DESCENDING)], background=True)
            self.db.audit_logs.create_index([("admin_id", ASCENDING)], background=True)
            self.db.audit_logs.create_index([("action", ASCENDING)], background=True)
            
            # Compound indexes for common queries
            self.db.users.create_index([
                ("is_banned", ASCENDING),
                ("verified_at", DESCENDING)
            ], background=True)
            
            self.db.users.create_index([
                ("verified_at", ASCENDING),
                ("role_added", ASCENDING)
            ], background=True)
            
            self.db.security_logs.create_index([
                ("timestamp", DESCENDING),
                ("level", ASCENDING)
            ], background=True)
            
            logger.info("✅ Database indexes created for optimal performance")
            
        except Exception as e:
            logger.error(f"❌ Index creation failed: {e}")
    
    # ============ CACHING METHODS ============
    
    def cache_get(self, key: str):
        """Get value from cache with metrics"""
        if not self.cache_enabled or not self.redis_client:
            return None
        
        start_time = time.time()
        try:
            value = self.redis_client.get(key)
            if value:
                try:
                    # Try to parse JSON
                    return json.loads(value)
                except json.JSONDecodeError:
                    # Return as string
                    return value
            return None
        except Exception as e:
            logger.warning(f"Cache get error for key {key}: {e}")
            return None
        finally:
            self._record_query_time(time.time() - start_time)
    
    def cache_set(self, key: str, value, expire: int = 300):
        """Set value in cache with expiration"""
        if not self.cache_enabled or not self.redis_client:
            return False
        
        start_time = time.time()
        try:
            if isinstance(value, (dict, list)):
                value = json.dumps(value)
            self.redis_client.setex(key, expire, value)
            return True
        except Exception as e:
            logger.warning(f"Cache set error for key {key}: {e}")
            return False
        finally:
            self._record_query_time(time.time() - start_time)
    
    def cache_delete(self, key: str):
        """Delete value from cache"""
        if not self.cache_enabled or not self.redis_client:
            return False
        
        start_time = time.time()
        try:
            self.redis_client.delete(key)
            return True
        except Exception as e:
            logger.warning(f"Cache delete error for key {key}: {e}")
            return False
        finally:
            self._record_query_time(time.time() - start_time)
    
    def cache_incr(self, key: str, amount: int = 1):
        """Increment cached counter"""
        if not self.cache_enabled or not self.redis_client:
            return None
        
        start_time = time.time()
        try:
            return self.redis_client.incrby(key, amount)
        except Exception as e:
            logger.warning(f"Cache incr error for key {key}: {e}")
            return None
        finally:
            self._record_query_time(time.time() - start_time)
    
    def cache_keys(self, pattern: str = "*"):
        """Get cache keys matching pattern"""
        if not self.cache_enabled or not self.redis_client:
            return []
        
        start_time = time.time()
        try:
            return self.redis_client.keys(pattern)
        except Exception as e:
            logger.warning(f"Cache keys error for pattern {pattern}: {e}")
            return []
        finally:
            self._record_query_time(time.time() - start_time)
    
    # ============ QUERY METHODS WITH CACHING ============
    
    def get_user(self, discord_id: str, use_cache: bool = True) -> Optional[Dict[str, Any]]:
        """Get user with optional caching"""
        cache_key = f"user:{discord_id}"
        
        if use_cache:
            cached = self.cache_get(cache_key)
            if cached:
                return cached
        
        if not self.db:
            return None
        
        start_time = time.time()
        try:
            user = self.db.users.find_one({"discord_id": str(discord_id)})
            
            if user and use_cache:
                # Cache for 5 minutes
                self.cache_set(cache_key, user, 300)
            
            return user
        except Exception as e:
            logger.error(f"get_user error: {e}")
            return None
        finally:
            self._record_query_time(time.time() - start_time)
    
    def get_user_by_ip(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Get user by IP address"""
        if not self.db:
            return None
        
        start_time = time.time()
        try:
            return self.db.users.find_one({"ip_address": ip_address})
        except Exception as e:
            logger.error(f"get_user_by_ip error: {e}")
            return None
        finally:
            self._record_query_time(time.time() - start_time)
    
    def is_ip_banned(self, ip_address: str, use_cache: bool = True) -> bool:
        """Check if IP is banned with caching"""
        cache_key = f"banned_ip:{ip_address}"
        
        if use_cache:
            cached = self.cache_get(cache_key)
            if cached is not None:
                return cached
        
        if not self.db:
            return False
        
        start_time = time.time()
        try:
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
        except Exception as e:
            logger.error(f"is_ip_banned error: {e}")
            return False
        finally:
            self._record_query_time(time.time() - start_time)
    
    def add_user(self, user_data: Dict[str, Any]) -> bool:
        """Add or update user"""
        if not self.db:
            return False
        
        start_time = time.time()
        try:
            # Check if user exists
            existing = self.db.users.find_one({"discord_id": user_data["discord_id"]})
            
            if existing:
                # Update existing user
                result = self.db.users.update_one(
                    {"discord_id": user_data["discord_id"]},
                    {"$set": user_data}
                )
            else:
                # Insert new user
                result = self.db.users.insert_one(user_data)
            
            # Clear cache
            self.cache_delete(f"user:{user_data['discord_id']}")
            
            return True
        except DuplicateKeyError:
            # Handle duplicate key error
            logger.warning(f"Duplicate key error for user: {user_data.get('discord_id')}")
            return False
        except Exception as e:
            logger.error(f"add_user error: {e}")
            return False
        finally:
            self._record_query_time(time.time() - start_time)
    
    def ban_ip(self, ip_address: str, discord_id: str = None, 
               username: str = None, reason: str = "Manual ban", 
               banned_by: str = "System") -> bool:
        """Ban IP address"""
        if not self.db:
            return False
        
        start_time = time.time()
        try:
            ban_data = {
                "ip_address": ip_address,
                "discord_id": discord_id,
                "username": username,
                "reason": reason,
                "banned_by": banned_by,
                "banned_at": datetime.utcnow(),
                "is_active": True,
                "type": "manual"
            }
            
            # Upsert ban
            result = self.db.banned_ips.update_one(
                {"ip_address": ip_address},
                {"$set": ban_data},
                upsert=True
            )
            
            # Clear cache
            self.cache_delete(f"banned_ip:{ip_address}")
            
            # Also ban any users with this IP
            if discord_id:
                self.db.users.update_one(
                    {"discord_id": str(discord_id)},
                    {"$set": {"is_banned": True}}
                )
                self.cache_delete(f"user:{discord_id}")
            
            return True
        except Exception as e:
            logger.error(f"ban_ip error: {e}")
            return False
        finally:
            self._record_query_time(time.time() - start_time)
    
    def unban_ip(self, ip_address: str) -> bool:
        """Unban IP address"""
        if not self.db:
            return False
        
        start_time = time.time()
        try:
            result = self.db.banned_ips.update_one(
                {"ip_address": ip_address},
                {"$set": {"is_active": False}}
            )
            
            # Clear cache
            self.cache_delete(f"banned_ip:{ip_address}")
            
            return result.modified_count > 0
        except Exception as e:
            logger.error(f"unban_ip error: {e}")
            return False
        finally:
            self._record_query_time(time.time() - start_time)
    
    def add_verification_log(self, log_data: Dict[str, Any]) -> bool:
        """Add verification log"""
        if not self.db:
            return False
        
        start_time = time.time()
        try:
            self.db.verification_logs.insert_one(log_data)
            return True
        except Exception as e:
            logger.error(f"add_verification_log error: {e}")
            return False
        finally:
            self._record_query_time(time.time() - start_time)
    
    def add_security_log(self, log_data: Dict[str, Any]) -> bool:
        """Add security log"""
        if not self.db:
            return False
        
        start_time = time.time()
        try:
            self.db.security_logs.insert_one(log_data)
            return True
        except Exception as e:
            logger.error(f"add_security_log error: {e}")
            return False
        finally:
            self._record_query_time(time.time() - start_time)
    
    # ============ STATISTICS METHODS ============
    
    def get_stats(self, use_cache: bool = True) -> Dict[str, Any]:
        """Get system statistics with caching"""
        cache_key = "system_stats"
        
        if use_cache:
            cached = self.cache_get(cache_key)
            if cached:
                return cached
        
        if not self.db:
            return {}
        
        start_time = time.time()
        try:
            stats = {
                "total_users": self.db.users.count_documents({}),
                "verified_users": self.db.users.count_documents({"verified_at": {"$exists": True}}),
                "banned_ips": self.db.banned_ips.count_documents({"is_active": True}),
                "today_verifications": self._get_today_verifications(),
                "vpn_detections": self.db.vpn_logs.count_documents({}),
                "security_events_today": self._get_today_security_events(),
                "active_temp_bans": self.db.temp_bans.count_documents({
                    "expires_at": {"$gt": datetime.utcnow()}
                }),
                "database_size": self._get_database_size(),
                "cache_enabled": self.cache_enabled,
                "query_performance": self.get_performance_metrics(),
                "uptime": int(time.time() - self._start_time)
            }
            
            if use_cache:
                # Cache stats for 1 minute
                self.cache_set(cache_key, stats, 60)
            
            return stats
            
        except Exception as e:
            logger.error(f"Stats calculation error: {e}")
            return {}
        finally:
            self._record_query_time(time.time() - start_time)
    
    def _get_today_verifications(self) -> int:
        """Get today's verification count"""
        try:
            today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
            return self.db.verification_logs.count_documents({
                "timestamp": {"$gte": today},
                "success": True
            })
        except:
            return 0
    
    def _get_today_security_events(self) -> int:
        """Get today's security events count"""
        try:
            today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
            return self.db.security_logs.count_documents({
                "timestamp": {"$gte": today}
            })
        except:
            return 0
    
    def _get_database_size(self) -> Dict[str, Any]:
        """Get database collection sizes"""
        try:
            sizes = {}
            for collection_name in ["users", "banned_ips", "security_logs", "verification_logs"]:
                count = self.db[collection_name].count_documents({})
                # Approximate size in KB (rough estimate)
                approx_size = count * 0.5  # 0.5KB per document avg
                sizes[collection_name] = {
                    "count": count,
                    "size_kb": round(approx_size, 2)
                }
            return sizes
        except:
            return {}
    
    # ============ PERFORMANCE MONITORING ============
    
    def _record_query_time(self, duration: float):
        """Record query execution time for metrics"""
        self._query_count += 1
        self._query_total_time += duration
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get database performance metrics"""
        avg_query_time = self._query_total_time / self._query_count if self._query_count > 0 else 0
        
        metrics = {
            "total_queries": self._query_count,
            "avg_query_time_ms": round(avg_query_time * 1000, 2),
            "query_per_second": round(self._query_count / (time.time() - self._start_time), 2),
            "connection_pool": self.connection_stats
        }
        
        # Add cache stats if Redis is enabled
        if self.cache_enabled and self.redis_client:
            try:
                redis_info = self.redis_client.info()
                metrics["redis"] = {
                    "used_memory": redis_info.get('used_memory_human', 'unknown'),
                    "connected_clients": redis_info.get('connected_clients', 0),
                    "keyspace_hits": redis_info.get('keyspace_hits', 0),
                    "keyspace_misses": redis_info.get('keyspace_misses', 0)
                }
                
                # Calculate cache hit rate
                hits = redis_info.get('keyspace_hits', 0)
                misses = redis_info.get('keyspace_misses', 0)
                total = hits + misses
                metrics["redis"]["hit_rate"] = f"{round((hits / total * 100) if total > 0 else 0, 1)}%"
            except:
                pass
        
        return metrics
    
    def reset_performance_metrics(self):
        """Reset performance metrics"""
        self._query_count = 0
        self._query_total_time = 0
    
    # ============ BATCH OPERATIONS ============
    
    def bulk_update_users(self, updates: List[Dict[str, Any]]) -> bool:
        """Bulk update users for performance"""
        if not self.db or not updates:
            return False
        
        start_time = time.time()
        try:
            bulk_operations = []
            cache_keys_to_delete = []
            
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
                    cache_keys_to_delete.append(f"user:{discord_id}")
            
            if bulk_operations:
                result = self.db.users.bulk_write(bulk_operations)
                
                # Clear cache for updated users
                for key in cache_keys_to_delete:
                    self.cache_delete(key)
                
                logger.info(f"Bulk updated {result.modified_count} users, inserted {result.upserted_count}")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Bulk update error: {e}")
            return False
        finally:
            self._record_query_time(time.time() - start_time)
    
    # ============ MAINTENANCE METHODS ============
    
    def cleanup_old_data(self, days_to_keep: int = 30):
        """Cleanup old data from database"""
        if not self.db:
            return 0
        
        try:
            total_deleted = 0
            cutoff = datetime.utcnow() - timedelta(days=days_to_keep)
            
            # Clean old security logs
            result = self.db.security_logs.delete_many({
                "timestamp": {"$lt": cutoff},
                "level": {"$ne": "CRITICAL"}  # Keep critical logs longer
            })
            total_deleted += result.deleted_count
            
            # Clean old verification logs
            result = self.db.verification_logs.delete_many({
                "timestamp": {"$lt": cutoff},
                "success": True  # Keep failed attempts longer
            })
            total_deleted += result.deleted_count
            
            # Clean old temp bans (keep for 7 days)
            temp_cutoff = datetime.utcnow() - timedelta(days=7)
            result = self.db.temp_bans.delete_many({
                "expires_at": {"$lt": temp_cutoff}
            })
            total_deleted += result.deleted_count
            
            logger.info(f"🧹 Cleaned {total_deleted} old database records")
            return total_deleted
            
        except Exception as e:
            logger.error(f"Cleanup error: {e}")
            return 0
    
    def optimize_database(self):
        """Run database optimization tasks"""
        if not self.db:
            return False
        
        try:
            # Rebuild indexes
            for collection_name in ["users", "banned_ips", "security_logs", "verification_logs"]:
                try:
                    self.db[collection_name].reindex()
                    logger.info(f"Rebuilt indexes for {collection_name}")
                except:
                    pass
            
            # Compact collections if needed
            # Note: This requires admin privileges in production
            
            return True
            
        except Exception as e:
            logger.error(f"Optimization error: {e}")
            return False
    
    # ============ BACKUP METHODS ============
    
    def create_backup(self, backup_path: str = None) -> Optional[str]:
        """Create database backup"""
        if not self.db:
            return None
        
        try:
            import os
            import json
            from datetime import datetime
            
            if not backup_path:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                backup_path = f"backups/backup_{timestamp}"
            
            os.makedirs(os.path.dirname(backup_path), exist_ok=True)
            
            backup_data = {
                "timestamp": datetime.utcnow().isoformat(),
                "collections": {}
            }
            
            # Backup each collection
            collections = ["users", "banned_ips", "security_logs", "verification_logs", "settings"]
            for collection_name in collections:
                try:
                    documents = list(self.db[collection_name].find({}))
                    
                    # Convert ObjectId to string
                    for doc in documents:
                        if '_id' in doc:
                            doc['_id'] = str(doc['_id'])
                    
                    backup_data["collections"][collection_name] = {
                        "count": len(documents),
                        "data": documents
                    }
                    
                except Exception as e:
                    logger.error(f"Failed to backup {collection_name}: {e}")
            
            # Save backup
            backup_file = f"{backup_path}.json"
            with open(backup_file, 'w', encoding='utf-8') as f:
                json.dump(backup_data, f, indent=2, default=str)
            
            logger.info(f"✅ Backup created: {backup_file}")
            return backup_file
            
        except Exception as e:
            logger.error(f"Backup creation error: {e}")
            return None
    
    # ============ HEALTH CHECK ============
    
    def health_check(self) -> Dict[str, Any]:
        """Perform health check on database connections"""
        health = {
            "mongodb": {"status": "disconnected", "latency_ms": 0},
            "redis": {"status": "disconnected", "latency_ms": 0},
            "overall": "unhealthy"
        }
        
        # Check MongoDB
        if self.mongo_client:
            try:
                start = time.time()
                self.mongo_client.admin.command('ping')
                latency = (time.time() - start) * 1000
                health["mongodb"] = {"status": "connected", "latency_ms": round(latency, 2)}
            except Exception as e:
                health["mongodb"]["error"] = str(e)
        
        # Check Redis
        if self.redis_client and self.cache_enabled:
            try:
                start = time.time()
                self.redis_client.ping()
                latency = (time.time() - start) * 1000
                health["redis"] = {"status": "connected", "latency_ms": round(latency, 2)}
            except Exception as e:
                health["redis"]["error"] = str(e)
        
        # Determine overall status
        mongodb_ok = health["mongodb"]["status"] == "connected"
        redis_ok = not self.cache_enabled or health["redis"]["status"] == "connected"
        
        if mongodb_ok and redis_ok:
            health["overall"] = "healthy"
        elif mongodb_ok:
            health["overall"] = "degraded"  # MongoDB OK, Redis down
        else:
            health["overall"] = "unhealthy"  # MongoDB down
        
        return health
    
    def close(self):
        """Close database connections gracefully"""
        logger.info("🛑 Closing database connections...")
        
        if self.mongo_client:
            try:
                self.mongo_client.close()
                logger.info("✅ MongoDB connection closed")
            except Exception as e:
                logger.error(f"Error closing MongoDB: {e}")
        
        if self.redis_client:
            try:
                self.redis_client.close()
                logger.info("✅ Redis connection closed")
            except Exception as e:
                logger.error(f"Error closing Redis: {e}")
        
        logger.info("✅ Database connections closed")

# Global instance for synchronous use (website)
db_manager = DatabaseManager()