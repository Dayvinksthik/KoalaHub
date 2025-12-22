import time
import hashlib
from datetime import datetime, timedelta
from collections import defaultdict
import redis
from config import Config

class RateLimiter:
    def __init__(self):
        self.attempts = defaultdict(list)
        self.locked_ips = {}
        self.redis_client = None
        self.use_redis = False
        
        # Try to connect to Redis if available
        try:
            if Config.REDIS_URL:
                self.redis_client = redis.from_url(Config.REDIS_URL)
                self.redis_client.ping()
                self.use_redis = True
                print("✅ Using Redis for rate limiting")
        except:
            print("⚠️ Redis not available, using memory-based rate limiting")
    
    def _get_key(self, identifier: str, action: str) -> str:
        """Generate unique key for rate limiting"""
        return f"rl:{action}:{identifier}"
    
    def check_rate_limit(self, identifier: str, action: str, limit: int, window: int) -> dict:
        """
        Check if rate limit is exceeded
        Returns: {"allowed": bool, "remaining": int, "reset": int, "retry_after": int}
        """
        current_time = time.time()
        key = self._get_key(identifier, action)
        
        if self.use_redis and self.redis_client:
            # Use Redis for distributed rate limiting
            try:
                # Remove old entries using sliding window
                pipe = self.redis_client.pipeline()
                pipe.zremrangebyscore(key, 0, current_time - window)
                pipe.zadd(key, {str(current_time): current_time})
                pipe.zrange(key, 0, -1)
                pipe.expire(key, window + 10)
                results = pipe.execute()
                
                requests = results[2]
                request_count = len(requests)
                
                if request_count > limit:
                    # Calculate oldest request to determine reset time
                    oldest = float(requests[0])
                    reset_time = oldest + window
                    retry_after = int(reset_time - current_time)
                    
                    return {
                        "allowed": False,
                        "remaining": 0,
                        "limit": limit,
                        "reset": int(reset_time),
                        "retry_after": retry_after,
                        "message": f"Rate limit exceeded. Try again in {retry_after} seconds."
                    }
                
                # Calculate remaining requests
                remaining = max(0, limit - request_count)
                
                # Get reset time (oldest request + window)
                reset = int(float(requests[0])) + window if requests else int(current_time + window)
                
                return {
                    "allowed": True,
                    "remaining": remaining,
                    "limit": limit,
                    "reset": reset,
                    "retry_after": 0
                }
                
            except Exception as e:
                print(f"Redis error: {e}, falling back to memory")
                self.use_redis = False
        
        # Memory-based rate limiting (fallback)
        if identifier not in self.attempts:
            self.attempts[identifier] = []
        
        # Clean old attempts
        self.attempts[identifier] = [
            t for t in self.attempts[identifier] 
            if current_time - t < window
        ]
        
        # Check limit
        if len(self.attempts[identifier]) >= limit:
            oldest = self.attempts[identifier][0]
            reset_time = oldest + window
            retry_after = int(reset_time - current_time)
            
            return {
                "allowed": False,
                "remaining": 0,
                "limit": limit,
                "reset": int(reset_time),
                "retry_after": retry_after,
                "message": f"Rate limit exceeded. Try again in {retry_after} seconds."
            }
        
        # Add current attempt
        self.attempts[identifier].append(current_time)
        
        # Clean up old data periodically
        if len(self.attempts) > 1000:
            self._cleanup_old_entries()
        
        remaining = max(0, limit - len(self.attempts[identifier]))
        reset = int(self.attempts[identifier][0] + window) if self.attempts[identifier] else int(current_time + window)
        
        return {
            "allowed": True,
            "remaining": remaining,
            "limit": limit,
            "reset": reset,
            "retry_after": 0
        }
    
    def _cleanup_old_entries(self):
        """Clean up old rate limit entries to prevent memory leak"""
        current_time = time.time()
        to_remove = []
        
        for identifier, attempts in self.attempts.items():
            # Keep only recent attempts (last hour)
            recent_attempts = [t for t in attempts if current_time - t < 3600]
            if not recent_attempts:
                to_remove.append(identifier)
            else:
                self.attempts[identifier] = recent_attempts
        
        for identifier in to_remove:
            del self.attempts[identifier]
    
    def is_ip_locked(self, ip_address: str) -> bool:
        """Check if IP is temporarily locked"""
        if ip_address in self.locked_ips:
            lock_until = self.locked_ips[ip_address]
            if time.time() < lock_until:
                return True
            else:
                # Lock expired
                del self.locked_ips[ip_address]
        return False
    
    def lock_ip(self, ip_address: str, duration: int = 300):
        """Lock IP for specified duration (seconds)"""
        self.locked_ips[ip_address] = time.time() + duration
    
    def get_remaining_time(self, ip_address: str) -> int:
        """Get remaining lock time for IP"""
        if ip_address in self.locked_ips:
            lock_until = self.locked_ips[ip_address]
            remaining = max(0, lock_until - time.time())
            return int(remaining)
        return 0

# Global instance
rate_limiter = RateLimiter()