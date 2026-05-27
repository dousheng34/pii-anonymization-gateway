import json
import time
import logging
import threading
from typing import Dict, Optional
import redis
from app.config import settings
from app.services.crypto import encrypt_value, decrypt_value

logger = logging.getLogger("pii_gateway.session_store")

class InMemorySessionStore:
    def __init__(self):
        self._data: Dict[str, Dict] = {}
        self._lock = threading.Lock()
        
        # Start background cleanup daemon thread
        self._start_cleanup_daemon()

    def _cleanup_expired(self):
        """Purges keys older than their expiration timestamp."""
        now = time.time()
        with self._lock:
            expired_keys = [k for k, v in self._data.items() if v["expires_at"] < now]
            for k in expired_keys:
                self._data.pop(k, None)

    def _start_cleanup_daemon(self):
        """Starts a background thread that executes cleanup every 10 seconds."""
        def cleanup_loop():
            while True:
                time.sleep(10)
                self._cleanup_expired()
        
        t = threading.Thread(target=cleanup_loop, daemon=True)
        t.start()
        logger.info("In-memory session cleanup background task started.")

    def set(self, key: str, value: str, ttl: int = 300):
        with self._lock:
            self._data[key] = {
                "value": value,
                "expires_at": time.time() + ttl
            }

    def get(self, key: str) -> Optional[str]:
        with self._lock:
            entry = self._data.get(key)
            if entry:
                if entry["expires_at"] > time.time():
                    return entry["value"]
                else:
                    self._data.pop(key, None)
            return None

    def get_stats(self) -> Dict:
        with self._lock:
            # Active non-expired keys count
            now = time.time()
            active_keys = [k for k, v in self._data.items() if v["expires_at"] > now]
            return {
                "active_sessions": len(active_keys)
            }


class SessionStoreManager:
    def __init__(self):
        self.redis_client = None
        self.in_memory_store = InMemorySessionStore()
        self.redis_online = False
        self.connect_redis()

    def connect_redis(self):
        """Tries to connect to Redis and ping the server."""
        try:
            self.redis_client = redis.Redis.from_url(
                settings.REDIS_URL, 
                socket_connect_timeout=2.0, 
                decode_responses=True
            )
            self.redis_client.ping()
            self.redis_online = True
            logger.info("Successfully connected to Redis.")
        except Exception as e:
            self.redis_online = False
            logger.warning(
                f"Redis connection failed: {e}. Falling back to in-memory session store."
            )

    def is_healthy(self) -> bool:
        """Pings Redis to check health status, updating online state."""
        if not self.redis_client:
            return False
        try:
            self.redis_client.ping()
            self.redis_online = True
            return True
        except Exception:
            if self.redis_online:
                logger.warning("Redis went offline. Switching to local in-memory fallback.")
            self.redis_online = False
            return False

    def save_session_mapping(self, session_key: str, mappings: Dict[str, str], ttl: int = 300) -> bool:
        """Serializes, encrypts, and caches the mappings."""
        try:
            serialized = json.dumps(mappings)
            encrypted = encrypt_value(serialized)
            
            if self.is_healthy():
                self.redis_client.setex(session_key, ttl, encrypted)
                return True
        except Exception as e:
            logger.error(f"Redis save failed, falling back to memory: {e}")
            self.redis_online = False

        # In-memory fallback
        try:
            serialized = json.dumps(mappings)
            encrypted = encrypt_value(serialized)
            self.in_memory_store.set(session_key, encrypted, ttl)
            return True
        except Exception as e:
            logger.critical(f"In-memory store failed to write mapping: {e}")
            return False

    def load_session_mapping(self, session_key: str) -> Dict[str, str]:
        """Loads, decrypts, and returns the session mappings dictionary."""
        encrypted = None
        try:
            if self.is_healthy():
                encrypted = self.redis_client.get(session_key)
        except Exception as e:
            logger.error(f"Redis read failed, trying memory fallback: {e}")
            self.redis_online = False

        if encrypted is None:
            encrypted = self.in_memory_store.get(session_key)

        if not encrypted:
            return {}

        try:
            decrypted = decrypt_value(encrypted)
            return json.loads(decrypted)
        except Exception as e:
            logger.error(f"Failed to decrypt/deserialize session mapping: {e}")
            return {}

# Singleton instance
store_manager = SessionStoreManager()
