import json
import time
import logging
import threading
from typing import Dict, Optional
import redis
from app.config import settings
from app.services.crypto import encrypt_value, decrypt_value

logger = logging.getLogger("pii_gateway.session_store")

# Thread-safe in-memory store for fallback operations
class InMemorySessionStore:
    def __init__(self):
        self._data: Dict[str, Dict] = {}
        self._lock = threading.Lock()

    def _cleanup_expired(self):
        """Removes expired entries from the cache."""
        now = time.time()
        expired_keys = [k for k, v in self._data.items() if v["expires_at"] < now]
        for k in expired_keys:
            self._data.pop(k, None)

    def set(self, key: str, value: str, ttl: int = 300):
        with self._lock:
            self._cleanup_expired()
            self._data[key] = {
                "value": value,
                "expires_at": time.time() + ttl
            }

    def get(self, key: str) -> Optional[str]:
        with self._lock:
            self._cleanup_expired()
            entry = self._data.get(key)
            if entry and entry["expires_at"] > time.time():
                return entry["value"]
            # Clean up if expired
            if entry:
                self._data.pop(key, None)
            return None

    def get_stats(self) -> Dict:
        with self._lock:
            self._cleanup_expired()
            return {
                "active_sessions": len(self._data)
            }


class SessionStoreManager:
    def __init__(self):
        self.redis_client = None
        self.in_memory_store = InMemorySessionStore()
        self.redis_online = False
        self.connect_redis()

    def connect_redis(self):
        """Attempts to connect to Redis and ping the server."""
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
        """Pings Redis to check health, dynamically updating online status."""
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
        """Serializes, encrypts, and stores session mappings under session_key."""
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
            logger.critical(f"In-memory session store failed to write: {e}")
            return False

    def load_session_mapping(self, session_key: str) -> Dict[str, str]:
        """Loads, decrypts, and deserializes session mappings from the store."""
        encrypted = None
        try:
            if self.is_healthy():
                encrypted = self.redis_client.get(session_key)
        except Exception as e:
            logger.error(f"Redis read failed, trying in-memory fallback: {e}")
            self.redis_online = False

        if encrypted is None:
            # Try in-memory store
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
