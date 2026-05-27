import base64
import hashlib
import logging
from cryptography.fernet import Fernet
from app.config import settings

logger = logging.getLogger("pii_gateway.crypto")

def derive_fernet_key(key_str: str) -> bytes:
    """Derive a URL-safe base64-encoded 32-byte key from any arbitrary key string using SHA-256."""
    hashed = hashlib.sha256(key_str.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(hashed)

# Select key: use env variable or generate an ephemeral fallback key
raw_key = settings.ENCRYPTION_KEY
if not raw_key:
    generated = Fernet.generate_key()
    logger.warning(
        "WARNING: ENCRYPTION_KEY environment variable is empty. "
        "Generating an ephemeral encryption key for this run. "
        "Cached PII mappings in Redis will not survive gateway restarts."
    )
    fernet_key = generated
else:
    fernet_key = derive_fernet_key(raw_key)

_fernet = Fernet(fernet_key)

def encrypt_value(text: str) -> str:
    """Encrypts a plaintext string and returns a base64 encoded ciphertext string."""
    if not text:
        return ""
    return _fernet.encrypt(text.encode("utf-8")).decode("utf-8")

def decrypt_value(encrypted_text: str) -> str:
    """Decrypts a base64 encoded ciphertext string back into plaintext."""
    if not encrypted_text:
        return ""
    return _fernet.decrypt(encrypted_text.encode("utf-8")).decode("utf-8")
