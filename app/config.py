import os
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )
    
    REDIS_URL: str = "redis://localhost:6379/0"
    OPENAI_API_KEY: str = ""
    ENCRYPTION_KEY: str = ""  # Auto-generated if not provided
    TARGET_LLM_URL: str = "https://api.openai.com"
    PORT: int = 8000
    HOST: str = "0.0.0.0"

settings = Settings()
