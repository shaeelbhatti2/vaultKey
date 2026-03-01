from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="VAULTKEY_", env_file=".env", extra="ignore")

    env: str = "development"
    database_url: str = "postgresql+asyncpg://vaultkey:vaultkey@localhost:5432/vaultkey"
    redis_url: str = "redis://localhost:6379/0"
    master_key: str = "change-me-to-32-byte-base64-key-here=="
    jwt_secret: str = "change-me-jwt-secret-min-32-chars"
    admin_host: str = "0.0.0.0"
    admin_port: int = 8080
    api_host: str = "0.0.0.0"
    api_port: int = 8090
    token_expire_minutes: int = 60
    max_secret_bytes: int = 65536


@lru_cache
def get_settings() -> Settings:
    return Settings()
