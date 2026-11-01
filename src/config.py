from functools import lru_cache

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_env: str
    port: int
    log_level: str
    cors_origins: list[str]

    database_url: SecretStr
    db_pool_min: int = Field(ge=1)
    db_pool_max: int = Field(ge=1)

    jwt_secret: SecretStr = Field(min_length=32)
    jwt_algorithm: str
    access_token_ttl_minutes: int = Field(gt=0)
    refresh_token_ttl_days: int = Field(gt=0)


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
