from functools import lru_cache

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
  model_config = SettingsConfigDict(env_file=".env", extra="ignore")

  app_env: str
  port: int
  log_level: str
  app_name: str
  cors_origins: list[str]

  database_url: SecretStr
  db_pool_min_size: int = Field(ge=1)
  db_pool_max_size: int = Field(ge=1)
  db_connect_timeout: float = Field(gt=0)  # seconds
  db_command_timeout: float = Field(gt=0)  # seconds

  jwt_secret: SecretStr = Field(min_length=32)
  jwt_algorithm: str
  access_token_ttl_minutes: int = Field(gt=0)
  refresh_token_ttl_days: int = Field(gt=0)

  log_format: str = "%(asctime)s %(levelname)s %(name)s %(message)s"

  @model_validator(mode="after")
  def _check_pool_sizes(self) -> "Settings":
    if self.db_pool_min_size > self.db_pool_max_size:
      raise ValueError("DB_POOL_MIN_SIZE must be <= DB_POOL_MAX_SIZE")
    return self


@lru_cache
def get_settings() -> Settings:
  return Settings()  # type: ignore[call-arg]