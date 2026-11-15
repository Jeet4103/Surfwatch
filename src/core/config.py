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

  # JWT (EdDSA; the algorithm is pinned in code, not configurable)
  jwt_private_key_path: str
  jwt_public_key_path: str
  jwt_key_id: str = Field(min_length=1)
  jwt_issuer: str = "surfwatch"
  jwt_audience: str = "surfwatch-api"
  jwt_leeway_seconds: int = Field(default=10, ge=0)
  access_token_ttl_minutes: int = Field(gt=0)
  refresh_token_ttl_days: int = Field(gt=0)

  # Password hashing (Argon2id)
  argon2_time_cost: int = Field(default=3, ge=1)
  argon2_memory_cost_kib: int = Field(default=65536, ge=8)
  argon2_parallelism: int = Field(default=4, ge=1)
  password_min_length: int = Field(default=8, ge=1)
  password_max_length: int = Field(default=128, ge=1)

  log_format: str = "%(asctime)s %(levelname)s %(name)s %(message)s"

  pagination_default_page_size: int = Field(ge=1)
  pagination_max_page_size: int = Field(ge=1)

  @model_validator(mode="after")
  def _check_pool_sizes(self) -> "Settings":
    if self.pagination_default_page_size > self.pagination_max_page_size:
      raise ValueError("PAGINATION_DEFAULT_PAGE_SIZE must be <= PAGINATION_MAX_PAGE_SIZE")
    if self.db_pool_min_size > self.db_pool_max_size:
      raise ValueError("DB_POOL_MIN_SIZE must be <= DB_POOL_MAX_SIZE")
    if self.password_min_length > self.password_max_length:
      raise ValueError("PASSWORD_MIN_LENGTH must be <= PASSWORD_MAX_LENGTH")
    return self


@lru_cache
def get_settings() -> Settings:
  return Settings()  # type: ignore[call-arg]