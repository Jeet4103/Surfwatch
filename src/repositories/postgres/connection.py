import asyncpg

from src.core.config import Settings


async def create_pool(settings: Settings) -> asyncpg.Pool:
  return await asyncpg.create_pool(
    dsn=settings.database_url.get_secret_value(),
    min_size=settings.db_pool_min_size,
    max_size=settings.db_pool_max_size,
    timeout=settings.db_connect_timeout,
    command_timeout=settings.db_command_timeout,
  )


async def close_pool(pool: asyncpg.Pool) -> None:
  await pool.close()


async def ping(pool: asyncpg.Pool) -> bool:
  async with pool.acquire() as conn:
    return await conn.fetchval("SELECT 1") == 1
