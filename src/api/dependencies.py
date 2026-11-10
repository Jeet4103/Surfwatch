from collections.abc import AsyncGenerator
from typing import Annotated

import asyncpg
from fastapi import Depends

from src.dependencies.database import get_pool


async def get_conn(
  pool: Annotated[asyncpg.Pool, Depends(get_pool)],
) -> AsyncGenerator[asyncpg.Connection]:
  async with pool.acquire() as conn:
    yield conn
