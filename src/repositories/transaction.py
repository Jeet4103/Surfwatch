from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, AbstractAsyncContextManager
from typing import Any, Protocol

import asyncpg

class TransactionManager(Protocol):
  def __call__(self) -> AbstractAsyncContextManager[Any]: ...
  
class PostgresTransaction:
  def __init__(self,pool: asyncpg.Pool) -> None:
    self._pool = pool
    
  @asynccontextmanager
  async def __call__(self) -> AsyncIterator[Any]:
    async with self._pool.acquire() as conn, conn.transaction():
      yield conn
      
class NoTransaction:
  """
  For unit tests with fake repositories: yield conn=None.
  """
  @asynccontextmanager
  async def __call__(self) -> AsyncIterator[Any]:
    yield None
