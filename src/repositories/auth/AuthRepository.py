from typing import Any

import asyncpg

from src.repositories.models.models import AuthUser, map_row
from src.repositories.auth import EmailAlreadyExistsError, UserRepository

_COLUMNS = "id, email, password_hash, is_active, is_verified, token_version, created_at, updated_at"


class PostgresUserRepository(UserRepository):
  def __init__(self, pool: asyncpg.Pool) -> None:
    self._pool = pool

  def _db(self, conn: Any) -> Any:
    return conn if conn is not None else self._pool

  async def create(
    self, *, email: str, password_hash: str, conn: Any = None
  ) -> AuthUser:
    try:
      row = await self._db(conn).fetchrow(
        f"INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING {_COLUMNS}",  # noqa: S608
        email,
        password_hash,
      )
    except asyncpg.UniqueViolationError as exc:
      raise EmailAlreadyExistsError from exc
    return map_row(AuthUser, row)
  
  
  async def get_by_email(self, *, email: str, conn: Any = None) -> AuthUser | None:
    row = await self._db(conn).fetchrow(
      f"SELECT {_COLUMNS} FROM users WHERE email = $1",  # noqa: S608
      email,
    )
    return map_row(AuthUser, row) if row is not None else None