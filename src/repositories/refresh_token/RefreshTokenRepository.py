from datetime import datetime
from typing import Any

import asyncpg

from src.repositories.models.models import AuthRefreshToken, map_row
from src.repositories.refresh_token import RefreshTokenRepository

_COLUMNS = (
  "id, session_id, token_hash, parent_token_id, replaced_by_id, "
  "created_at, expires_at, used_at, revoked_at"
)


class RefreshTokenRepository(RefreshTokenRepository):
    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool
        
    def _db(self, conn: Any) -> None:
        return conn if conn is not None else self._pool    
    
    async def create(
        self,
        *,
        session_id: int,
        token_hash: str,
        parent_token_id: int | None,
        now: datetime,
        expires_at: datetime,
        conn: Any = None,
    ) -> AuthRefreshToken:
        row = await self._db(conn).fetchrow(
            f"""
            INSERT INTO refresh_tokens (session_id, token_hash, parent_token_id, created_at, expires_at)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING {_COLUMNS}
            """,
            session_id,
            token_hash,
            parent_token_id,
            now,
            expires_at,
        )
        return map_row(AuthRefreshToken, row)