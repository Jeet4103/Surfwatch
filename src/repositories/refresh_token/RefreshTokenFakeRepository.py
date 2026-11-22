from datetime import datetime
from typing import Any

from src.repositories.refresh_token import RefreshTokenRepository
from src.repositories.models.models import AuthRefreshToken

class FakeRefreshTokenRepository(RefreshTokenRepository):
  def __init__(self) -> None:
    self._rows: dict[int, AuthRefreshToken] = {}
    self._next_id = 1

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
    if any(t.token_hash == token_hash for t in self._rows.values()):
      raise ValueError("duplicate token_hash")
    token = AuthRefreshToken(
      id=self._next_id,
      session_id=session_id,
      token_hash=token_hash,
      parent_token_id=parent_token_id,
      replaced_by_id=None,
      created_at=now,
      expires_at=expires_at,
      used_at=None,
      revoked_at=None,
    )
    self._rows[token.id] = token
    self._next_id += 1
    return token