import hashlib
import secrets
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from typing import Any

from src.repositories.refresh_token import RefreshTokenRepository


def _utcnow() -> datetime:
  return datetime.now(timezone.utc)

def hash_token(token: str) -> str:
  return hashlib.sha256(token.encode()).hexdigest()


class RefreshTokenOperation:
  def __init__(
    self,
    repository: RefreshTokenRepository,
    *,
    token_ttl: timedelta,
    clock: Callable[[], datetime] = _utcnow,
  ) -> None:
    if token_ttl <= timedelta(0):
      raise ValueError("token_ttl must be positive")
    self._repository = repository
    self._ttl = token_ttl
    self._clock = clock

  async def issue(
    self,
    *,
    session_id: int,
    parent_token_id: int | None = None,
    conn: Any = None,
  ) -> str:
    """Create a refresh token and return the plaintext. Only its hash is stored."""
    token = secrets.token_urlsafe(32)
    now = self._clock()
    await self._repository.create(
      session_id=session_id,
      token_hash=hash_token(token),
      parent_token_id=parent_token_id,
      now=now,
      expires_at=now + self._ttl,
      conn=conn,
    )
    return token
  