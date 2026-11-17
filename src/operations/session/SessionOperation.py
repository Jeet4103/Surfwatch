import ipaddress
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from typing import Any

from src.operations.models.models import Session
from src.repositories.models.models import AuthSession, RevokeReason
from src.repositories.session import SessionRepository

MAX_DEVICE_NAME = 150
MAX_USER_AGENT = 512


def _utcnow() -> datetime:
  return datetime.now(timezone.utc)


def _clean(value: str | None, limit: int) -> str | None:
  if value is None:
    return None
  value = value.strip()[:limit]
  return value or None


def _clean_ip(value: str | None) -> str | None:
  if not value:
    return None
  try:
    return str(ipaddress.ip_address(value.strip()))
  except ValueError:
    return None


def _to_output(session: AuthSession, current_session_id: int | None = None) -> Session:
  return Session(
    id=session.id,
    user_id=session.user_id,
    device_name=session.device_name,
    ip_address=session.ip_address,
    user_agent=session.user_agent,
    created_at=session.created_at,
    last_active_at=session.last_active_at,
    expires_at=session.expires_at,
    is_current=session.id == current_session_id,
  )


class SessionOperation:
  def __init__(
    self,
    repository: SessionRepository,
    *,
    session_ttl: timedelta,
    touch_interval_seconds: float = 60,
    clock: Callable[[], datetime] = _utcnow,
  ) -> None:
    if session_ttl <= timedelta(0):
      raise ValueError("session_ttl must be positive")
    if touch_interval_seconds < 0:
      raise ValueError("touch_interval_seconds must not be negative")
    self._repo = repository
    self._ttl = session_ttl
    self._touch_interval = touch_interval_seconds
    self._clock = clock

  async def create(
    self,
    user_id: int,
    *,
    device_name: str | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    conn: Any = None,
  ) -> Session:
    now = self._clock()
    session = await self._repo.create(
      user_id=user_id,
      device_name=_clean(device_name, MAX_DEVICE_NAME),
      ip_address=_clean_ip(ip_address),
      user_agent=_clean(user_agent, MAX_USER_AGENT),
      now=now,
      expires_at=now + self._ttl,
      conn=conn,
    )
    return _to_output(session)

  async def get_active(self, session_id: int, *, conn: Any = None) -> Session | None:
    """Session if it exists, is not revoked and not expired; otherwise None."""
    session = await self._repo.get_by_id(session_id, conn=conn)
    if session is None or not session.is_active(self._clock()):
      return None
    return _to_output(session)

  async def list_active(
    self, user_id: int, *, current_session_id: int | None = None, conn: Any = None
  ) -> list[Session]:
    sessions = await self._repo.list_active_by_user(user_id, self._clock(), conn=conn)
    return [_to_output(s, current_session_id) for s in sessions]

  async def revoke(
    self,
    session_id: int,
    user_id: int,
    reason: RevokeReason = RevokeReason.LOGOUT,
    *,
    conn: Any = None,
  ) -> bool:
    """Revoke one of the user's own sessions. False if missing, not theirs, or already revoked."""
    return await self._repo.revoke(session_id, user_id, reason.value, self._clock(), conn=conn)

  async def revoke_all(
    self,
    user_id: int,
    reason: RevokeReason = RevokeReason.LOGOUT_ALL,
    *,
    except_session_id: int | None = None,
    conn: Any = None,
  ) -> int:
    return await self._repo.revoke_all_for_user(
      user_id, reason.value, self._clock(), except_session_id=except_session_id, conn=conn
    )

  async def touch(self, session_id: int, *, conn: Any = None) -> None:
    await self._repo.touch(session_id, self._clock(), self._touch_interval, conn=conn)
