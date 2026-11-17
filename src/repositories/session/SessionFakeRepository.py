from dataclasses import replace
from datetime import datetime, timedelta
from typing import Any

from src.repositories.models.models import AuthSession
from src.repositories.session import SessionRepository


class FakeSessionRepository(SessionRepository):
  def __init__(self) -> None:
    self._rows: dict[int, AuthSession] = {}
    self._next_id = 1

  async def create(self,
                   *,
                   user_id: int,
                   device_name: str | None,
                   ip_address: str | None,
                   user_agent: str | None,
                   now: datetime,
                   expires_at: datetime,
                   conn: Any = None,
                   ) -> AuthSession:
    session = AuthSession(id=self._next_id,
                          user_id=user_id,
                          device_name=device_name,
                          ip_address=ip_address,
                          user_agent=user_agent,
                          created_at=now,
                          last_active_at=now,
                          expires_at=expires_at,
                          revoked_at=None,
                          revoke_reason=None,
                          )
    self._rows[session.id] = session
    self._next_id += 1
    return session

  async def get_by_id(self, session_id: int, *, conn: Any = None) -> AuthSession | None:
    
    return self._rows.get(session_id)

  async def list_active_by_user(self, user_id: int, now: datetime, *, conn: Any = None) -> list[AuthSession]:
    
    rows = [s for s in self._rows.values() if s.user_id == user_id and s.is_active(now)]
    return sorted(rows, key=lambda s: (s.last_active_at, s.id), reverse=True)

  async def revoke(self, session_id: int, user_id: int | None, reason: str, now: datetime, *, conn: Any = None) -> bool:
    
    s = self._rows.get(session_id)
    if s is None or s.revoked_at is not None or (user_id is not None and s.user_id != user_id):
      return False
    self._rows[session_id] = replace(s, revoked_at=now, revoke_reason=reason)
    return True

  async def revoke_all_for_user(self, user_id: int, reason: str, now: datetime, *, except_session_id: int | None = None, conn: Any = None) -> int:
    
    count = 0
    for sid, s in list(self._rows.items()):
      if s.user_id == user_id and s.revoked_at is None and sid != except_session_id:
        self._rows[sid] = replace(s, revoked_at=now, revoke_reason=reason)
        count += 1
    return count

  async def touch(self, session_id: int, now: datetime, min_interval_seconds: float, *, conn: Any = None) -> None:
    
    s = self._rows.get(session_id)
    if s and s.revoked_at is None and s.last_active_at < now - timedelta(seconds=min_interval_seconds):
      self._rows[session_id] = replace(s, last_active_at=now)