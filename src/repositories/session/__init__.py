from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any

from src.repositories.models.models import AuthSession

class SessionRepository(ABC):
  @abstractmethod
  async def create(
    self,
    *,
    user_id: int,
    device_name: str | None,
    ip_address: str | None,
    user_agent: str | None,
    now: datetime,
    expires_at: datetime,
    conn: Any = None,
  ) -> AuthSession: ...
  
  @abstractmethod
  async def get_by_id(self, session_id: int, *, conn: Any = None) -> AuthSession | None: ...

  @abstractmethod
  async def list_active_by_user(self, user_id: int, now: datetime, *, conn: Any = None) -> list[AuthSession]: ...

  @abstractmethod
  async def revoke(self, session_id: int, user_id: int | None, reason: str, now: datetime, *, conn: Any = None) -> bool:
    """Revoke one active session. user_id=None skips the ownership check (internal use only)."""

  @abstractmethod
  async def revoke_all_for_user(self, user_id: int, reason: str, now: datetime, *, except_session_id: int | None = None, conn: Any = None) -> int: ...

  @abstractmethod
  async def touch(self, session_id: int, now: datetime, min_interval_seconds: float, *, conn: Any = None) -> None: ...