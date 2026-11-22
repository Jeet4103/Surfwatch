from datetime import datetime, timezone
from typing import Any

from src.repositories.models.models import AuthUser
from src.repositories.auth import EmailAlreadyExistsError, UserRepository


class UserFakeRepository(UserRepository):
  def __init__(self) -> None:
    self._rows: dict[int, AuthUser] = {}
    self._next_id = 1

  async def create(
    self, *, email: str, password_hash: str, conn: Any = None
  ) -> AuthUser:
    if any(u.email.lower() == email.lower() for u in self._rows.values()):
      raise EmailAlreadyExistsError
    now = datetime.now(timezone.utc)
    user = AuthUser(
      id=self._next_id,
      email=email,
      password_hash=password_hash,
      is_active=True,
      is_verified=False,
      token_version=0,
      created_at=now,
      updated_at=now,
    )
    self._rows[user.id] = user
    self._next_id += 1
    return user
  
  async def get_by_email(self, *, email: str, conn: Any = None) -> AuthUser | None:
    return next((u for u in self._rows.values() if u.email.lower() == email.lower()), None)