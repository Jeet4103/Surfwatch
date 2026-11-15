from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum


class RevokeReason(StrEnum):
  LOGOUT = "logout"
  LOGOUT_ALL = "logout_all"
  REUSE_DETECTED = "reuse_detected"
  PASSWORD_CHANGED = "password_changed"
  USER_REVOKED = "user_revoked"
  ADMIN_REVOKED = "admin_revoked"
  
@dataclass(frozen=True)
class AuthSession:

  id: int
  user_id: int
  device_name: str | None
  ip_address: str | None
  user_agent: str | None
  created_at: datetime
  last_active_at: datetime
  expires_at: datetime
  revoked_at: datetime | None
  revoke_reason: str | None

  def is_active(self, now: datetime) -> bool:
    return self.revoked_at is None and self.expires_at > now
