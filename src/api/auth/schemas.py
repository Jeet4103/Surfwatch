import re
from datetime import datetime, timedelta

from pydantic import BaseModel, ConfigDict, field_validator, Field

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class RegisterRequest(BaseModel):
  email: str
  password: str

  @field_validator("email")
  @classmethod
  def _check_email(cls, value: str) -> str:
    value = value.strip().lower()
    if len(value) > 255 or not _EMAIL_RE.match(value):
      raise ValueError("must be a valid email address")
    return value


class UserResponse(BaseModel):
  model_config = ConfigDict(from_attributes=True)

  id: int
  email: str
  is_verified: bool
  created_at: datetime
  
class LoginRequest(BaseModel):
  email: str = Field(min_length=1, max_length=255)
  password: str = Field(min_length=1, max_length=128)  # cap avoids hashing huge inputs
  device_name: str | None = Field(default=None, max_length=150)


class TokenResponse(BaseModel):
  access_token: str
  refresh_token: str
  token_type: str = "bearer"
  expires_in: int
  user: UserResponse  

class SessionResponse(BaseModel):
  model_config = ConfigDict(from_attributes=True)

  id: int
  device_name: str | None
  ip_address: str | None
  user_agent: str | None
  created_at: datetime
  last_active_at: datetime
  expires_at: datetime
  is_current: bool


class LogoutAllResponse(BaseModel):
  revoked: int