import re
from datetime import datetime

from pydantic import BaseModel, ConfigDict, field_validator

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