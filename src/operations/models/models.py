from datetime import datetime

from pydantic import BaseModel, ConfigDict


class Session(BaseModel):
  model_config = ConfigDict(frozen=True, from_attributes=True)

  id: int
  user_id: int
  device_name: str | None
  ip_address: str | None
  user_agent: str | None
  created_at: datetime
  last_active_at: datetime
  expires_at: datetime
  is_current: bool = False
  
class User(BaseModel):
  model_config = ConfigDict(frozen=True, from_attributes=True)

  id: int
  email: str
  is_active: bool
  is_verified: bool
  token_version: int
  created_at: datetime