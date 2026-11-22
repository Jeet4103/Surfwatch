from abc import ABC, abstractmethod
from typing import Any

from src.repositories.models.models import AuthUser

class EmailAlreadyExistsError(Exception):
  pass

class UserRepository(ABC):
  @abstractmethod
  async def create(self, *, email: str, password_hash: str, conn: Any = None) -> AuthUser:
    pass
  
  @abstractmethod
  async def get_by_email(self, *, email: str, conn: Any = None) -> AuthUser | None:
    pass