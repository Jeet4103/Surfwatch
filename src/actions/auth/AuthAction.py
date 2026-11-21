# src/actions/auth/AuthAction.py
from src.operations.models.models import User
from src.operations.auth.AuthOperation import UserOperation


class AuthAction:
  def __init__(self, users: UserOperation) -> None:
    self._users = users

  async def register(self, email: str, password: str) -> User:
    return await self._users.register(email, password)