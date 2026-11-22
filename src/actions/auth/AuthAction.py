from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from typing import Any

from src.core.security.jwt import JWTService
from src.operations.auth.AuthOperation import UserOperation
from src.operations.models.models import User
from src.operations.refresh_token.RefreshTokenOperation import RefreshTokenOperation
from src.operations.session.SessionOperation import SessionOperation


@dataclass(frozen=True)
class LoginResult:
  access_token: str
  refresh_token: str
  expires_in: int
  user: User


class AuthAction:
  def __init__(
    self,
    users: UserOperation,
    sessions: SessionOperation,
    refresh_tokens: RefreshTokenOperation,
    jwt: JWTService,
    transaction: Callable[[], AbstractAsyncContextManager[Any]],
  ) -> None:
    self._users = users
    self._sessions = sessions
    self._refresh_tokens = refresh_tokens
    self._jwt = jwt
    self._transaction = transaction

  async def register(self, email: str, password: str) -> User:
    return await self._users.register(email, password)

  async def login(
    self,
    email: str,
    password: str,
    *,
    device_name: str | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
  ) -> LoginResult:
    user = await self._users.authenticate(email, password)

    async with self._transaction() as conn:
      session = await self._sessions.create(
        user.id,
        device_name=device_name,
        ip_address=ip_address,
        user_agent=user_agent,
        conn=conn,
      )
      refresh_token = await self._refresh_tokens.issue(session_id=session.id, conn=conn)

    access_token = self._jwt.create_access_token(
      user_id=user.id, session_id=session.id, token_version=user.token_version
    )
    return LoginResult(
      access_token=access_token,
      refresh_token=refresh_token,
      expires_in=self._jwt.access_ttl_seconds,
      user=user,
    )