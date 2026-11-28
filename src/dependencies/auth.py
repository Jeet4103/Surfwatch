from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from src.core.errors import Unauthorized
from src.core.security.jwt import JWTService, InvalidTokenError, TokenExpiredError
from src.dependencies.services import (
    get_jwt_service,
    get_user_operation,
    get_session_operation,
)
from src.operations.auth.AuthOperation import UserOperation
from src.operations.models.models import User
from src.operations.session.SessionOperation import SessionOperation

_bearer = HTTPBearer(auto_error=False) #we raise our own errors shape
_CHALLENGE = {"WWW-Authenticate": "Bearer"}


class NotAuthenticated(Unauthorized):
    def __init__(self, message: str | None = None) -> None:
      super().__init__(message, headers=_CHALLENGE)
      
class TokenExpired(NotAuthenticated):
  code = "TOKEN_EXPIRED"
  message = "Access token expired, please login again"
  
@dataclass(frozen=True)
class Identity:
  user: User
  session_id: int


async def get_identity(
  creds: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
  jwt: Annotated[JWTService, Depends(get_jwt_service)],
  users: Annotated[UserOperation, Depends(get_user_operation)],
  sessions: Annotated[SessionOperation, Depends(get_session_operation)],
) -> Identity:
  if creds is None:
    raise NotAuthenticated()

  try:
    claims = jwt.decode_access_token(creds.credentials)
  except TokenExpiredError as exc:  # subclass of InvalidTokenError, so first
    raise TokenExpired() from exc
  except InvalidTokenError as exc:
    raise NotAuthenticated("Invalid access token") from exc

  # the access token is only valid while its session is live
  session = await sessions.get_active(claims.session_id)
  if session is None or session.user_id != claims.user_id:
    raise NotAuthenticated("Session is no longer active")

  user = await users.get_by_id(claims.user_id)
  # bumping users.token_version invalidates every outstanding access token
  if user is None or not user.is_active or user.token_version != claims.token_version:
    raise NotAuthenticated("Invalid access token")

  await sessions.touch(claims.session_id)
  return Identity(user=user, session_id=claims.session_id)


CurrentIdentity = Annotated[Identity, Depends(get_identity)]
  
  

