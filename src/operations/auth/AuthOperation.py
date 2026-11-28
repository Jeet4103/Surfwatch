from typing import Any

from src.core.errors import Conflict, ValidationFailed , Unauthorized
from src.core.security.password import PasswordService, WeakPasswordError
from src.operations.models.models import User
from src.repositories.models.models import AuthUser
from src.repositories.auth import EmailAlreadyExistsError as RepositoryEmailAlreadyExistsError, UserRepository


class EmailAlreadyExistsError(Conflict):
  code = "EMAIL_ALREADY_REGISTERED"
  message = "An account with this email already exists"

class InvalidCredentials(Unauthorized):
  code = "INVALID_CREDENTIALS"
  message = "Invalid email or password"

# Backwards-compatible name used by the integration tests and older callers.
EmailAlreadyRegistered = EmailAlreadyExistsError


def normalize_email(email: str) -> str:
  return email.strip().lower()



def _to_output(user: AuthUser) -> User:
  return User(
    id=user.id,
    email=user.email,
    is_active=user.is_active,
    is_verified=user.is_verified,
    token_version=user.token_version,
    created_at=user.created_at,
  )


class UserOperation:
  def __init__(self, repository: UserRepository, passwords: PasswordService) -> None:
    self._repo = repository
    self._passwords = passwords
    
  async def register(self, email: str, password: str, *, conn: Any = None) -> User:
    try:
      password_hash = await self._passwords.hash_async(password)
    except WeakPasswordError as exc:
      raise ValidationFailed(str(exc)) from exc
    
    try:
      user = await self._repo.create(
        email=normalize_email(email),
        password_hash=password_hash,
        conn=conn,
      )
    except RepositoryEmailAlreadyExistsError as exc:
      raise EmailAlreadyExistsError() from exc
    
    return _to_output(user)
  
  async def authenticate(self, email: str, password: str, *, conn: Any = None) -> User:
    user = await self._repo.get_by_email(email=normalize_email(email), conn=conn)
    # verifies against a dummy hash when user doesn't exist to prevent timing attacks
    ok = await self._passwords.verify_async(user.password_hash if user else None, password)
    if user is None or not ok or not user.is_active:
      raise InvalidCredentials()
    return _to_output(user)
  
  async def get_by_id(self, user_id: int, *, conn: Any = None) -> User | None:
    user = await self._repo.get_by_id(user_id=user_id, conn=conn)
    return _to_output(user) if user is not None else None