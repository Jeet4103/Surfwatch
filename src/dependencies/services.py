from datetime import timedelta
from functools import lru_cache
from typing import Annotated

import asyncpg
from fastapi import Depends

from src.actions.auth.AuthAction import AuthAction
from src.core.config import get_settings
from src.core.security.jwt import JWTService
from src.core.security.password import PasswordPolicy, PasswordService
from src.dependencies.database import get_pool
from src.operations.auth.AuthOperation import UserOperation
from src.operations.refresh_token.RefreshTokenOperation import RefreshTokenOperation
from src.operations.session.SessionOperation import SessionOperation
from src.repositories.auth.AuthRepository import PostgresUserRepository
from src.repositories.refresh_token.RefreshTokenRepository import RefreshTokenRepository
from src.repositories.session.SessionRepository import PostgresSessionRepository
from src.repositories.transaction import PostgresTransaction


@lru_cache
def get_password_service() -> PasswordService:
  s = get_settings()
  return PasswordService(
    time_cost=s.argon2_time_cost,
    memory_cost_kib=s.argon2_memory_cost_kib,
    parallelism=s.argon2_parallelism,
    policy=PasswordPolicy(s.password_min_length, s.password_max_length),
  )


@lru_cache
def get_jwt_service() -> JWTService:
  s = get_settings()
  return JWTService.from_files(
    private_key_path=s.jwt_private_key_path,
    public_key_path=s.jwt_public_key_path,
    kid=s.jwt_key_id,
    issuer=s.jwt_issuer,
    audience=s.jwt_audience,
    access_ttl_seconds=s.access_token_ttl_minutes * 60,
    leeway_seconds=s.jwt_leeway_seconds,
  )


def get_user_operation(
  pool: Annotated[asyncpg.Pool, Depends(get_pool)],
  passwords: Annotated[PasswordService, Depends(get_password_service)],
) -> UserOperation:
  return UserOperation(PostgresUserRepository(pool), passwords)


def get_session_operation(
  pool: Annotated[asyncpg.Pool, Depends(get_pool)],
) -> SessionOperation:
  ttl = timedelta(days=get_settings().refresh_token_ttl_days)
  return SessionOperation(PostgresSessionRepository(pool), session_ttl=ttl)


def get_refresh_token_operation(
  pool: Annotated[asyncpg.Pool, Depends(get_pool)],
) -> RefreshTokenOperation:
  ttl = timedelta(days=get_settings().refresh_token_ttl_days)
  return RefreshTokenOperation(RefreshTokenRepository(pool), token_ttl=ttl)


def get_auth_action(
  pool: Annotated[asyncpg.Pool, Depends(get_pool)],
  users: Annotated[UserOperation, Depends(get_user_operation)],
  sessions: Annotated[SessionOperation, Depends(get_session_operation)],
  refresh_tokens: Annotated[RefreshTokenOperation, Depends(get_refresh_token_operation)],
  jwt: Annotated[JWTService, Depends(get_jwt_service)],
) -> AuthAction:
  return AuthAction(users, sessions, refresh_tokens, jwt, PostgresTransaction(pool))


AuthActions = Annotated[AuthAction, Depends(get_auth_action)]