from functools import lru_cache
from typing import Annotated

import asyncpg
from fastapi import Depends

from src.actions.auth.AuthAction import AuthAction
from src.core.config import get_settings
from src.core.security.password import PasswordPolicy, PasswordService
from src.dependencies.database import get_pool
from src.operations.auth.AuthOperation import UserOperation
from src.repositories.auth.AuthRepository import PostgresUserRepository


@lru_cache
def get_password_service() -> PasswordService:
  s = get_settings()
  return PasswordService(
    time_cost=s.argon2_time_cost,
    memory_cost_kib=s.argon2_memory_cost_kib,
    parallelism=s.argon2_parallelism,
    policy=PasswordPolicy(s.password_min_length, s.password_max_length),
  )


def get_user_operation(
  pool: Annotated[asyncpg.Pool, Depends(get_pool)],
  passwords: Annotated[PasswordService, Depends(get_password_service)],
) -> UserOperation:
  return UserOperation(PostgresUserRepository(pool), passwords)


def get_auth_action(
  users: Annotated[UserOperation, Depends(get_user_operation)],
) -> AuthAction:
  return AuthAction(users)


AuthActions = Annotated[AuthAction, Depends(get_auth_action)]