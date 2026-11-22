import asyncio
from dataclasses import dataclass
from typing import Any

import pytest

from src.core.errors import ValidationFailed
from src.core.security.password import PasswordService
from src.operations.auth.AuthOperation import EmailAlreadyRegistered, UserOperation
from src.repositories.auth.AuthRepository import PostgresUserRepository
from src.repositories.auth.AuthFakeRepository import UserFakeRepository
from tests.pg import delete_users, open_test_pool

SUFFIX = "@user-integration.test"
PASSWORD = "correct horse battery"

# cheap params so tests run fast
passwords = PasswordService(time_cost=1, memory_cost_kib=8, parallelism=1)


@dataclass
class Env:
  ops: UserOperation
  pool: Any  # None for the fake


@pytest.fixture(params=["fake", "postgres"])
async def env(request):
  if request.param == "fake":
    yield Env(UserOperation(UserFakeRepository(), passwords), None)
    return

  pool = await open_test_pool()  # skips when TEST_DATABASE_URL is not set
  try:
    yield Env(UserOperation(PostgresUserRepository(pool), passwords), pool)
  finally:
    await delete_users(pool, SUFFIX)
    await pool.close()


def email(name: str) -> str:
  return f"{name}{SUFFIX}"


async def test_register_normalizes_email_and_hides_hash(env):
  u = await env.ops.register(f"  Bob{SUFFIX.upper()} ", PASSWORD)
  assert u.email == email("bob").lower()
  assert u.is_active is True
  assert u.is_verified is False
  assert not hasattr(u, "password_hash")


async def test_duplicate_email_is_case_insensitive(env):
  await env.ops.register(email("dup"), PASSWORD)
  with pytest.raises(EmailAlreadyRegistered):
    await env.ops.register(email("DUP"), "another good password")


async def test_weak_password_rejected_and_nothing_stored(env):
  with pytest.raises(ValidationFailed):
    await env.ops.register(email("weak"), "short")
  # the email is still free, so the failed attempt left nothing behind
  assert (await env.ops.register(email("weak"), PASSWORD)).email == email("weak")


async def test_ids_are_unique(env):
  a = await env.ops.register(email("a"), PASSWORD)
  b = await env.ops.register(email("b"), PASSWORD)
  assert a.id != b.id


async def test_concurrent_duplicate_registration_only_one_wins(env):
  results = await asyncio.gather(
    *(env.ops.register(email("race"), PASSWORD) for _ in range(3)),
    return_exceptions=True,
  )
  ok = [r for r in results if not isinstance(r, Exception)]
  failed = [r for r in results if isinstance(r, EmailAlreadyRegistered)]
  assert len(ok) == 1
  assert len(failed) == 2


# --- Postgres-only behaviour (skipped for the fake) ---

async def test_stored_hash_is_argon2id_not_plaintext(env):
  if env.pool is None:
    pytest.skip("postgres only")

  u = await env.ops.register(email("hash"), PASSWORD)
  stored = await env.pool.fetchval("SELECT password_hash FROM users WHERE id = $1", u.id)
  assert stored.startswith("$argon2id$")
  assert PASSWORD not in stored
  assert passwords.verify(stored, PASSWORD) is True


async def test_email_stored_lowercased(env):
  if env.pool is None:
    pytest.skip("postgres only")

  u = await env.ops.register(f"MiXeD{SUFFIX.upper()}", PASSWORD)
  stored = await env.pool.fetchval("SELECT email FROM users WHERE id = $1", u.id)
  assert stored == stored.lower()


async def test_transaction_rollback_discards_user(env):
  if env.pool is None:
    pytest.skip("postgres only")

  class Boom(Exception):
    pass

  with pytest.raises(Boom):
    async with env.pool.acquire() as conn:
      async with conn.transaction():
        await env.ops.register(email("rollback"), PASSWORD, conn=conn)
        raise Boom

  # email is free again because the insert was rolled back
  assert (await env.ops.register(email("rollback"), PASSWORD)).email == email("rollback")


async def test_deleting_user_cascades_to_sessions(env):
  if env.pool is None:
    pytest.skip("postgres only")

  u = await env.ops.register(email("cascade"), PASSWORD)
  await env.pool.execute(
    "INSERT INTO auth_sessions (user_id, expires_at) VALUES ($1, now() + interval '1 day')",
    u.id,
  )
  await env.pool.execute("DELETE FROM users WHERE id = $1", u.id)
  count = await env.pool.fetchval("SELECT COUNT(*) FROM auth_sessions WHERE user_id = $1", u.id)
  assert count == 0
