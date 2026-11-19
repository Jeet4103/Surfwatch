from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
from typing import Any

import pytest

# Ensure the repository root is importable when this test is run directly.
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from src.operations.session.SessionOperation import SessionOperation
from src.repositories.models.models import RevokeReason
from src.repositories.session.SessionFakeRepository import FakeSessionRepository
from src.repositories.session.SessionRepository import PostgresSessionRepository
from tests.pg import create_user, delete_users, open_test_pool

SUFFIX = "@session-integration.test"
WEEK = timedelta(days=7)


class Clock:
  def __init__(self) -> None:
    self.now = datetime(2026, 11, 15, 12, 0, tzinfo=timezone.utc)

  def __call__(self) -> datetime:
    return self.now

  def advance(self, **kwargs) -> None:
    self.now += timedelta(**kwargs)


@dataclass
class Env:
  ops: SessionOperation
  user_id: int
  other_user_id: int
  clock: Clock
  pool: Any  # None for the fake


@pytest.fixture(params=["fake", "postgres"])
async def env(request):
  clock = Clock()

  if request.param == "fake":
    ops = SessionOperation(FakeSessionRepository(), session_ttl=WEEK, clock=clock)
    yield Env(ops, 1, 2, clock, None)
    return



  pool = await open_test_pool()  # skips when TEST_DATABASE_URL is not set
  try:
    ops = SessionOperation(PostgresSessionRepository(pool), session_ttl=WEEK, clock=clock)
    yield Env(
      ops,
      await create_user(pool, SUFFIX),
      await create_user(pool, SUFFIX),
      clock,
      pool,
    )
  finally:
    await delete_users(pool, SUFFIX)
    await pool.close()


async def test_full_lifecycle(env):
  ops, uid = env.ops, env.user_id
  s = await ops.create(uid, device_name="Chrome", ip_address="203.0.113.7", user_agent="UA")
  assert (await ops.get_active(s.id)).id == s.id
  assert [x.id for x in await ops.list_active(uid)] == [s.id]

  assert await ops.revoke(s.id, uid, RevokeReason.LOGOUT) is True
  assert await ops.get_active(s.id) is None
  assert await ops.list_active(uid) == []


async def test_ownership_and_double_revoke(env):
  ops = env.ops
  s = await ops.create(env.user_id)
  assert await ops.revoke(s.id, env.other_user_id) is False
  assert await ops.get_active(s.id) is not None
  assert await ops.revoke(s.id, env.user_id) is True
  assert await ops.revoke(s.id, env.user_id) is False


async def test_revoke_all_except_current_leaves_other_users(env):
  ops = env.ops
  current = await ops.create(env.user_id)
  await ops.create(env.user_id)
  await ops.create(env.user_id)
  theirs = await ops.create(env.other_user_id)

  assert await ops.revoke_all(env.user_id, except_session_id=current.id) == 2
  assert [s.id for s in await ops.list_active(env.user_id)] == [current.id]
  assert await ops.get_active(theirs.id) is not None


async def test_list_marks_current(env):
  ops = env.ops
  a = await ops.create(env.user_id)
  b = await ops.create(env.user_id)
  listed = await ops.list_active(env.user_id, current_session_id=b.id)
  assert {s.id: s.is_current for s in listed} == {a.id: False, b.id: True}


async def test_list_orders_by_recent_activity(env):
  ops = env.ops
  first = await ops.create(env.user_id)
  env.clock.advance(minutes=1)
  second = await ops.create(env.user_id)
  env.clock.advance(minutes=1)
  third = await ops.create(env.user_id)
  assert [s.id for s in await ops.list_active(env.user_id)] == [third.id, second.id, first.id]


async def test_expiry(env):
  ops = env.ops
  s = await ops.create(env.user_id)
  env.clock.advance(days=7, seconds=1)
  assert await ops.get_active(s.id) is None
  assert await ops.list_active(env.user_id) == []


async def test_ip_roundtrip_and_invalid_ip_dropped(env):
  ops = env.ops
  v6 = await ops.create(env.user_id, ip_address="2001:db8::1")
  bad = await ops.create(env.user_id, ip_address="not-an-ip")
  assert (await ops.get_active(v6.id)).ip_address == "2001:db8::1"
  assert (await ops.get_active(bad.id)).ip_address is None


async def test_touch_throttled(env):
  ops = env.ops
  s = await ops.create(env.user_id)
  start = s.last_active_at
  env.clock.advance(seconds=30)
  await ops.touch(s.id)
  assert (await ops.get_active(s.id)).last_active_at == start
  env.clock.advance(seconds=31)
  await ops.touch(s.id)
  assert (await ops.get_active(s.id)).last_active_at == env.clock.now


# --- Postgres-only behaviour (skipped for the fake) ---

async def test_transaction_rollback_discards_session(env):
  if env.pool is None:
    pytest.skip("postgres only")

  class Boom(Exception):
    pass

  created_id = None
  with pytest.raises(Boom):
    async with env.pool.acquire() as conn:
      async with conn.transaction():
        s = await env.ops.create(env.user_id, conn=conn)
        created_id = s.id
        assert await env.ops.get_active(s.id, conn=conn) is not None
        raise Boom

  assert await env.ops.get_active(created_id) is None


async def test_deleting_user_cascades_to_sessions(env):
  if env.pool is None:
    pytest.skip("postgres only")

  s = await env.ops.create(env.user_id)
  await env.pool.execute("DELETE FROM users WHERE id = $1", env.user_id)
  assert await env.ops.get_active(s.id) is None