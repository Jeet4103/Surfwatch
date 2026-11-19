from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from src.operations.models.models import Session
from src.operations.session.SessionOperation import SessionOperation
from src.repositories.models.models import RevokeReason
from src.repositories.session.SessionFakeRepository import FakeSessionRepository


class Clock:
  def __init__(self) -> None:
    self.now = datetime(2026, 11, 15, 12, 0, tzinfo=timezone.utc)

  def __call__(self) -> datetime:
    return self.now

  def advance(self, **kwargs) -> None:
    self.now += timedelta(**kwargs)


@pytest.fixture
def clock() -> Clock:
  return Clock()


@pytest.fixture
def ops(clock) -> SessionOperation:
  return SessionOperation(FakeSessionRepository(), session_ttl=timedelta(days=7), clock=clock)


async def test_create_sets_expiry_and_cleans_input(ops, clock):
  s = await ops.create(1, device_name="  Chrome  ", ip_address="not-an-ip", user_agent="x" * 1000)
  assert s.expires_at == clock.now + timedelta(days=7)
  assert s.device_name == "Chrome"
  assert s.ip_address is None
  assert len(s.user_agent) == 512


async def test_valid_ip_kept(ops):
  s = await ops.create(1, ip_address=" 192.168.1.5 ")
  assert s.ip_address == "192.168.1.5"


async def test_get_active_ok_then_expired(ops, clock):
  s = await ops.create(1)
  assert await ops.get_active(s.id) is not None
  clock.advance(days=7, seconds=1)
  assert await ops.get_active(s.id) is None


async def test_get_active_missing_returns_none(ops):
  assert await ops.get_active(999) is None


async def test_revoke_then_not_active(ops):
  s = await ops.create(1)
  assert await ops.revoke(s.id, 1) is True
  assert await ops.get_active(s.id) is None


async def test_revoke_records_reason(ops):
  s = await ops.create(1)
  await ops.revoke(s.id, 1, RevokeReason.USER_REVOKED)
  stored = await ops._repo.get_by_id(s.id)
  assert stored.revoke_reason == "user_revoked"
  assert stored.revoked_at is not None


async def test_revoke_other_users_session_denied(ops):
  s = await ops.create(1)
  assert await ops.revoke(s.id, 2) is False
  assert await ops.get_active(s.id) is not None


async def test_revoke_twice_second_false(ops):
  s = await ops.create(1)
  assert await ops.revoke(s.id, 1) is True
  assert await ops.revoke(s.id, 1) is False


async def test_revoke_all_except_current(ops):
  a = await ops.create(1)
  b = await ops.create(1)
  other = await ops.create(2)
  assert await ops.revoke_all(1, except_session_id=a.id) == 1
  assert await ops.get_active(a.id) is not None
  assert await ops.get_active(b.id) is None
  assert await ops.get_active(other.id) is not None


async def test_revoke_all_counts_only_active(ops):
  a = await ops.create(1)
  await ops.create(1)
  await ops.revoke(a.id, 1)
  assert await ops.revoke_all(1) == 1


async def test_list_active_excludes_revoked_and_expired_and_other_users(ops, clock):
  old = await ops.create(1)
  clock.advance(days=8)
  revoked = await ops.create(1)
  live = await ops.create(1)
  await ops.create(2)
  await ops.revoke(revoked.id, 1)
  assert [s.id for s in await ops.list_active(1)] == [live.id]
  assert old.id not in [s.id for s in await ops.list_active(1)]


async def test_touch_is_throttled(ops, clock):
  s = await ops.create(1)
  start = s.last_active_at
  clock.advance(seconds=30)
  await ops.touch(s.id)
  assert (await ops.get_active(s.id)).last_active_at == start
  clock.advance(seconds=31)
  await ops.touch(s.id)
  assert (await ops.get_active(s.id)).last_active_at == clock.now


async def test_touch_ignores_revoked(ops, clock):
  s = await ops.create(1)
  await ops.revoke(s.id, 1)
  clock.advance(minutes=5)
  await ops.touch(s.id)
  assert (await ops._repo.get_by_id(s.id)).last_active_at == s.last_active_at


async def test_operations_return_pydantic_output(ops):
  s = await ops.create(1, device_name="Chrome")
  assert isinstance(s, Session)
  assert isinstance(await ops.get_active(s.id), Session)
  assert not hasattr(s, "revoked_at")  # repository internals don't leak


async def test_output_is_immutable(ops):
  s = await ops.create(1)
  with pytest.raises(ValidationError):
    s.device_name = "hacked"


async def test_list_marks_current_session(ops):
  a = await ops.create(1)
  b = await ops.create(1)
  listed = await ops.list_active(1, current_session_id=a.id)
  assert {s.id: s.is_current for s in listed} == {a.id: True, b.id: False}


class _SpyRepo(FakeSessionRepository):
  def __init__(self) -> None:
    super().__init__()
    self.seen_conns: list = []

  async def create(self, **kwargs):
    self.seen_conns.append(kwargs.get("conn"))
    return await super().create(**kwargs)


async def test_conn_is_passed_through_to_repository(clock):
  repo = _SpyRepo()
  ops = SessionOperation(repo, session_ttl=timedelta(days=7), clock=clock)
  marker = object()
  await ops.create(1, conn=marker)
  assert repo.seen_conns == [marker]