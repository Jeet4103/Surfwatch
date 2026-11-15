import ipaddress
from datetime import datetime
from typing import Any

import asyncpg

from src.repositories.models.models import AuthSession
from src.repositories.session import SessionRepository

_COLUMNS = (
  "id, user_id, device_name, ip_address, user_agent, created_at, "
  "last_active_at, expires_at, revoked_at, revoke_reason"
)


def _parse_ip(value: str | None):
  if not value:
    return None
  try:
    return ipaddress.ip_address(value)
  except ValueError:
    return None


def _to_session(row: asyncpg.Record) -> AuthSession:
  ip = row["ip_address"]
  return AuthSession(
    id=row["id"],
    user_id=row["user_id"],
    device_name=row["device_name"],
    ip_address=str(ip) if ip is not None else None,
    user_agent=row["user_agent"],
    created_at=row["created_at"],
    last_active_at=row["last_active_at"],
    expires_at=row["expires_at"],
    revoked_at=row["revoked_at"],
    revoke_reason=row["revoke_reason"],
  )


class PostgresSessionRepository(SessionRepository):
  def __init__(self, pool: asyncpg.Pool) -> None:
    self._pool = pool

  def _db(self, conn: Any):
    return conn if conn is not None else self._pool

  async def create(
    self,
    *,
    user_id: int,
    device_name: str | None,
    ip_address: str | None,
    user_agent: str | None,
    now: datetime,
    expires_at: datetime,
    conn: Any = None,
  ) -> AuthSession:
    row = await self._db(conn).fetchrow(
      f"""
      INSERT INTO auth_sessions
        (user_id, device_name, ip_address, user_agent, created_at, last_active_at, expires_at)
      VALUES ($1, $2, $3, $4, $5, $5, $6)
      RETURNING {_COLUMNS}
      """,
      user_id, device_name, _parse_ip(ip_address), user_agent, now, expires_at,
    )
    return _to_session(row)

  async def get_by_id(self, session_id: int, *, conn: Any = None) -> AuthSession | None:
    row = await self._db(conn).fetchrow(
      f"SELECT {_COLUMNS} FROM auth_sessions WHERE id = $1", session_id
    )
    return _to_session(row) if row else None

  async def list_active_by_user(self, user_id: int, now: datetime, *, conn: Any = None) -> list[AuthSession]:
    rows = await self._db(conn).fetch(
      f"""
      SELECT {_COLUMNS} FROM auth_sessions
      WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > $2
      ORDER BY last_active_at DESC, id DESC
      """,
      user_id, now,
    )
    return [_to_session(r) for r in rows]

  async def revoke(
    self, session_id: int, user_id: int | None, reason: str, now: datetime, *, conn: Any = None
  ) -> bool:
    row = await self._db(conn).fetchrow(
      """
      UPDATE auth_sessions
      SET revoked_at = $3, revoke_reason = $4
      WHERE id = $1 AND revoked_at IS NULL AND ($2::int IS NULL OR user_id = $2::int)
      RETURNING id
      """,
      session_id, user_id, now, reason,
    )
    return row is not None

  async def revoke_all_for_user(
    self, user_id: int, reason: str, now: datetime, *, except_session_id: int | None = None, conn: Any = None
  ) -> int:
    rows = await self._db(conn).fetch(
      """
      UPDATE auth_sessions
      SET revoked_at = $2, revoke_reason = $3
      WHERE user_id = $1 AND revoked_at IS NULL AND ($4::int IS NULL OR id <> $4::int)
      RETURNING id
      """,
      user_id, now, reason, except_session_id,
    )
    return len(rows)

  async def touch(
    self, session_id: int, now: datetime, min_interval_seconds: float, *, conn: Any = None
  ) -> None:
    # only writes when last_active_at is older than the interval: avoids a write per request
    await self._db(conn).execute(
      """
      UPDATE auth_sessions
      SET last_active_at = $2
      WHERE id = $1 AND revoked_at IS NULL
        AND last_active_at < $2 - make_interval(secs => $3::float8)
      """,
      session_id, now, float(min_interval_seconds),
    )