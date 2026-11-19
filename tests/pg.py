import os
import uuid

import asyncpg
import pytest


async def open_test_pool() -> asyncpg.Pool:
  url = os.environ.get("TEST_DATABASE_URL")
  if not url:
    pytest.skip("TEST_DATABASE_URL not set")
  dbname = url.rsplit("/", 1)[-1].split("?")[0]
  if "test" not in dbname:
    # never run against a dev/prod database by accident
    raise RuntimeError(f"TEST_DATABASE_URL must point to a database with 'test' in its name, got '{dbname}'")
  return await asyncpg.create_pool(url, min_size=1, max_size=3)


async def create_user(pool: asyncpg.Pool, suffix: str) -> int:
  email = f"{uuid.uuid4().hex[:12]}{suffix}"
  return await pool.fetchval("INSERT INTO users (email) VALUES ($1) RETURNING id", email)


async def delete_users(pool: asyncpg.Pool, suffix: str) -> None:
  # cascades to auth_sessions and refresh_tokens
  await pool.execute("DELETE FROM users WHERE email LIKE $1", f"%{suffix}")