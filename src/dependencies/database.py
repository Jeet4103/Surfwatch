import asyncpg
from fastapi import Request


def get_pool(request: Request) -> asyncpg.Pool:
  return request.app.state.db_pool