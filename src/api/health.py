# src/api/health.py
from typing import Annotated

import asyncpg
from fastapi import APIRouter, Depends, Response, status
from pydantic import BaseModel

from src.dependencies.database import get_pool
from src.repositories.connection import ping

router = APIRouter(tags=["health"])


class HealthResponse(BaseModel):
  status: str
  database: str


@router.get("/health", response_model=HealthResponse)
async def health(
  response: Response,
  pool: Annotated[asyncpg.Pool, Depends(get_pool)],
) -> HealthResponse:
  try:
    db_ok = await ping(pool)
  except Exception:
    db_ok = False

  if not db_ok:
    response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return HealthResponse(status="degraded", database="down")
  return HealthResponse(status="ok", database="up")
