import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from src.core.config import get_settings
from src.repositories.connection import close_pool, create_pool

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
  settings = get_settings()
  logger.info("starting %s (%s)", settings.app_name, settings.app_env)
  app.state.db_pool = await create_pool(settings)
  logger.info(
    "database pool ready (min=%s max=%s)",
    settings.db_pool_min_size,
    settings.db_pool_max_size,
  )
  try:
    yield
  finally:
    await close_pool(app.state.db_pool)
    logger.info("shutting down %s", settings.app_name)
