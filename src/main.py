import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from config import get_settings
from logging_config import setup_logging

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
  settings = get_settings()
  logger.info("starting %s (%s)", settings.app_name, settings.app_env)
  # startup: DB pool init goes here (db_pool_min / db_pool_max)
  yield
  # shutdown: DB pool close goes here
  logger.info("shutting down %s", settings.app_name)


def create_app() -> FastAPI:
  setup_logging()
  settings = get_settings()
  app = FastAPI(title=settings.app_name, lifespan=lifespan)

  app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
  )

  @app.get("/health", tags=["system"])
  async def health() -> dict[str, str]:
    return {"status": "ok"}

  # routers get included here as layers are built
  return app

app = create_app()