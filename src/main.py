from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.api.health import router as health_router
from src.core.config import get_settings
from src.core.logging_config import setup_logging
from src.dependencies.lifespan import lifespan


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

  app.include_router(health_router)
  # routers get included here as layers are built
  return app


app = create_app()