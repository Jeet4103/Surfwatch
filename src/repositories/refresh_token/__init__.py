from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any

from src.repositories.models.models import AuthRefreshToken

class RefreshTokenRepository(ABC):
    @abstractmethod
    async def create(self,
                     *,
                     session_id: int,
                     token_hash: str,
                     parent_token_id: int | None,
                     now: datetime,
                     expires_at: datetime,
                     conn: Any = None,) -> AuthRefreshToken:
        pass