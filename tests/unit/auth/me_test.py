from datetime import timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.security import HTTPAuthorizationCredentials

from src.core.security.jwt import JWTService
from src.core.security.password import PasswordService
from src.dependencies.auth import NotAuthenticated, TokenExpired, get_identity
from src.operations.auth.AuthOperation import UserOperation
from src.operations.session.SessionOperation import SessionOperation
from src.repositories.auth.AuthFakeRepository import UserFakeRepository
from src.repositories.session.SessionFakeRepository import FakeSessionRepository


def _creds(token: str) -> HTTPAuthorizationCredentials:
  return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)


@pytest.fixture
def env():
  key = Ed25519PrivateKey.generate()
  private = key.private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
  )
  public = key.public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
  )
  jwt = JWTService(
    private_key_pem=private, signing_kid="k1", public_keys_pem={"k1": public},
    issuer="surfwatch", audience="surfwatch-api", leeway_seconds=0,
  )
  user_repo = UserFakeRepository()
  users = UserOperation(user_repo, PasswordService(time_cost=1, memory_cost_kib=8, parallelism=1))
  sessions = SessionOperation(FakeSessionRepository(), session_ttl=timedelta(days=7))
  return jwt, users, sessions, user_repo


async def _login(jwt, users, sessions):
  user = await users.register("me@example.com", "correct horse battery")
  session = await sessions.create(user.id)
  token = jwt.create_access_token(user_id=user.id, session_id=session.id, token_version=0)
  return user, session, token


async def test_valid_token_returns_identity(env):
  jwt, users, sessions, _ = env
  user, session, token = await _login(jwt, users, sessions)
  identity = await get_identity(_creds(token), jwt, users, sessions)
  assert identity.user.id == user.id
  assert identity.session_id == session.id


async def test_missing_credentials(env):
  jwt, users, sessions, _ = env
  with pytest.raises(NotAuthenticated):
    await get_identity(None, jwt, users, sessions)


async def test_garbage_token(env):
  jwt, users, sessions, _ = env
  with pytest.raises(NotAuthenticated):
    await get_identity(_creds("abc.def.ghi"), jwt, users, sessions)


async def test_expired_token_has_own_code(env):
  jwt, users, sessions, _ = env
  user = await users.register("me@example.com", "correct horse battery")
  session = await sessions.create(user.id)
  token = jwt.create_access_token(
    user_id=user.id, session_id=session.id, token_version=0, now=1_000_000_000
  )
  with pytest.raises(TokenExpired):
    await get_identity(_creds(token), jwt, users, sessions)


async def test_revoked_session_rejected(env):
  jwt, users, sessions, _ = env
  user, session, token = await _login(jwt, users, sessions)
  await sessions.revoke(session.id, user.id)
  with pytest.raises(NotAuthenticated):
    await get_identity(_creds(token), jwt, users, sessions)


async def test_token_version_mismatch_rejected(env):
  jwt, users, sessions, user_repo = env
  user, _, token = await _login(jwt, users, sessions)
  from dataclasses import replace
  user_repo._rows[user.id] = replace(user_repo._rows[user.id], token_version=1)
  with pytest.raises(NotAuthenticated):
    await get_identity(_creds(token), jwt, users, sessions)


async def test_inactive_user_rejected(env):
  jwt, users, sessions, user_repo = env
  user, _, token = await _login(jwt, users, sessions)
  from dataclasses import replace
  user_repo._rows[user.id] = replace(user_repo._rows[user.id], is_active=False)
  with pytest.raises(NotAuthenticated):
    await get_identity(_creds(token), jwt, users, sessions)