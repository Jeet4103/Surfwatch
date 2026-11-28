from datetime import timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.actions.auth.AuthAction import AuthAction
from src.core.errors import NotFound
from src.core.security.jwt import JWTService
from src.core.security.password import PasswordService
from src.operations.auth.AuthOperation import UserOperation
from src.operations.refresh_token.RefreshTokenOperation import RefreshTokenOperation
from src.operations.session.SessionOperation import SessionOperation
from src.repositories.auth.AuthFakeRepository import UserFakeRepository
from src.repositories.refresh_token.RefreshTokenFakeRepository import FakeRefreshTokenRepository
from src.repositories.session.SessionFakeRepository import FakeSessionRepository
from src.repositories.transaction import NoTransaction

PASSWORD = "correct horse battery"


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
    issuer="surfwatch", audience="surfwatch-api",
  )
  sessions = SessionOperation(FakeSessionRepository(), session_ttl=timedelta(days=7))
  action = AuthAction(
    UserOperation(UserFakeRepository(), PasswordService(time_cost=1, memory_cost_kib=8, parallelism=1)),
    sessions,
    RefreshTokenOperation(FakeRefreshTokenRepository(), token_ttl=timedelta(days=7)),
    jwt,
    NoTransaction(),
  )
  return action, jwt, sessions


async def _login(action, jwt, email="me@example.com"):
  r = await action.login(email, PASSWORD)
  return r.user.id, jwt.decode_access_token(r.access_token).session_id


async def _register_and_login(action, jwt, email="me@example.com"):
  await action.register(email, PASSWORD)
  return await _login(action, jwt, email)


async def test_logout_revokes_only_that_session(env):
  action, jwt, sessions = env
  uid, a = await _register_and_login(action, jwt)
  _, b = await _login(action, jwt)
  await action.logout(user_id=uid, session_id=a)
  assert await sessions.get_active(a) is None
  assert await sessions.get_active(b) is not None


async def test_logout_is_idempotent(env):
  action, jwt, _ = env
  uid, a = await _register_and_login(action, jwt)
  await action.logout(user_id=uid, session_id=a)
  await action.logout(user_id=uid, session_id=a)  # no error


async def test_logout_all_revokes_everything(env):
  action, jwt, sessions = env
  uid, a = await _register_and_login(action, jwt)
  _, b = await _login(action, jwt)
  assert await action.logout_all(user_id=uid) == 2
  assert await sessions.get_active(a) is None
  assert await sessions.get_active(b) is None


async def test_logout_all_keep_current(env):
  action, jwt, sessions = env
  uid, a = await _register_and_login(action, jwt)
  _, b = await _login(action, jwt)
  assert await action.logout_all(user_id=uid, keep_session_id=a) == 1
  assert await sessions.get_active(a) is not None
  assert await sessions.get_active(b) is None


async def test_list_sessions_marks_current(env):
  action, jwt, _ = env
  uid, a = await _register_and_login(action, jwt)
  _, b = await _login(action, jwt)
  listed = await action.list_sessions(user_id=uid, current_session_id=b)
  assert {s.id: s.is_current for s in listed} == {a: False, b: True}


async def test_revoke_session_ok_then_not_found(env):
  action, jwt, _ = env
  uid, _ = await _register_and_login(action, jwt)
  _, other = await _login(action, jwt)
  await action.revoke_session(user_id=uid, session_id=other)
  with pytest.raises(NotFound):
    await action.revoke_session(user_id=uid, session_id=other)


async def test_cannot_revoke_another_users_session(env):
  action, jwt, sessions = env
  uid, _ = await _register_and_login(action, jwt, "a@example.com")
  _, theirs = await _register_and_login(action, jwt, "b@example.com")
  with pytest.raises(NotFound):
    await action.revoke_session(user_id=uid, session_id=theirs)
  assert await sessions.get_active(theirs) is not None