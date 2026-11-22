from dataclasses import replace
from datetime import timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.actions.auth.AuthAction import AuthAction
from src.core.security.jwt import JWTService
from src.core.security.password import PasswordService
from src.operations.auth.AuthOperation import InvalidCredentials, UserOperation
from src.operations.refresh_token.RefreshTokenOperation import RefreshTokenOperation, hash_token
from src.operations.session.SessionOperation import SessionOperation
from src.repositories.refresh_token.RefreshTokenFakeRepository import FakeRefreshTokenRepository
from src.repositories.session.SessionFakeRepository import FakeSessionRepository
from src.repositories.transaction import NoTransaction
from src.repositories.auth.AuthFakeRepository import UserFakeRepository

PASSWORD = "correct horse battery"


@pytest.fixture
def parts():
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
  user_repo = UserFakeRepository()
  token_repo = FakeRefreshTokenRepository()
  passwords = PasswordService(time_cost=1, memory_cost_kib=8, parallelism=1)
  action = AuthAction(
    UserOperation(user_repo, passwords),
    SessionOperation(FakeSessionRepository(), session_ttl=timedelta(days=7)),
    RefreshTokenOperation(token_repo, token_ttl=timedelta(days=7)),
    jwt,
    NoTransaction(),
  )
  return action, jwt, user_repo, token_repo


async def test_login_issues_working_tokens(parts):
  action, jwt, _, token_repo = parts
  user = await action.register("Me@Example.com", PASSWORD)
  result = await action.login(" ME@example.com ", PASSWORD, device_name="Chrome")

  claims = jwt.decode_access_token(result.access_token)
  assert claims.user_id == user.id
  assert claims.session_id >= 1
  assert result.expires_in == 900
  # only the hash is stored, never the plaintext token
  stored = [t.token_hash for t in token_repo._rows.values()]
  assert stored == [hash_token(result.refresh_token)]
  assert result.refresh_token not in stored


async def test_wrong_password_and_unknown_email_same_error(parts):
  action, *_ = parts
  await action.register("me@example.com", PASSWORD)
  with pytest.raises(InvalidCredentials) as wrong:
    await action.login("me@example.com", "not the password")
  with pytest.raises(InvalidCredentials) as unknown:
    await action.login("nobody@example.com", PASSWORD)
  assert wrong.value.message == unknown.value.message


async def test_inactive_user_cannot_login(parts):
  action, _, user_repo, _ = parts
  user = await action.register("me@example.com", PASSWORD)
  user_repo._rows[user.id] = replace(user_repo._rows[user.id], is_active=False)
  with pytest.raises(InvalidCredentials):
    await action.login("me@example.com", PASSWORD)


async def test_each_login_creates_new_session_and_token(parts):
  action, jwt, _, token_repo = parts
  await action.register("me@example.com", PASSWORD)
  a = await action.login("me@example.com", PASSWORD)
  b = await action.login("me@example.com", PASSWORD)
  assert a.refresh_token != b.refresh_token
  assert jwt.decode_access_token(a.access_token).session_id != jwt.decode_access_token(b.access_token).session_id
  assert len(token_repo._rows) == 2