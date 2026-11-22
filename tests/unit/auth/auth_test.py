import pytest

from src.core.errors import ValidationFailed
from src.core.security.password import PasswordService
from src.operations.auth.AuthOperation import EmailAlreadyExistsError, UserOperation
from src.repositories.auth.AuthFakeRepository import UserFakeRepository


@pytest.fixture
def ops() -> UserOperation:
  passwords = PasswordService(time_cost=1, memory_cost_kib=8, parallelism=1)
  return UserOperation(UserFakeRepository(), passwords)



async def test_register_normalizes_email_and_hides_hash(ops):
  u = await ops.register("  Bob@Example.COM ", "correct horse battery")
  assert u.email == "bob@example.com"
  assert u.is_verified is False
  assert not hasattr(u, "password_hash")


async def test_duplicate_email_case_insensitive(ops):
  await ops.register("a@example.com", "correct horse battery")
  with pytest.raises(EmailAlreadyExistsError):
    await ops.register("A@EXAMPLE.com", "another good password")


async def test_weak_password_rejected(ops):
  with pytest.raises(ValidationFailed):
    await ops.register("a@example.com", "short")