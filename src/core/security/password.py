import asyncio
from dataclasses import dataclass

from argon2 import PasswordHasher as Argon2
from argon2 import Type
from argon2.exceptions import InvalidHashError, VerificationError


class WeakPasswordError(ValueError):
  pass


@dataclass(frozen=True)
class PasswordPolicy:
  min_length: int = 8
  max_length: int = 128
  
  def validate(self, password: str) -> None:
    if (len(password) < self.min_length or len(password) > self.max_length):
      raise WeakPasswordError(
        f"Password must be between {self.min_length} and {self.max_length} characters."
      )
    if password.strip() == "":
      raise WeakPasswordError("Password must not be blank")  
      

class PasswordService:
  def __init__(
    self,
    time_cost: int = 3,
    memory_cost_kib: int = 65536,
    parallelism: int = 4,
    policy: PasswordPolicy | None = None,
  ) -> None:
    self._hasher = Argon2(
      time_cost=time_cost,
      memory_cost=memory_cost_kib,
      parallelism=parallelism,
      type=Type.ID,
    )
    self._policy = policy or PasswordPolicy()
    # verified against when the user doesn't exist, so response time
    # doesn't reveal whether an email is registered
    self._dummy_hash = self._hasher.hash("surfwatch-dummy-password")

  @property
  def policy(self) -> PasswordPolicy:
    return self._policy

  @property
  def dummy_hash(self) -> str:
    return self._dummy_hash

  def hash(self, password: str) -> str:
    self._policy.validate(password)
    return self._hasher.hash(password)

  def verify(self, stored_hash: str | None, password: str) -> bool:
    if stored_hash is None:
      stored_hash = self._dummy_hash

    try:
      return self._hasher.verify(stored_hash, password)
    except (InvalidHashError, VerificationError):
      return False  
    
  def verify_dummy(self, password: str) -> None:
    self.verify(self._dummy_hash, password)
    
  def needs_rehash(self, password_hash: str) -> bool:
    return self._hasher.check_needs_rehash(password_hash)
  
  async def hash_async(self, password: str) -> str:
    self.policy.validate(password)
    return await asyncio.to_thread(self._hasher.hash, password)

  async def verify_async(self, stored_hash: str | None, password: str) -> bool:
    return await asyncio.to_thread(self.verify, stored_hash, password)

  async def verify_dummy_async(self, password: str) -> None:
    await asyncio.to_thread(self.verify_dummy, password)