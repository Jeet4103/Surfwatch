import asyncio

import pytest

from src.core.security.password import PasswordService, WeakPasswordError

# cheap params so tests run fast
svc = PasswordService(time_cost=1, memory_cost_kib=8, parallelism=1)


def test_hash_is_argon2id_and_not_plaintext():
    h = svc.hash("correct horse battery")
    assert h.startswith("$argon2id$")
    assert "correct horse" not in h


def test_same_password_different_hash():
    assert svc.hash("correct horse battery") != svc.hash("correct horse battery")


def test_verify_ok_and_wrong():
    h = svc.hash("correct horse battery")
    assert svc.verify(h, "correct horse battery") is True
    assert svc.verify(h, "wrong password!!") is False


def test_verify_garbage_hash_returns_false():
    assert svc.verify("not-a-hash", "whatever123") is False


def test_policy_rejects_short_long_blank():
    with pytest.raises(WeakPasswordError):
        svc.hash("short")
    with pytest.raises(WeakPasswordError):
        svc.hash("x" * 129)
    with pytest.raises(WeakPasswordError):
        svc.hash("          ")


def test_needs_rehash_when_params_change():
    old = svc.hash("correct horse battery")
    stronger = PasswordService(time_cost=2, memory_cost_kib=16, parallelism=1)
    assert stronger.needs_rehash(old) is True
    assert svc.needs_rehash(old) is False


def test_async_roundtrip():
    async def run():
        h = await svc.hash_async("correct horse battery")
        assert await svc.verify_async(h, "correct horse battery") is True
        assert await svc.verify_async(h, "nope nope nope") is False

    asyncio.run(run())