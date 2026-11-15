import base64
import json
import time

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.core.security.jwt import InvalidTokenError, JWTService, TokenExpiredError

ISS, AUD, KID = "surfwatch", "surfwatch-api", "k1"


def _pems():
    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    public = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private, public, key


@pytest.fixture
def env():
    private, public, key = _pems()
    svc = JWTService(
        private_key_pem=private,
        signing_kid=KID,
        public_keys_pem={KID: public},
        issuer=ISS,
        audience=AUD,
        access_ttl_seconds=900,
        leeway_seconds=0,
    )
    return svc, key


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _payload(**overrides):
    now = int(time.time())
    base = {
        "sub": "1", "sid": 2, "ver": 0, "jti": "x",
        "iss": ISS, "aud": AUD, "iat": now, "exp": now + 900,
    }
    base.update(overrides)
    return base


def test_roundtrip(env):
    svc, _ = env
    token = svc.create_access_token(user_id=7, session_id=42, token_version=3)
    claims = svc.decode_access_token(token)
    assert (claims.user_id, claims.session_id, claims.token_version) == (7, 42, 3)
    assert claims.expires_at - claims.issued_at == 900


def test_header_has_kid_and_eddsa(env):
    svc, _ = env
    header = pyjwt.get_unverified_header(svc.create_access_token(user_id=1, session_id=1, token_version=0))
    assert header["alg"] == "EdDSA" and header["kid"] == KID


def test_expired_token(env):
    svc, _ = env
    token = svc.create_access_token(user_id=1, session_id=1, token_version=0, now=int(time.time()) - 3600)
    with pytest.raises(TokenExpiredError):
        svc.decode_access_token(token)


def test_tampered_payload_rejected(env):
    svc, _ = env
    head, body, sig = svc.create_access_token(user_id=1, session_id=1, token_version=0).split(".")
    forged = {**json.loads(base64.urlsafe_b64decode(body + "==")), "sub": "999"}
    with pytest.raises(InvalidTokenError):
        svc.decode_access_token(f"{head}.{_b64(json.dumps(forged).encode())}.{sig}")


def test_alg_none_rejected(env):
    svc, _ = env
    head = _b64(json.dumps({"alg": "none", "typ": "JWT", "kid": KID}).encode())
    body = _b64(json.dumps(_payload()).encode())
    with pytest.raises(InvalidTokenError):
        svc.decode_access_token(f"{head}.{body}.")


def test_hs256_confusion_rejected(env):
    svc, _ = env
    token = pyjwt.encode(_payload(), "a-shared-secret-of-sufficient-length-123", algorithm="HS256", headers={"kid": KID})
    with pytest.raises(InvalidTokenError):
        svc.decode_access_token(token)


def test_wrong_issuer_and_audience_rejected(env):
    svc, key = env
    for bad in ({"iss": "evil"}, {"aud": "other-api"}):
        token = pyjwt.encode(_payload(**bad), key, algorithm="EdDSA", headers={"kid": KID})
        with pytest.raises(InvalidTokenError):
            svc.decode_access_token(token)


def test_missing_required_claim_rejected(env):
    svc, key = env
    payload = _payload()
    del payload["sid"]
    token = pyjwt.encode(payload, key, algorithm="EdDSA", headers={"kid": KID})
    with pytest.raises(InvalidTokenError):
        svc.decode_access_token(token)


def test_unknown_kid_rejected(env):
    svc, key = env
    token = pyjwt.encode(_payload(), key, algorithm="EdDSA", headers={"kid": "unknown"})
    with pytest.raises(InvalidTokenError):
        svc.decode_access_token(token)


def test_token_signed_by_other_key_rejected(env):
    svc, _ = env
    _, _, other = _pems()
    token = pyjwt.encode(_payload(), other, algorithm="EdDSA", headers={"kid": KID})
    with pytest.raises(InvalidTokenError):
        svc.decode_access_token(token)


def test_garbage_rejected(env):
    svc, _ = env
    for bad in ("", "abc", "a.b.c", "....", "x" * 500):
        with pytest.raises(InvalidTokenError):
            svc.decode_access_token(bad)


def test_key_rotation_old_kid_still_verifies():
    old_private, old_public, _ = _pems()
    new_private, new_public, _ = _pems()
    old_svc = JWTService(private_key_pem=old_private, signing_kid="old", public_keys_pem={"old": old_public},
                         issuer=ISS, audience=AUD)
    new_svc = JWTService(private_key_pem=new_private, signing_kid="new",
                         public_keys_pem={"old": old_public, "new": new_public}, issuer=ISS, audience=AUD)
    old_token = old_svc.create_access_token(user_id=1, session_id=1, token_version=0)
    assert new_svc.decode_access_token(old_token).user_id == 1