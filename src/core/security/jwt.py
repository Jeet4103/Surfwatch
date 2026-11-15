import time
import uuid
from dataclasses import dataclass
from pathlib import Path

import jwt
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from jwt.exceptions import ExpiredSignatureError
from jwt.exceptions import InvalidTokenError as PyJWTInvalidTokenError

ALGORITHM = "EdDSA"
REQUIRED_CLAIMS = ["exp", "iat", "iss", "aud", "sub", "sid", "jti", "ver"]


class InvalidTokenError(Exception):
  """Token is malformed, tampered, wrong issuer/audience, or otherwise unusable."""
  

class TokenExpiredError(InvalidTokenError):
    """Token was valid but has expired."""  
  
  
@dataclass(frozen=True)
class AccessTokenClaims:
    user_id: int
    session_id: int
    token_version: int
    jti: str
    issued_at: int
    expires_at: int
    
def _is_int(value: object) -> bool:
  return isinstance(value, int) and not isinstance(value, bool)


class JWTService:
    def __init__(
        self,
        *,
        private_key_pem: bytes,
        signing_kid: str,
        public_keys_pem: dict[str, bytes],
        issuer: str,
        audience: str,
        access_ttl_seconds: int = 900,
        leeway_seconds: int = 10,
    ) -> None:
        if signing_kid not in public_keys_pem:
            raise ValueError("public_keys_pem must include the signing kid")
        self._private_key = load_pem_private_key(private_key_pem, password=None)
        self._signing_kid = signing_kid
        # kid -> public key. Keep old kids here during key rotation.
        self._public_keys = {
            kid: load_pem_public_key(pem) for kid, pem in public_keys_pem.items()
        }
        self._issuer = issuer
        self._audience = audience
        self._access_ttl = access_ttl_seconds
        self._leeway = leeway_seconds

    @classmethod
    def from_files(
        cls,
        *,
        private_key_path: str | Path,
        public_key_path: str | Path,
        kid: str,
        issuer: str,
        audience: str,
        access_ttl_seconds: int = 900,
        leeway_seconds: int = 10,
    ) -> "JWTService":
        return cls(
            private_key_pem=Path(private_key_path).read_bytes(),
            signing_kid=kid,
            public_keys_pem={kid: Path(public_key_path).read_bytes()},
            issuer=issuer,
            audience=audience,
            access_ttl_seconds=access_ttl_seconds,
            leeway_seconds=leeway_seconds,
        )

    @property
    def access_ttl_seconds(self) -> int:
        return self._access_ttl

    def create_access_token(
        self,
        *,
        user_id: int,
        session_id: int,
        token_version: int,
        now: int | None = None,
    ) -> str:
        issued_at = int(time.time()) if now is None else now
        payload = {
            "sub": str(user_id),
            "sid": session_id,
            "ver": token_version,
            "jti": uuid.uuid4().hex,
            "iss": self._issuer,
            "aud": self._audience,
            "iat": issued_at,
            "exp": issued_at + self._access_ttl,
        }
        return jwt.encode(
            payload,
            self._private_key,
            algorithm=ALGORITHM,
            headers={"kid": self._signing_kid},
        )

    def decode_access_token(self, token: str) -> AccessTokenClaims:
        try:
            header = jwt.get_unverified_header(token)
        except PyJWTInvalidTokenError as exc:
            raise InvalidTokenError("malformed token") from exc

        if header.get("alg") != ALGORITHM:
            raise InvalidTokenError("unexpected algorithm")

        kid = header.get("kid")
        if not isinstance(kid, str) or kid not in self._public_keys:
            raise InvalidTokenError("unknown key id")

        try:
            payload = jwt.decode(
                token,
                self._public_keys[kid],
                algorithms=[ALGORITHM],
                issuer=self._issuer,
                audience=self._audience,
                leeway=self._leeway,
                options={"require": REQUIRED_CLAIMS},
            )
        except ExpiredSignatureError as exc:
            raise TokenExpiredError("token expired") from exc
        except PyJWTInvalidTokenError as exc:
            raise InvalidTokenError("invalid token") from exc

        subject = payload["sub"]
        if not isinstance(subject, str) or not subject.isdecimal():
            raise InvalidTokenError("invalid subject")
        try:
            user_id = int(subject)
        except (TypeError, ValueError) as exc:
            raise InvalidTokenError("invalid subject") from exc

        if (
            user_id <= 0
            or not _is_int(payload["sid"])
            or payload["sid"] <= 0
            or not _is_int(payload["ver"])
            or payload["ver"] < 0
            or not isinstance(payload["jti"], str)
            or not payload["jti"]
            or not _is_int(payload["iat"])
            or not _is_int(payload["exp"])
            or payload["exp"] <= payload["iat"]
        ):
            raise InvalidTokenError("invalid claims")

        return AccessTokenClaims(
            user_id=user_id,
            session_id=payload["sid"],
            token_version=payload["ver"],
            jti=payload["jti"],
            issued_at=payload["iat"],
            expires_at=payload["exp"],
        )
    
