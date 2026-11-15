import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

KEYS_DIR = Path(__file__).resolve().parent.parent / "keys"
PRIVATE = KEYS_DIR / "jwt_private.pem"
PUBLIC = KEYS_DIR / "jwt_public.pem"

KEYS_DIR.mkdir(exist_ok=True)
key = Ed25519PrivateKey.generate()
private_pem = key.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),
)
public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
)


def write_new(path: Path, content: bytes, mode: int = 0o644) -> None:
    """Create a key file exclusively so existing files can never be overwritten."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(descriptor, "wb") as file:
        file.write(content)


private_created = False
try:
    write_new(PRIVATE, private_pem, 0o600)
    private_created = True
    write_new(PUBLIC, public_pem)
except FileExistsError as exc:
    if private_created:
        PRIVATE.unlink()
    raise SystemExit("keys already exist, refusing to overwrite") from exc

print(f"written: {PRIVATE}\nwritten: {PUBLIC}")
