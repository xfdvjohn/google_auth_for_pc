"""Encrypted local vault for TOTP account secrets.

Format (JSON on disk):
    {
        "version": 1,
        "kdf": "pbkdf2-sha256",
        "iterations": <int>,
        "salt": <base64>,
        "nonce": <base64>,
        "ciphertext": <base64>  # AES-GCM(plaintext=JSON accounts)
    }
"""

from __future__ import annotations

import base64
import json
import os
import secrets
from dataclasses import asdict, dataclass, field
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

VAULT_VERSION = 1
PBKDF2_ITERATIONS = 600_000
SALT_BYTES = 16
NONCE_BYTES = 12
KEY_BYTES = 32


class VaultError(Exception):
    pass


class InvalidPassword(VaultError):
    pass


@dataclass
class Account:
    issuer: str
    name: str
    secret: str  # Base32, uppercase, no padding (as used by pyotp)
    digits: int = 6
    period: int = 30
    algorithm: str = "SHA1"  # SHA1 / SHA256 / SHA512


@dataclass
class VaultData:
    accounts: list[Account] = field(default_factory=list)

    def to_json(self) -> bytes:
        return json.dumps(
            {"accounts": [asdict(a) for a in self.accounts]},
            separators=(",", ":"),
        ).encode("utf-8")

    @classmethod
    def from_json(cls, data: bytes) -> "VaultData":
        obj = json.loads(data.decode("utf-8"))
        return cls(accounts=[Account(**a) for a in obj.get("accounts", [])])


def _derive_key(password: str, salt: bytes, iterations: int) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_BYTES,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


class Vault:
    """In-memory vault bound to a file path and a master password."""

    def __init__(self, path: Path, password: str, data: VaultData):
        self.path = path
        self._password = password
        self.data = data

    @classmethod
    def create(cls, path: Path, password: str) -> "Vault":
        if path.exists():
            raise VaultError(f"Vault already exists at {path}")
        v = cls(path=path, password=password, data=VaultData())
        v.save()
        return v

    @classmethod
    def load(cls, path: Path, password: str) -> "Vault":
        if not path.exists():
            raise VaultError(f"No vault at {path}")
        header = json.loads(path.read_text("utf-8"))
        if header.get("version") != VAULT_VERSION:
            raise VaultError(f"Unsupported vault version: {header.get('version')}")
        salt = _b64d(header["salt"])
        nonce = _b64d(header["nonce"])
        ciphertext = _b64d(header["ciphertext"])
        iterations = int(header["iterations"])
        key = _derive_key(password, salt, iterations)
        try:
            plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
        except Exception as e:
            raise InvalidPassword("Wrong master password or vault is corrupted") from e
        return cls(path=path, password=password, data=VaultData.from_json(plaintext))

    def save(self) -> None:
        salt = secrets.token_bytes(SALT_BYTES)
        nonce = secrets.token_bytes(NONCE_BYTES)
        key = _derive_key(self._password, salt, PBKDF2_ITERATIONS)
        ciphertext = AESGCM(key).encrypt(nonce, self.data.to_json(), None)
        header = {
            "version": VAULT_VERSION,
            "kdf": "pbkdf2-sha256",
            "iterations": PBKDF2_ITERATIONS,
            "salt": _b64e(salt),
            "nonce": _b64e(nonce),
            "ciphertext": _b64e(ciphertext),
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(header, indent=2), "utf-8")
        os.replace(tmp, self.path)

    def change_password(self, new_password: str) -> None:
        self._password = new_password
        self.save()


def default_vault_path() -> Path:
    """Per-user vault location. On Windows: %APPDATA%\\DesktopAuthenticator\\vault.json."""
    if os.name == "nt":
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    else:
        base = Path(
            os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")
        )
    return base / "DesktopAuthenticator" / "vault.json"
