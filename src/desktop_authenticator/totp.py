"""TOTP helpers and otpauth:// URI parsing."""

from __future__ import annotations

import re
import time
from urllib.parse import parse_qs, unquote, urlparse

import pyotp

from .vault import Account

_BASE32_RE = re.compile(r"^[A-Z2-7]+=*$")


def normalize_secret(secret: str) -> str:
    """Strip whitespace, uppercase, and validate Base32."""
    cleaned = secret.replace(" ", "").replace("-", "").upper()
    if not cleaned:
        raise ValueError("Secret is empty")
    if not _BASE32_RE.match(cleaned):
        raise ValueError("Secret is not valid Base32 (A-Z, 2-7)")
    # pyotp accepts unpadded base32; ensure it decodes.
    try:
        pyotp.TOTP(cleaned).now()
    except Exception as e:
        raise ValueError(f"Secret rejected by TOTP library: {e}") from e
    return cleaned


def parse_otpauth_uri(uri: str) -> Account:
    """Parse an otpauth://totp/Issuer:account?secret=...&issuer=... URI."""
    parsed = urlparse(uri)
    if parsed.scheme != "otpauth":
        raise ValueError("URI must start with otpauth://")
    if parsed.netloc.lower() != "totp":
        raise ValueError("Only otpauth://totp/ URIs are supported (not hotp)")

    label = unquote(parsed.path.lstrip("/"))
    if ":" in label:
        issuer_from_label, name = label.split(":", 1)
    else:
        issuer_from_label, name = "", label
    name = name.strip()

    params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
    secret = params.get("secret")
    if not secret:
        raise ValueError("otpauth URI missing 'secret' parameter")

    issuer = params.get("issuer", issuer_from_label).strip()
    digits = int(params.get("digits", "6"))
    period = int(params.get("period", "30"))
    algorithm = params.get("algorithm", "SHA1").upper()
    if algorithm not in {"SHA1", "SHA256", "SHA512"}:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    return Account(
        issuer=issuer,
        name=name,
        secret=normalize_secret(secret),
        digits=digits,
        period=period,
        algorithm=algorithm,
    )


def _digest_for(algorithm: str):
    import hashlib

    return {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}[
        algorithm.upper()
    ]


def current_code(account: Account, now: float | None = None) -> str:
    totp = pyotp.TOTP(
        account.secret,
        digits=account.digits,
        interval=account.period,
        digest=_digest_for(account.algorithm),
    )
    return totp.at(int(now if now is not None else time.time()))


def seconds_remaining(account: Account, now: float | None = None) -> float:
    t = now if now is not None else time.time()
    return account.period - (t % account.period)
