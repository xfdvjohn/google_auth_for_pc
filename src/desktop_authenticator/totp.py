"""TOTP helpers and otpauth:// URI parsing."""

from __future__ import annotations

import base64
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


def _read_varint(data: bytes, pos: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        if pos >= len(data):
            raise ValueError("Truncated varint")
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7
        if shift > 63:
            raise ValueError("Varint too long")


def _read_field(data: bytes, pos: int) -> tuple[int, int, object, int]:
    tag, pos = _read_varint(data, pos)
    wire_type = tag & 0x07
    field_number = tag >> 3
    if wire_type == 0:
        value, pos = _read_varint(data, pos)
    elif wire_type == 2:
        length, pos = _read_varint(data, pos)
        if pos + length > len(data):
            raise ValueError("Truncated length-delimited field")
        value = data[pos : pos + length]
        pos += length
    elif wire_type == 1:
        value = data[pos : pos + 8]
        pos += 8
    elif wire_type == 5:
        value = data[pos : pos + 4]
        pos += 4
    else:
        raise ValueError(f"Unsupported protobuf wire type: {wire_type}")
    return field_number, wire_type, value, pos


_MIGRATION_ALGORITHMS = {0: "SHA1", 1: "SHA1", 2: "SHA256", 3: "SHA512"}
_MIGRATION_DIGITS = {0: 6, 1: 6, 2: 8}
_MIGRATION_TYPE_TOTP = 2


def _parse_migration_entry(data: bytes) -> Account:
    secret_bytes = b""
    name = ""
    issuer = ""
    algorithm = "SHA1"
    digits = 6
    otp_type = _MIGRATION_TYPE_TOTP
    pos = 0
    while pos < len(data):
        field_num, _wt, value, pos = _read_field(data, pos)
        if field_num == 1:
            secret_bytes = value  # bytes
        elif field_num == 2:
            name = value.decode("utf-8", "replace")
        elif field_num == 3:
            issuer = value.decode("utf-8", "replace")
        elif field_num == 4:
            algorithm = _MIGRATION_ALGORITHMS.get(value, "SHA1")
        elif field_num == 5:
            digits = _MIGRATION_DIGITS.get(value, 6)
        elif field_num == 6:
            otp_type = value
    if otp_type != _MIGRATION_TYPE_TOTP:
        raise ValueError("Entry is not TOTP")
    if not secret_bytes:
        raise ValueError("Entry has no secret")
    secret_b32 = base64.b32encode(secret_bytes).decode("ascii").rstrip("=")
    return Account(
        issuer=issuer,
        name=name,
        secret=normalize_secret(secret_b32),
        digits=digits,
        period=30,  # Google Authenticator exports do not encode period; always 30
        algorithm=algorithm,
    )


def parse_migration_uri(uri: str) -> list[Account]:
    """Parse an ``otpauth-migration://offline?data=...`` URI (Google Authenticator
    export/transfer QR). Returns every TOTP account it contains."""
    parsed = urlparse(uri)
    if parsed.scheme != "otpauth-migration":
        raise ValueError("URI must start with otpauth-migration://")
    if parsed.netloc.lower() != "offline":
        raise ValueError("Only otpauth-migration://offline URIs are supported")
    params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
    data_b64 = params.get("data")
    if not data_b64:
        raise ValueError("Migration URI is missing the 'data' parameter")
    try:
        payload = base64.b64decode(data_b64, validate=False)
    except Exception as e:
        raise ValueError(f"Migration 'data' is not valid base64: {e}") from e

    accounts: list[Account] = []
    skipped = 0
    pos = 0
    while pos < len(payload):
        field_num, wt, value, pos = _read_field(payload, pos)
        if field_num == 1 and wt == 2:  # otp_parameters (repeated submessage)
            try:
                accounts.append(_parse_migration_entry(value))
            except ValueError:
                skipped += 1
    if not accounts:
        detail = f" ({skipped} non-TOTP entries skipped)" if skipped else ""
        raise ValueError(f"No TOTP accounts found in migration payload{detail}")
    return accounts


def parse_import_uri(uri: str) -> list[Account]:
    """Accept either a single ``otpauth://totp/`` URI or an
    ``otpauth-migration://offline`` export; always returns a list."""
    uri = uri.strip()
    if uri.startswith("otpauth-migration://"):
        return parse_migration_uri(uri)
    if uri.startswith("otpauth://"):
        return [parse_otpauth_uri(uri)]
    raise ValueError("Expected an otpauth:// or otpauth-migration:// URI")


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
