"""Decode QR codes from image bytes or a file path.

Returns the raw payload (typically an ``otpauth://totp/...`` URI); callers are
expected to hand the string off to :func:`totp.parse_otpauth_uri`.
"""

from __future__ import annotations

from pathlib import Path

import cv2
import numpy as np


class QRDecodeError(ValueError):
    pass


_detector = cv2.QRCodeDetector()


def _decode_ndarray(img: np.ndarray) -> str:
    data, _points, _straight = _detector.detectAndDecode(img)
    if not data:
        raise QRDecodeError("No QR code detected in the image.")
    return data


def decode_qr_from_bytes(data: bytes) -> str:
    if not data:
        raise QRDecodeError("Empty image data.")
    buf = np.frombuffer(data, dtype=np.uint8)
    img = cv2.imdecode(buf, cv2.IMREAD_COLOR)
    if img is None:
        raise QRDecodeError("Could not read image data (unsupported format?).")
    return _decode_ndarray(img)


def decode_qr_from_file(path: Path | str) -> str:
    p = Path(path)
    if not p.is_file():
        raise QRDecodeError(f"File not found: {p}")
    # imread handles Unicode paths poorly on Windows; read bytes and decode.
    return decode_qr_from_bytes(p.read_bytes())
