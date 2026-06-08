from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

from app.config import SETTINGS


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def hash_token(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def generate_session_token() -> str:
    return secrets.token_urlsafe(48)


def generate_session_uid() -> str:
    return secrets.token_hex(16)


def build_password_hash(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        _password_material(password),
        salt,
        SETTINGS.auth_password_iterations,
    )
    return "$".join(
        [
            "pbkdf2_sha256",
            str(SETTINGS.auth_password_iterations),
            base64.b64encode(salt).decode("ascii"),
            base64.b64encode(digest).decode("ascii"),
        ]
    )


def verify_password(password: str, password_hash: str | None) -> bool:
    if not password_hash:
        verify_dummy_password(password)
        return False

    try:
        algorithm, iterations_raw, salt_b64, digest_b64 = password_hash.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        iterations = int(iterations_raw)
        salt = base64.b64decode(salt_b64.encode("ascii"))
        expected = base64.b64decode(digest_b64.encode("ascii"))
    except Exception:
        return False

    actual = hashlib.pbkdf2_hmac("sha256", _password_material(password), salt, iterations)
    return hmac.compare_digest(actual, expected)


def verify_dummy_password(password: str) -> None:
    hashlib.pbkdf2_hmac(
        "sha256",
        _password_material(password),
        b"ai-proxy-dummy-salt",
        SETTINGS.auth_password_iterations,
    )


def session_expiry() -> datetime:
    return utcnow() + timedelta(minutes=SETTINGS.auth_access_ttl_minutes)


def _password_material(password: str) -> bytes:
    return f"{SETTINGS.auth_password_pepper}{password}".encode("utf-8")
