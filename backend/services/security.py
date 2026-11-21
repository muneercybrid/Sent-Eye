"""Password hashing, opaque sessions, cookies and CSRF protection."""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time
from typing import Any, Dict

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from fastapi import HTTPException, Request, Response

from backend.services.auth_store import auth_store

PASSWORD_HASHER = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=2,
    hash_len=32,
    salt_len=16,
)

SESSION_COOKIE = "sent_eye_session"
CSRF_COOKIE = "sent_eye_csrf"


def _env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def session_ttl() -> int:
    try:
        hours = int(os.environ.get("SENT_EYE_SESSION_HOURS", "12"))
    except ValueError:
        hours = 12
    return max(1, min(hours, 168)) * 3600


def cookie_secure() -> bool:
    # Public deployments should retain the secure default.
    return _env_bool("SENT_EYE_COOKIE_SECURE", True)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def hash_password(password: str) -> str:
    return PASSWORD_HASHER.hash(password)


def verify_password(encoded_hash: str, password: str) -> bool:
    try:
        return PASSWORD_HASHER.verify(encoded_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def password_needs_rehash(encoded_hash: str) -> bool:
    try:
        return PASSWORD_HASHER.check_needs_rehash(encoded_hash)
    except (VerificationError, InvalidHashError):
        return False


def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def set_csrf_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=CSRF_COOKIE,
        value=token,
        max_age=session_ttl(),
        path="/",
        secure=cookie_secure(),
        httponly=False,
        samesite="lax",
    )


def set_session_cookies(
    response: Response,
    session_token: str,
    csrf_token: str,
) -> None:
    response.set_cookie(
        key=SESSION_COOKIE,
        value=session_token,
        max_age=session_ttl(),
        path="/",
        secure=cookie_secure(),
        httponly=True,
        samesite="lax",
    )
    set_csrf_cookie(response, csrf_token)


def clear_session_cookies(response: Response) -> None:
    response.delete_cookie(
        SESSION_COOKIE,
        path="/",
        secure=cookie_secure(),
        httponly=True,
        samesite="lax",
    )
    response.delete_cookie(
        CSRF_COOKIE,
        path="/",
        secure=cookie_secure(),
        httponly=False,
        samesite="lax",
    )


def require_csrf(request: Request, session: Dict[str, Any] | None = None) -> str:
    cookie_token = request.cookies.get(CSRF_COOKIE, "")
    header_token = request.headers.get("X-CSRF-Token", "")

    if (
        not cookie_token
        or not header_token
        or not hmac.compare_digest(cookie_token, header_token)
    ):
        raise HTTPException(403, "CSRF validation failed.")

    if session is not None:
        if not hmac.compare_digest(hash_token(cookie_token), session["csrf_hash"]):
            raise HTTPException(403, "CSRF token is no longer valid.")

    return cookie_token


def get_current_user(request: Request) -> Dict[str, Any]:
    raw_token = request.cookies.get(SESSION_COOKIE, "")
    if not raw_token:
        raise HTTPException(401, "Authentication required.")

    session = auth_store.get_session(hash_token(raw_token))
    if session is None:
        raise HTTPException(401, "Session expired or invalid.")

    return session


def require_admin(user: Dict[str, Any]) -> None:
    if user.get("role") != "admin":
        raise HTTPException(403, "Administrator access required.")


def create_session_for_user(user_id: str) -> tuple[str, str]:
    session_token = secrets.token_urlsafe(48)
    csrf_token = new_csrf_token()
    expires_at = time.time() + session_ttl()

    auth_store.create_session(
        user_id=user_id,
        token_hash=hash_token(session_token),
        csrf_hash=hash_token(csrf_token),
        expires_at=expires_at,
    )
    return session_token, csrf_token
