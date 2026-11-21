"""Registration, authentication and administrator endpoints."""
from __future__ import annotations

import hashlib
import re
import secrets
import sqlite3
import time
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel

from backend.core.runner import MODULE_REGISTRY
from backend.services.auth_store import auth_store
from backend.services.security import (
    CSRF_COOKIE,
    create_session_for_user,
    hash_password,
    hash_token,
    new_csrf_token,
    password_needs_rehash,
    require_admin,
    require_csrf,
    set_csrf_cookie,
    set_session_cookies,
    clear_session_cookies,
    verify_password,
    get_current_user,
)

router = APIRouter()

SENSITIVE_MODULES = {
    "face_analysis",
    "geolocation",
    "reverse_image_search",
}

MODULE_NAMES = {module.name for module in MODULE_REGISTRY}

EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class RegisterPayload(BaseModel):
    email: str
    full_name: str
    password: str


class LoginPayload(BaseModel):
    email: str
    password: str


class UserStatusPayload(BaseModel):
    status: str


class UserRolePayload(BaseModel):
    role: str


class ModulePermissionPayload(BaseModel):
    enabled: bool
    daily_limit: Optional[int] = None
    monthly_limit: Optional[int] = None


def _public_user(user: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "user_id": user["user_id"],
        "email": user["email"],
        "full_name": user["full_name"],
        "role": user["role"],
        "status": user["status"],
    }


def _request_ip_key(request: Request) -> str:
    # Trust Cloudflare's client address header only when a Cloudflare-Ray
    # header is also present. Otherwise use the direct peer address.
    if request.headers.get("CF-Ray"):
        ip = request.headers.get("CF-Connecting-IP", "")
    else:
        ip = request.client.host if request.client else ""
    return hashlib.sha256(ip.encode("utf-8")).hexdigest()


def _email_key(email: str) -> str:
    return hashlib.sha256(email.strip().lower().encode("utf-8")).hexdigest()


def _check_csrf(request: Request) -> None:
    require_csrf(request)


def _check_authenticated_csrf(request: Request, user: Dict[str, Any]) -> None:
    require_csrf(request, user)


def _validated_registration(payload: RegisterPayload) -> tuple[str, str, str]:
    email = payload.email.strip().lower()
    full_name = " ".join(payload.full_name.split())
    password = payload.password

    if len(email) > 254 or not EMAIL_PATTERN.fullmatch(email):
        raise HTTPException(400, "Enter a valid email address.")
    if len(full_name) < 2 or len(full_name) > 100:
        raise HTTPException(400, "Full name must be between 2 and 100 characters.")
    if len(password) < 12:
        raise HTTPException(400, "Password must be at least 12 characters.")
    if len(password) > 256:
        raise HTTPException(400, "Password is too long.")

    return email, full_name, password


@router.get("/api/auth/csrf")
async def issue_csrf(request: Request, response: Response):
    token = request.cookies.get(CSRF_COOKIE, "")
    if len(token) < 32:
        token = new_csrf_token()
        set_csrf_cookie(response, token)
    response.headers["Cache-Control"] = "no-store"
    return {"csrf_token": token}


@router.post("/api/auth/register", status_code=201)
async def register(payload: RegisterPayload, request: Request):
    _check_csrf(request)
    email, full_name, password = _validated_registration(payload)

    password_hash = hash_password(password)
    try:
        user = auth_store.create_user(
            email=email,
            full_name=full_name,
            password_hash=password_hash,
            role="user",
            status="pending",
        )
        auth_store.record_audit_event(
            actor_user_id=None,
            subject_user_id=user["user_id"],
            event_type="user.registered",
            details={"registration_status": "pending"},
        )
    except sqlite3.IntegrityError:
        # Keep duplicate-address responses indistinguishable from new
        # registrations to reduce account enumeration.
        pass

    return {
        "status": "pending_review",
        "message": (
            "Registration received. An administrator must approve your "
            "account before you can sign in."
        ),
    }


@router.post("/api/auth/login")
async def login(payload: LoginPayload, request: Request, response: Response):
    _check_csrf(request)

    email = payload.email.strip().lower()
    if len(email) > 254 or len(payload.password) > 256:
        raise HTTPException(401, "Invalid email or password.")

    email_key = _email_key(email)
    ip_key = _request_ip_key(request)

    if auth_store.login_is_rate_limited(email_key, ip_key):
        raise HTTPException(
            429,
            "Too many unsuccessful sign-in attempts. Try again in 15 minutes.",
        )

    user = auth_store.get_user_by_email(email)
    password_ok = (
        verify_password(user["password_hash"], payload.password)
        if user
        else False
    )

    if not user or not password_ok:
        auth_store.record_login_attempt(email_key, ip_key, False, user_id=user['user_id'] if user else None)
        raise HTTPException(401, "Invalid email or password.")

    if user["status"] != "approved":
        auth_store.record_login_attempt(
            email_key, ip_key, False, user_id=user["user_id"]
        )
        if user["status"] == "pending":
            raise HTTPException(
                403,
                "Your account is awaiting administrator approval.",
            )
        raise HTTPException(
            403,
            "This account is not currently permitted to sign in.",
        )

    auth_store.record_login_attempt(email_key, ip_key, True, user_id=user['user_id'])
    auth_store.update_last_login(user["user_id"])

    if password_needs_rehash(user["password_hash"]):
        from backend.services.security import hash_password
        # Update the hash directly; the plaintext password is never stored.
        with auth_store._connection() as db:
            db.execute(
                "UPDATE users SET password_hash = ? WHERE user_id = ?",
                (hash_password(payload.password), user["user_id"]),
            )

    session_token, csrf_token = create_session_for_user(user["user_id"])
    set_session_cookies(response, session_token, csrf_token)
    response.headers["Cache-Control"] = "no-store"

    return {
        "status": "authenticated",
        "user": _public_user(user),
        "csrf_token": csrf_token,
    }


@router.get("/api/auth/me")
async def who_am_i(
    request: Request,
    user: Dict[str, Any] = Depends(get_current_user),
):
    response = {
        "user": {
            "user_id": user["user_id"],
            "email": user["email"],
            "full_name": user["full_name"],
            "role": user["role"],
            "status": user["status"],
        },
        "csrf_token": request.cookies.get(CSRF_COOKIE, ""),
    }
    return response


@router.post("/api/auth/logout")
async def logout(
    request: Request,
    response: Response,
    user: Dict[str, Any] = Depends(get_current_user),
):
    _check_authenticated_csrf(request, user)
    from backend.services.auth_store import auth_store

    auth_store.revoke_session(user["token_hash"])
    clear_session_cookies(response)
    return {"status": "logged_out"}


@router.get("/api/admin/users")
async def admin_list_users(
    user: Dict[str, Any] = Depends(get_current_user),
):
    require_admin(user)
    records = auth_store.list_users()
    permissions = {
        record["user_id"]: auth_store.get_module_permissions(record["user_id"])
        for record in records
    }
    return [
        {**record, "module_permissions": permissions[record["user_id"]]}
        for record in records
    ]


@router.post("/api/admin/users/{user_id}/status")
async def admin_update_user_status(
    user_id: str,
    payload: UserStatusPayload,
    request: Request,
    user: Dict[str, Any] = Depends(get_current_user),
):
    require_admin(user)
    _check_authenticated_csrf(request, user)

    if user_id == user["user_id"] and payload.status != "approved":
        raise HTTPException(400, "You cannot suspend or reject your own account.")

    try:
        updated = auth_store.update_user_status(
            user_id,
            payload.status,
            user["user_id"],
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc))

    return updated


@router.put("/api/admin/users/{user_id}/role")
async def admin_update_user_role(
    user_id: str,
    payload: UserRolePayload,
    request: Request,
    user: Dict[str, Any] = Depends(get_current_user),
):
    require_admin(user)
    _check_authenticated_csrf(request, user)

    if user_id == user["user_id"]:
        raise HTTPException(400, "You cannot change your own administrator role.")

    try:
        updated = auth_store.update_user_role(
            user_id,
            payload.role,
            user["user_id"],
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc))

    return updated


@router.put("/api/admin/users/{user_id}/modules/{module_name}")
async def admin_set_module_permission(
    user_id: str,
    module_name: str,
    payload: ModulePermissionPayload,
    request: Request,
    user: Dict[str, Any] = Depends(get_current_user),
):
    require_admin(user)
    _check_authenticated_csrf(request, user)

    if module_name not in MODULE_NAMES:
        raise HTTPException(404, "Unknown module.")

    try:
        auth_store.set_module_permission(
            user_id=user_id,
            module_name=module_name,
            enabled=payload.enabled,
            actor_user_id=user["user_id"],
            daily_limit=payload.daily_limit,
            monthly_limit=payload.monthly_limit,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc))

    return {
        "user_id": user_id,
        "module_name": module_name,
        "sensitive": module_name in SENSITIVE_MODULES,
        "enabled": payload.enabled,
        "daily_limit": payload.daily_limit,
        "monthly_limit": payload.monthly_limit,
    }


@router.get("/api/admin/overview")
async def admin_overview(
    user: Dict[str, Any] = Depends(get_current_user),
):
    require_admin(user)
    return auth_store.get_admin_overview()


@router.get("/api/admin/investigations")
async def admin_list_investigations(
    user: Dict[str, Any] = Depends(get_current_user),
    limit: int = 100,
):
    require_admin(user)
    return auth_store.list_investigations(limit)


@router.get("/api/admin/audit")
async def admin_list_audit(
    user: Dict[str, Any] = Depends(get_current_user),
    limit: int = 100,
):
    require_admin(user)
    return auth_store.list_audit_events(limit)
