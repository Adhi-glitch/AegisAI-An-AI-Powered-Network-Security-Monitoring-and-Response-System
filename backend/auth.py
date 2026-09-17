"""
AegisAI JWT Authentication Module
Provides password hashing, token creation, and FastAPI dependency functions.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
import bcrypt
from pydantic import BaseModel

# ── Config ────────────────────────────────────────────────────────────────────
SECRET_KEY = os.getenv("SECRET_KEY", "aegisai-secret-key-change-in-production")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "480"))  # 8h

# ── OAuth2 bearer scheme ──────────────────────────────────────────────────────
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token", auto_error=False)


# ── Pydantic schemas ──────────────────────────────────────────────────────────
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class TokenData(BaseModel):
    username: Optional[str] = None
    role: Optional[str] = None


class UserOut(BaseModel):
    username: str
    role: str
    is_active: bool


# ── Core functions ────────────────────────────────────────────────────────────
def verify_password(plain: str, hashed: str) -> bool:
    """Verify a plain-text password against its bcrypt hash."""
    try:
        return bcrypt.checkpw(plain.encode("utf-8")[:72], hashed.encode("utf-8"))
    except Exception:
        return False


def get_password_hash(password: str) -> str:
    """Hash a plain-text password with bcrypt."""
    return bcrypt.hashpw(password.encode("utf-8")[:72], bcrypt.gensalt()).decode("utf-8")


# ── Default users (env-aware so deployments can override demo credentials) ──

def _load_default_users() -> dict[str, dict]:
    admin_username = os.getenv("AEGIS_ADMIN_USERNAME", "admin")
    admin_password = os.getenv("AEGIS_ADMIN_PASSWORD", "aegisai2024")
    viewer_username = os.getenv("AEGIS_VIEWER_USERNAME", "viewer")
    viewer_password = os.getenv("AEGIS_VIEWER_PASSWORD", "viewer2024")

    return {
        admin_username: {
            "username": admin_username,
            "hashed_password": get_password_hash(admin_password),
            "role": "admin",
            "is_active": True,
        },
        viewer_username: {
            "username": viewer_username,
            "hashed_password": get_password_hash(viewer_password),
            "role": "viewer",
            "is_active": True,
        },
    }


_DEFAULT_USERS: dict[str, dict] = _load_default_users()


def authenticate_user(username: str, password: str) -> Optional[dict]:
    """Authenticate user against the default user store (or DB in future)."""
    user = _DEFAULT_USERS.get(username)
    if not user:
        return None
    if not verify_password(password, user["hashed_password"]):
        return None
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a signed JWT access token."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode["exp"] = expire
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


# ── FastAPI dependencies ──────────────────────────────────────────────────────
def get_optional_user(token: Optional[str] = Depends(oauth2_scheme)) -> Optional[dict]:
    """
    Return the current user if a valid token is supplied, else None.
    Used for endpoints that are accessible without auth but show more data with it.
    """
    if not token:
        return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if not username:
            return None
        return _DEFAULT_USERS.get(username)
    except JWTError:
        return None


def get_current_user(token: Optional[str] = Depends(oauth2_scheme)) -> dict:
    """
    FastAPI dependency: require a valid JWT token.
    Raises HTTP 401 if missing or invalid.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if not token:
        raise credentials_exception
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = _DEFAULT_USERS.get(username)
    if user is None or not user["is_active"]:
        raise credentials_exception
    return user


def get_current_admin(current_user: dict = Depends(get_current_user)) -> dict:
    """
    FastAPI dependency: require admin role.
    Raises HTTP 403 if the authenticated user is not an admin.
    """
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return current_user
