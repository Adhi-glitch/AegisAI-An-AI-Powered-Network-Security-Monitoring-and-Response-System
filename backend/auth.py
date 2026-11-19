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
from dotenv import load_dotenv

load_dotenv()

# ── Config ────────────────────────────────────────────────────────────────────
SECRET_KEY = os.getenv("SECRET_KEY", "")
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


def validate_security_config() -> None:
    """Require explicit, non-placeholder secrets and bootstrap credentials."""
    secret_key = os.getenv("SECRET_KEY", "")
    admin_password = os.getenv("AEGIS_ADMIN_PASSWORD", "")
    viewer_password = os.getenv("AEGIS_VIEWER_PASSWORD", "")
    admin_username = os.getenv("AEGIS_ADMIN_USERNAME", "admin")
    viewer_username = os.getenv("AEGIS_VIEWER_USERNAME", "viewer")

    if len(secret_key.encode("utf-8")) < 32 or "replace-with" in secret_key.lower():
        raise RuntimeError("SECRET_KEY must be configured with at least 32 non-placeholder bytes.")
    if not admin_username or not viewer_username or admin_username == viewer_username:
        raise RuntimeError("Configure distinct non-empty admin and viewer usernames.")
    for role, password in (("admin", admin_password), ("viewer", viewer_password)):
        if (
            len(password.encode("utf-8")) < 12
            or len(password.encode("utf-8")) > 72
            or "replace-with" in password.lower()
        ):
            raise RuntimeError(
                f"AEGIS_{role.upper()}_PASSWORD must be 12-72 bytes and must replace the example value."
            )
    if admin_password == viewer_password:
        raise RuntimeError("Admin and viewer passwords must be different.")


def ensure_bootstrap_users() -> None:
    """Create configured bootstrap accounts once; authentication is DB-backed."""
    validate_security_config()
    from database import models
    from database.init_db import SessionLocal

    accounts = (
        (
            os.getenv("AEGIS_ADMIN_USERNAME", "admin"),
            os.environ["AEGIS_ADMIN_PASSWORD"],
            "admin",
        ),
        (
            os.getenv("AEGIS_VIEWER_USERNAME", "viewer"),
            os.environ["AEGIS_VIEWER_PASSWORD"],
            "viewer",
        ),
    )
    db = SessionLocal()
    try:
        for username, password, role in accounts:
            if db.query(models.User).filter(models.User.username == username).first():
                continue
            db.add(
                models.User(
                    username=username,
                    hashed_password=get_password_hash(password),
                    role=role,
                    is_active=True,
                )
            )
        db.commit()
    finally:
        db.close()


def _find_user(username: str) -> Optional[dict]:
    from database import models
    from database.init_db import SessionLocal

    db = SessionLocal()
    try:
        user = db.query(models.User).filter(models.User.username == username).first()
        if user is None:
            return None
        return {
            "username": user.username,
            "hashed_password": user.hashed_password,
            "role": user.role,
            "is_active": user.is_active,
        }
    finally:
        db.close()


def authenticate_user(username: str, password: str) -> Optional[dict]:
    """Authenticate a configured user against the persistent user table."""
    user = _find_user(username)
    if not user or not user["is_active"]:
        return None
    if not verify_password(password, user["hashed_password"]):
        return None
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a signed JWT access token."""
    if not SECRET_KEY:
        raise RuntimeError("SECRET_KEY is not configured.")
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
    return get_user_from_token(token)


def get_user_from_token(token: Optional[str]) -> Optional[dict]:
    """Resolve a signed token to an active configured user."""
    if not token:
        return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if not username:
            return None
        user = _find_user(username)
        return user if user and user["is_active"] else None
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
    user = get_user_from_token(token)
    if user is None:
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


def get_current_viewer(current_user: dict = Depends(get_current_user)) -> dict:
    """Require viewer role for viewer-exclusive console features."""
    if current_user.get("role") != "viewer":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Viewer access required",
        )
    return current_user
