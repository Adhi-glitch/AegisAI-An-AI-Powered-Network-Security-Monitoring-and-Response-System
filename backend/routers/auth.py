"""
Auth router: /api/v1/auth/token and /api/v1/auth/me
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm

from backend.auth import (
    Token,
    UserOut,
    authenticate_user,
    create_access_token,
    get_current_user,
)

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


@router.post("/token", response_model=Token, summary="Obtain JWT access token")
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Standard OAuth2 password flow.
    Submit username and password as form fields to receive a Bearer token.
    """
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = create_access_token(
        data={"sub": user["username"], "role": user["role"]}
    )
    return Token(access_token=token)


@router.get("/me", response_model=UserOut, summary="Current user info")
def read_current_user(current_user: dict = Depends(get_current_user)):
    """Return the currently authenticated user's profile."""
    return UserOut(
        username=current_user["username"],
        role=current_user["role"],
        is_active=current_user["is_active"],
    )
