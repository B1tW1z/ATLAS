"""
ATLAS Authentication Routes

Handles user login, logout, signup, and session management.
Now uses SQLite database for persistent user storage.
"""

import hashlib
import html
import logging
import re
import secrets
import uuid
from urllib.parse import urlencode
from datetime import datetime, timedelta
from typing import Optional, Any

import httpx
from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator
from slowapi import Limiter
from slowapi.util import get_remote_address

from atlas.persistence.database import Database
from atlas.persistence.models import User
from atlas.utils.config import get_config

router = APIRouter(prefix="/auth", tags=["Authentication"])
logger = logging.getLogger("atlas.auth")
limiter = Limiter(key_func=get_remote_address)

# Simple in-memory session store (use Redis in production)
_sessions = {}
_oauth_states = {}

# Database instance (initialized lazily)
_db = None

def get_db() -> Database:
    """Get database instance"""
    global _db
    if _db is None:
        _db = Database()
    return _db


ROLE_OPTIONS = {"admin", "pentester", "analyst", "user"}
TAG_RE = re.compile(r"<[^>]+>")
MULTISPACE_RE = re.compile(r"\s+")


def sanitize_text(value: str) -> str:
    """Strip HTML tags, normalize whitespace, then escape special chars."""
    without_tags = TAG_RE.sub("", value)
    normalized = MULTISPACE_RE.sub(" ", without_tags).strip()
    return html.escape(normalized, quote=True)


def create_csrf_token() -> str:
    """Create CSRF token for double-submit protection."""
    return secrets.token_urlsafe(32)


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    return forwarded.split(",")[0].strip() if forwarded else (request.client.host if request.client else "unknown")


def _record_auth_event(event_type: str, message: str) -> None:
    """Persist auth events to activity log and structured logger."""
    logger.info("auth_event type=%s message=%s", event_type, message)
    try:
        get_db().add_scan_event(None, event_type, message)
    except Exception as exc:
        logger.warning("Unable to persist auth event: %s", exc)


def _set_auth_cookies(response: Response, session_token: str, remember: bool = False) -> str:
    csrf_token = create_csrf_token()
    max_age = 30 * 24 * 60 * 60 if remember else 24 * 60 * 60
    response.set_cookie(
        key="atlas_session",
        value=session_token,
        httponly=True,
        max_age=max_age,
        samesite="lax",
        secure=True
    )
    response.set_cookie(
        key=get_config().csrf_cookie_name,
        value=csrf_token,
        httponly=False,
        max_age=max_age,
        samesite="lax",
        secure=True
    )
    return csrf_token


def _upsert_oauth_user(db: Database, email: str, name: str, preferred_username: str, role: str = "user") -> User:
    existing = db.get_user_by_email(email.lower())
    if existing:
        return existing

    raw_username = re.sub(r"[^a-z0-9_]", "_", preferred_username.lower())[:50].strip("_")
    base_username = raw_username or f"user_{uuid.uuid4().hex[:8]}"
    username = base_username
    suffix = 1
    while db.username_exists(username):
        suffix += 1
        username = f"{base_username[:45]}_{suffix}"

    user = User(
        id=str(uuid.uuid4())[:8],
        username=username,
        email=email.lower(),
        name=sanitize_text(name)[:80] or "ATLAS User",
        password_hash=hash_password(secrets.token_urlsafe(48)),
        role=role,
        created_at=datetime.utcnow()
    )
    db.create_user(user)
    return user


class LoginRequest(BaseModel):
    """Login request body"""
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    username: str = Field(..., min_length=3, max_length=100)
    password: str = Field(..., min_length=8, max_length=256)
    remember: bool = False

    @field_validator("username")
    @classmethod
    def validate_username(cls, value: str) -> str:
        lowered = value.lower()
        if "@" in lowered:
            if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", lowered):
                raise ValueError("Invalid email format")
        elif not re.fullmatch(r"[a-z0-9_]{3,50}", lowered):
            raise ValueError("Username must be 3-50 chars: letters, numbers, underscore")
        return lowered


class LoginResponse(BaseModel):
    """Login response"""
    success: bool
    message: str
    token: Optional[str] = None
    csrf_token: Optional[str] = None
    user: Optional[dict] = None


class SignupRequest(BaseModel):
    """Signup request body"""
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    name: str = Field(..., min_length=2, max_length=80)
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=12, max_length=256)
    role: str = Field(default="pentester")

    @field_validator("name")
    @classmethod
    def sanitize_name(cls, value: str) -> str:
        cleaned = sanitize_text(value)
        if len(cleaned) < 2:
            raise ValueError("Name is too short")
        return cleaned

    @field_validator("username")
    @classmethod
    def validate_username(cls, value: str) -> str:
        lowered = value.lower()
        if not re.fullmatch(r"[a-z0-9_]{3,50}", lowered):
            raise ValueError("Username can only contain letters, numbers, and underscores")
        return lowered

    @field_validator("role")
    @classmethod
    def validate_role(cls, value: str) -> str:
        role = value.lower().strip()
        if role not in ROLE_OPTIONS:
            raise ValueError("Invalid role")
        return role


class UserInfo(BaseModel):
    """Current user info"""
    username: str
    name: str
    email: Optional[str] = None
    role: str
    created_at: Optional[str] = None


class ProfileUpdateRequest(BaseModel):
    """Validated profile update payload"""
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    name: Optional[str] = Field(default=None, min_length=2, max_length=80)
    email: Optional[EmailStr] = None

    @field_validator("name")
    @classmethod
    def sanitize_name(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        return sanitize_text(value)


class PasswordChangeRequest(BaseModel):
    """Validated password change payload"""
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    current_password: str = Field(..., min_length=8, max_length=256)
    new_password: str = Field(..., min_length=12, max_length=256)


def hash_password(password: str) -> str:
    """Hash password with SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()


def create_session(username: str, remember: bool = False) -> str:
    """Create a new session token"""
    token = secrets.token_urlsafe(32)
    expires = datetime.utcnow() + timedelta(days=30 if remember else 1)
    
    _sessions[token] = {
        "username": username,
        "created_at": datetime.utcnow(),
        "expires_at": expires
    }
    
    return token


def get_session(token: str) -> Optional[dict]:
    """Get session by token"""
    session = _sessions.get(token)
    
    if session:
        if datetime.utcnow() < session["expires_at"]:
            return session
        else:
            # Expired session
            del _sessions[token]
    
    return None


def get_current_user(request: Request) -> Optional[str]:
    """Extract current user from request"""
    # Check Authorization header
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        session = get_session(token)
        if session:
            return session["username"]
    
    # Check cookie
    token = request.cookies.get("atlas_session")
    if token:
        session = get_session(token)
        if session:
            return session["username"]
    
    return None


@router.post("/login", response_model=LoginResponse)
@limiter.limit("100/15minutes")
async def login(request: Request, credentials: LoginRequest, response: Response):
    """
    Authenticate user and create session.
    
    Users are stored in SQLite database for persistence.
    """
    db = get_db()
    username = credentials.username
    password_hash = hash_password(credentials.password)
    
    # Get user from database
    user = db.get_user_by_username(username)
    
    if not user or user.password_hash != password_hash:
        logger.warning("Failed login attempt for username=%s", username)
        _record_auth_event("auth_login_failed", f"username={username} ip={_client_ip(request)}")
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    # Create session
    token = create_session(username, credentials.remember)
    
    csrf_token = _set_auth_cookies(response, token, remember=credentials.remember)
    _record_auth_event("auth_login_success", f"username={username} ip={_client_ip(request)}")
    
    return LoginResponse(
        success=True,
        message="Login successful",
        token=token,
        csrf_token=csrf_token,
        user={
            "username": user.username,
            "name": user.name,
            "role": user.role
        }
    )


@router.post("/logout")
async def logout(request: Request, response: Response):
    """Logout and invalidate session"""
    # Get token from header or cookie
    token = None
    
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
    else:
        token = request.cookies.get("atlas_session")
    
    # Remove session
    if token and token in _sessions:
        del _sessions[token]
    
    # Clear cookie
    response.delete_cookie("atlas_session")
    response.delete_cookie(get_config().csrf_cookie_name)
    _record_auth_event("auth_logout", f"ip={_client_ip(request)}")
    
    return {"success": True, "message": "Logged out successfully"}


@router.get("/verify")
async def verify_session(request: Request):
    """Verify current session is valid"""
    db = get_db()
    username = get_current_user(request)
    
    if not username:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    user = db.get_user_by_username(username)
    
    return {
        "valid": True,
        "user": {
            "username": username,
            "name": user.name if user else username,
            "email": user.email if user else None,
            "role": user.role if user else "user",
            "created_at": user.created_at.isoformat() if user else None
        }
    }


@router.get("/me", response_model=UserInfo)
async def get_current_user_info(request: Request):
    """Get current logged-in user info"""
    db = get_db()
    username = get_current_user(request)
    
    if not username:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    user = db.get_user_by_username(username)
    
    return UserInfo(
        username=username,
        name=user.name if user else username,
        email=user.email if user else None,
        role=user.role if user else "user",
        created_at=user.created_at.isoformat() if user else None
    )


@router.post("/signup", response_model=LoginResponse)
@limiter.limit("100/15minutes")
async def signup(request: Request, signup_data: SignupRequest, response: Response):
    """
    Create a new user account.
    
    Registers the user in SQLite database and automatically logs them in.
    """
    db = get_db()
    username = signup_data.username
    email = str(signup_data.email).lower().strip()
    name = signup_data.name
    
    # Check if username already exists
    if db.username_exists(username):
        raise HTTPException(
            status_code=400,
            detail="Username already taken"
        )
    
    # Check if email already exists
    if db.email_exists(email):
        raise HTTPException(
            status_code=400,
            detail="Email already registered"
        )
    
    role = signup_data.role
    
    # Create new user in database
    new_user = User(
        id=str(uuid.uuid4())[:8],
        username=username,
        email=email,
        name=name,
        password_hash=hash_password(signup_data.password),
        role=role,
        created_at=datetime.utcnow()
    )
    
    db.create_user(new_user)
    
    # Automatically log in the new user
    token = create_session(username, remember=False)
    
    csrf_token = _set_auth_cookies(response, token, remember=False)
    _record_auth_event("auth_signup_success", f"username={username} ip={_client_ip(request)}")
    
    return LoginResponse(
        success=True,
        message="Account created successfully",
        token=token,
        csrf_token=csrf_token,
        user={
            "username": username,
            "name": name,
            "role": role
        }
    )


def _oauth_provider_config(provider: str) -> dict[str, Any]:
    cfg = get_config()
    providers = {
        "google": {
            "client_id": cfg.google_client_id,
            "client_secret": cfg.google_client_secret,
            "redirect_uri": cfg.google_redirect_uri or f"{cfg.app_base_url}/api/auth/oauth/google/callback",
            "authorize_url": "https://accounts.google.com/o/oauth2/v2/auth",
            "token_url": "https://oauth2.googleapis.com/token",
            "userinfo_url": "https://openidconnect.googleapis.com/v1/userinfo",
            "scope": "openid email profile",
        },
        "microsoft": {
            "client_id": cfg.microsoft_client_id,
            "client_secret": cfg.microsoft_client_secret,
            "redirect_uri": cfg.microsoft_redirect_uri or f"{cfg.app_base_url}/api/auth/oauth/microsoft/callback",
            "authorize_url": f"https://login.microsoftonline.com/{cfg.microsoft_tenant}/oauth2/v2.0/authorize",
            "token_url": f"https://login.microsoftonline.com/{cfg.microsoft_tenant}/oauth2/v2.0/token",
            "userinfo_url": "https://graph.microsoft.com/v1.0/me",
            "scope": "openid profile email User.Read",
        },
        "github": {
            "client_id": cfg.github_client_id,
            "client_secret": cfg.github_client_secret,
            "redirect_uri": cfg.github_redirect_uri or f"{cfg.app_base_url}/api/auth/oauth/github/callback",
            "authorize_url": "https://github.com/login/oauth/authorize",
            "token_url": "https://github.com/login/oauth/access_token",
            "userinfo_url": "https://api.github.com/user",
            "scope": "read:user user:email",
        },
    }
    provider_cfg = providers.get(provider)
    if not provider_cfg:
        raise HTTPException(status_code=404, detail="Unsupported OAuth provider")
    if not provider_cfg["client_id"] or not provider_cfg["client_secret"]:
        raise HTTPException(status_code=503, detail=f"{provider.title()} OAuth is not configured")
    return provider_cfg


@router.get("/oauth/{provider}/start")
@limiter.limit("100/15minutes")
async def oauth_start(provider: str, request: Request):
    cfg = _oauth_provider_config(provider)
    state = secrets.token_urlsafe(24)
    _oauth_states[state] = {"provider": provider, "created_at": datetime.utcnow()}
    params = {
        "client_id": cfg["client_id"],
        "redirect_uri": cfg["redirect_uri"],
        "response_type": "code",
        "scope": cfg["scope"],
        "state": state,
    }
    if provider == "google":
        params["access_type"] = "online"
        params["prompt"] = "select_account"
    _record_auth_event("auth_oauth_start", f"provider={provider} ip={_client_ip(request)}")
    return RedirectResponse(f"{cfg['authorize_url']}?{urlencode(params)}", status_code=302)


@router.get("/oauth/{provider}/callback")
@limiter.limit("100/15minutes")
async def oauth_callback(provider: str, request: Request, code: str, state: str):
    state_record = _oauth_states.pop(state, None)
    if not state_record or state_record.get("provider") != provider:
        raise HTTPException(status_code=400, detail="Invalid OAuth state")
    if (datetime.utcnow() - state_record["created_at"]).seconds > 300:
        raise HTTPException(status_code=400, detail="Expired OAuth state")

    cfg = _oauth_provider_config(provider)
    token_payload = {
        "client_id": cfg["client_id"],
        "client_secret": cfg["client_secret"],
        "code": code,
        "redirect_uri": cfg["redirect_uri"],
        "grant_type": "authorization_code",
    }
    async with httpx.AsyncClient(timeout=15.0) as client:
        token_resp = await client.post(cfg["token_url"], data=token_payload, headers={"Accept": "application/json"})
        if token_resp.status_code >= 400:
            logger.error("OAuth token exchange failed provider=%s status=%s", provider, token_resp.status_code)
            raise HTTPException(status_code=401, detail="OAuth token exchange failed")
        token_data = token_resp.json()
        access_token = token_data.get("access_token")
        if not access_token:
            raise HTTPException(status_code=401, detail="OAuth token missing")

        user_headers = {"Authorization": f"Bearer {access_token}", "Accept": "application/json"}
        if provider == "github":
            user_headers["User-Agent"] = "ATLAS"
        user_resp = await client.get(cfg["userinfo_url"], headers=user_headers)
        if user_resp.status_code >= 400:
            raise HTTPException(status_code=401, detail="OAuth userinfo lookup failed")
        user_data = user_resp.json()

        if provider == "github" and not user_data.get("email"):
            email_resp = await client.get("https://api.github.com/user/emails", headers=user_headers)
            if email_resp.status_code == 200:
                emails = email_resp.json()
                primary = next((entry["email"] for entry in emails if entry.get("primary")), None)
                user_data["email"] = primary or (emails[0]["email"] if emails else None)

    email = user_data.get("email")
    if not email:
        raise HTTPException(status_code=400, detail="OAuth provider did not return an email")
    name = user_data.get("name") or user_data.get("displayName") or user_data.get("login") or email.split("@")[0]
    preferred_username = user_data.get("preferred_username") or user_data.get("login") or email.split("@")[0]

    user = _upsert_oauth_user(get_db(), email=email, name=name, preferred_username=preferred_username, role="user")
    token = create_session(user.username, remember=False)
    response = RedirectResponse(url="/dashboard", status_code=302)
    _set_auth_cookies(response, token, remember=False)
    _record_auth_event("auth_oauth_success", f"provider={provider} username={user.username} ip={_client_ip(request)}")
    return response


@router.get("/csrf")
async def get_csrf(request: Request, response: Response):
    token = request.cookies.get(get_config().csrf_cookie_name) or create_csrf_token()
    response.set_cookie(
        key=get_config().csrf_cookie_name,
        value=token,
        httponly=False,
        max_age=24 * 60 * 60,
        samesite="lax",
        secure=True,
    )
    return {"csrf_token": token}


@router.put("/profile")
@limiter.limit("100/15minutes")
async def update_profile(request: Request, profile_data: ProfileUpdateRequest):
    """
    Update current user's profile (name, email).
    
    Requires valid session. Only updates provided fields.
    """
    db = get_db()
    username = get_current_user(request)
    
    if not username:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    user = db.get_user_by_username(username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    updates = {}

    if profile_data.name:
        updates["name"] = profile_data.name
    if profile_data.email:
        new_email = str(profile_data.email).lower().strip()
        # Check if email is already taken by another user
        existing = db.get_user_by_email(new_email)
        if existing and existing.id != user.id:
            raise HTTPException(status_code=400, detail="Email already in use")
        updates["email"] = new_email
    
    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")
    
    db.update_user(user.id, **updates)
    _record_auth_event("auth_profile_updated", f"username={username} fields={','.join(updates.keys())} ip={_client_ip(request)}")
    
    return {
        "success": True,
        "message": "Profile updated",
        "user": {
            "username": username,
            "name": updates.get("name", user.name),
            "email": updates.get("email", user.email),
            "role": user.role
        }
    }


@router.put("/password")
@limiter.limit("100/15minutes")
async def change_password(request: Request, payload: PasswordChangeRequest):
    """
    Change current user's password.
    
    Requires valid session and current password verification.
    """
    db = get_db()
    username = get_current_user(request)
    
    if not username:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    user = db.get_user_by_username(username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Verify current password
    if hash_password(payload.current_password) != user.password_hash:
        raise HTTPException(status_code=400, detail="Current password is incorrect")

    # Update password
    db.update_user_password(user.id, hash_password(payload.new_password))
    _record_auth_event("auth_password_changed", f"username={username} ip={_client_ip(request)}")
    
    return {"success": True, "message": "Password changed successfully"}
