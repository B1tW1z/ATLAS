"""
ATLAS Authentication Routes

Handles user login, logout, and session management.
"""

import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, HTTPException, Depends, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel

router = APIRouter(prefix="/auth", tags=["Authentication"])

# Simple in-memory session store (use Redis in production)
_sessions = {}

# Default users (in production, use database)
DEFAULT_USERS = {
    "admin": {
        "password_hash": hashlib.sha256("admin123".encode()).hexdigest(),
        "role": "admin",
        "name": "Administrator"
    },
    "analyst": {
        "password_hash": hashlib.sha256("analyst123".encode()).hexdigest(),
        "role": "analyst", 
        "name": "Security Analyst"
    },
    "pentester": {
        "password_hash": hashlib.sha256("pentester123".encode()).hexdigest(),
        "role": "pentester", 
        "name": "Penetration Tester"
    }
}


class LoginRequest(BaseModel):
    """Login request body"""
    username: str
    password: str
    remember: bool = False


class LoginResponse(BaseModel):
    """Login response"""
    success: bool
    message: str
    token: Optional[str] = None
    user: Optional[dict] = None


class SignupRequest(BaseModel):
    """Signup request body"""
    name: str
    username: str
    email: str
    password: str
    role: str = "pentester"  # Default role, can be 'admin' or 'pentester'


class UserInfo(BaseModel):
    """Current user info"""
    username: str
    name: str
    role: str


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
async def login(credentials: LoginRequest, response: Response):
    """
    Authenticate user and create session.
    
    Default credentials:
    - admin / admin123
    - analyst / analyst123
    """
    username = credentials.username.lower().strip()
    password_hash = hash_password(credentials.password)
    
    # Check credentials
    user = DEFAULT_USERS.get(username)
    
    if not user or user["password_hash"] != password_hash:
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password"
        )
    
    # Create session
    token = create_session(username, credentials.remember)
    
    # Set cookie
    response.set_cookie(
        key="atlas_session",
        value=token,
        httponly=True,
        max_age=30 * 24 * 60 * 60 if credentials.remember else 24 * 60 * 60,
        samesite="lax"
    )
    
    return LoginResponse(
        success=True,
        message="Login successful",
        token=token,
        user={
            "username": username,
            "name": user["name"],
            "role": user["role"]
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
    
    return {"success": True, "message": "Logged out successfully"}


@router.get("/verify")
async def verify_session(request: Request):
    """Verify current session is valid"""
    username = get_current_user(request)
    
    if not username:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    user = DEFAULT_USERS.get(username)
    
    return {
        "valid": True,
        "user": {
            "username": username,
            "name": user["name"] if user else username,
            "role": user["role"] if user else "user"
        }
    }


@router.get("/me", response_model=UserInfo)
async def get_current_user_info(request: Request):
    """Get current logged-in user info"""
    username = get_current_user(request)
    
    if not username:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    user = DEFAULT_USERS.get(username, {})
    
    return UserInfo(
        username=username,
        name=user.get("name", username),
        role=user.get("role", "user")
    )


@router.post("/signup", response_model=LoginResponse)
async def signup(signup_data: SignupRequest, response: Response):
    """
    Create a new user account.
    
    Registers the user and automatically logs them in.
    """
    username = signup_data.username.lower().strip()
    email = signup_data.email.lower().strip()
    name = signup_data.name.strip()
    
    # Validate username format
    if not username.replace('_', '').isalnum():
        raise HTTPException(
            status_code=400,
            detail="Username can only contain letters, numbers, and underscores"
        )
    
    if len(username) < 3:
        raise HTTPException(
            status_code=400,
            detail="Username must be at least 3 characters"
        )
    
    # Check if username already exists
    if username in DEFAULT_USERS:
        raise HTTPException(
            status_code=400,
            detail="Username already taken"
        )
    
    # Check password length
    if len(signup_data.password) < 8:
        raise HTTPException(
            status_code=400,
            detail="Password must be at least 8 characters"
        )
    
    # Validate role
    valid_roles = ['admin', 'pentester']
    role = signup_data.role if signup_data.role in valid_roles else 'pentester'
    
    # Create new user (in memory for demo)
    DEFAULT_USERS[username] = {
        "password_hash": hash_password(signup_data.password),
        "role": role,
        "name": name,
        "email": email
    }
    
    # Automatically log in the new user
    token = create_session(username, remember=False)
    
    # Set cookie
    response.set_cookie(
        key="atlas_session",
        value=token,
        httponly=True,
        max_age=24 * 60 * 60,
        samesite="lax"
    )
    
    return LoginResponse(
        success=True,
        message="Account created successfully",
        token=token,
        user={
            "username": username,
            "name": name,
            "role": role
        }
    )


@router.post("/google", response_model=LoginResponse)
async def google_auth(response: Response):
    """
    Google OAuth authentication (demo mode).
    
    In production, this would verify Google OAuth tokens.
    For demo purposes, creates/logs in a demo Google user.
    """
    # Demo Google user
    google_email = "demo.user@gmail.com"
    google_name = "Demo Google User"
    username = "google_demo_user"
    
    # Create user if doesn't exist
    if username not in DEFAULT_USERS:
        DEFAULT_USERS[username] = {
            "password_hash": hash_password(secrets.token_urlsafe(32)),  # Random password
            "role": "user",
            "name": google_name,
            "email": google_email,
            "provider": "google"
        }
    
    # Create session
    token = create_session(username, remember=False)
    
    # Set cookie
    response.set_cookie(
        key="atlas_session",
        value=token,
        httponly=True,
        max_age=24 * 60 * 60,
        samesite="lax"
    )
    
    return LoginResponse(
        success=True,
        message="Google sign-in successful",
        token=token,
        user={
            "username": username,
            "name": google_name,
            "role": "user"
        }
    )


@router.post("/microsoft", response_model=LoginResponse)
async def microsoft_auth(response: Response):
    """
    Microsoft OAuth authentication (demo mode).
    
    In production, this would verify Microsoft OAuth tokens.
    For demo purposes, creates/logs in a demo Microsoft user.
    """
    # Demo Microsoft user
    ms_email = "demo.user@outlook.com"
    ms_name = "Demo Microsoft User"
    username = "microsoft_demo_user"
    
    # Create user if doesn't exist
    if username not in DEFAULT_USERS:
        DEFAULT_USERS[username] = {
            "password_hash": hash_password(secrets.token_urlsafe(32)),
            "role": "user",
            "name": ms_name,
            "email": ms_email,
            "provider": "microsoft"
        }
    
    # Create session
    token = create_session(username, remember=False)
    
    # Set cookie
    response.set_cookie(
        key="atlas_session",
        value=token,
        httponly=True,
        max_age=24 * 60 * 60,
        samesite="lax"
    )
    
    return LoginResponse(
        success=True,
        message="Microsoft sign-in successful",
        token=token,
        user={
            "username": username,
            "name": ms_name,
            "role": "user"
        }
    )


@router.post("/github", response_model=LoginResponse)
async def github_auth(response: Response):
    """
    GitHub OAuth authentication (demo mode).
    
    In production, this would verify GitHub OAuth tokens.
    For demo purposes, creates/logs in a demo GitHub user.
    """
    # Demo GitHub user
    gh_email = "demo.user@github.com"
    gh_name = "Demo GitHub User"
    username = "github_demo_user"
    
    # Create user if doesn't exist
    if username not in DEFAULT_USERS:
        DEFAULT_USERS[username] = {
            "password_hash": hash_password(secrets.token_urlsafe(32)),
            "role": "pentester",  # GitHub users default to pentester
            "name": gh_name,
            "email": gh_email,
            "provider": "github"
        }
    
    # Create session
    token = create_session(username, remember=False)
    
    # Set cookie
    response.set_cookie(
        key="atlas_session",
        value=token,
        httponly=True,
        max_age=24 * 60 * 60,
        samesite="lax"
    )
    
    return LoginResponse(
        success=True,
        message="GitHub sign-in successful",
        token=token,
        user={
            "username": username,
            "name": gh_name,
            "role": "pentester"
        }
    )
