"""
ATLAS Authentication Routes

Handles user login, logout, signup, and session management.
Now uses SQLite database for persistent user storage.
"""

import hashlib
import secrets
import uuid
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, HTTPException, Depends, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from atlas.persistence.database import Database
from atlas.persistence.models import User

router = APIRouter(prefix="/auth", tags=["Authentication"])

# Simple in-memory session store (use Redis in production)
_sessions = {}

# Database instance (initialized lazily)
_db = None

def get_db() -> Database:
    """Get database instance"""
    global _db
    if _db is None:
        _db = Database()
    return _db


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
    role: str = "pentester"  # Default role


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
    
    Users are stored in SQLite database for persistence.
    """
    db = get_db()
    username = credentials.username.lower().strip()
    password_hash = hash_password(credentials.password)
    
    # Get user from database
    user = db.get_user_by_username(username)
    
    if not user or user.password_hash != password_hash:
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
            "role": user.role if user else "user"
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
        role=user.role if user else "user"
    )


@router.post("/signup", response_model=LoginResponse)
async def signup(signup_data: SignupRequest, response: Response):
    """
    Create a new user account.
    
    Registers the user in SQLite database and automatically logs them in.
    """
    db = get_db()
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
    
    # Check password length
    if len(signup_data.password) < 8:
        raise HTTPException(
            status_code=400,
            detail="Password must be at least 8 characters"
        )
    
    # Validate role
    valid_roles = ['admin', 'pentester', 'analyst', 'user']
    role = signup_data.role if signup_data.role in valid_roles else 'pentester'
    
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
    db = get_db()
    
    # Demo Google user
    google_email = "demo.user@gmail.com"
    google_name = "Demo Google User"
    username = "google_demo_user"
    
    # Create user if doesn't exist
    if not db.username_exists(username):
        new_user = User(
            id=str(uuid.uuid4())[:8],
            username=username,
            email=google_email,
            name=google_name,
            password_hash=hash_password(secrets.token_urlsafe(32)),
            role="user",
            created_at=datetime.utcnow()
        )
        db.create_user(new_user)
    
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
    db = get_db()
    
    # Demo Microsoft user
    ms_email = "demo.user@outlook.com"
    ms_name = "Demo Microsoft User"
    username = "microsoft_demo_user"
    
    # Create user if doesn't exist
    if not db.username_exists(username):
        new_user = User(
            id=str(uuid.uuid4())[:8],
            username=username,
            email=ms_email,
            name=ms_name,
            password_hash=hash_password(secrets.token_urlsafe(32)),
            role="user",
            created_at=datetime.utcnow()
        )
        db.create_user(new_user)
    
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
    db = get_db()
    
    # Demo GitHub user
    gh_email = "demo.user@github.com"
    gh_name = "Demo GitHub User"
    username = "github_demo_user"
    
    # Create user if doesn't exist
    if not db.username_exists(username):
        new_user = User(
            id=str(uuid.uuid4())[:8],
            username=username,
            email=gh_email,
            name=gh_name,
            password_hash=hash_password(secrets.token_urlsafe(32)),
            role="pentester",
            created_at=datetime.utcnow()
        )
        db.create_user(new_user)
    
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


@router.put("/profile")
async def update_profile(request: Request):
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
    
    body = await request.json()
    updates = {}
    
    if "name" in body and body["name"]:
        updates["name"] = body["name"].strip()
    if "email" in body and body["email"]:
        new_email = body["email"].lower().strip()
        # Check if email is already taken by another user
        existing = db.get_user_by_email(new_email)
        if existing and existing.id != user.id:
            raise HTTPException(status_code=400, detail="Email already in use")
        updates["email"] = new_email
    
    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")
    
    db.update_user(user.id, **updates)
    
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
async def change_password(request: Request):
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
    
    body = await request.json()
    current_password = body.get("current_password", "")
    new_password = body.get("new_password", "")
    
    # Verify current password
    if hash_password(current_password) != user.password_hash:
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    
    # Validate new password
    if len(new_password) < 8:
        raise HTTPException(status_code=400, detail="New password must be at least 8 characters")
    
    # Update password
    db.update_user_password(user.id, hash_password(new_password))
    
    return {"success": True, "message": "Password changed successfully"}
