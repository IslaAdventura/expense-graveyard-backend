# app/routers/auth.py - REPLACE YOUR EXISTING FILE WITH THIS
"""
Ultra-secure authentication with server-side sessions and encrypted data
"""
import os
import logging
from datetime import datetime, timezone
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, status, Request, Response, Cookie
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.user import User
from app.models.session import UserSession
from app.schemas.user import UserCreate, UserLogin, UserResponse, SessionInfo, Token
from app.core.security import verify_password, get_password_hash

# Setup logging for security events
logging.basicConfig(level=logging.INFO)
security_logger = logging.getLogger("security")

router = APIRouter()

def get_device_info(request: Request) -> dict:
    """Extract device information for session tracking"""
    # Safely extract client host
    if request.client and hasattr(request.client, 'host'):
        client_host = request.client.host
    else:
        client_host = "unknown"

    # Extract user agent from headers
    user_agent = request.headers.get('user-agent', '')

    # Create device fingerprint
    fingerprint = f"{client_host}:{user_agent}"[:255]

    return {
        'ip_address': client_host,
        'user_agent': user_agent,
        'fingerprint': fingerprint
    }

def get_current_session(
    request: Request,  # pylint: disable=unused-argument
    session_id: Optional[str] = Cookie(None, alias="session_id"),
    db: Session = Depends(get_db)
) -> UserSession:
    """Get current session from secure cookie"""

    if not session_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No active session"
        )

    # Find session in database
    session = db.query(UserSession).filter(
        UserSession.session_id == session_id,
        UserSession.is_active is True
    ).first()

    if not session or not session.is_valid():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session"
        )

    # Update last accessed time
    session.last_accessed = datetime.now(timezone.utc)
    db.commit()

    # Log access for security monitoring
    security_logger.info(
    "Session accessed: user_id=%s, ip=%s",
    session.user_id,
    request.client.host if request.client else "unknown"
)

    return session

def get_current_user(
    session: UserSession = Depends(get_current_session),
    db: Session = Depends(get_db)
) -> User:
    """Get current user from session"""

    user = db.query(User).filter(User.id == session.user_id).first()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive"
        )

    return user

@router.post("/register", response_model=UserResponse)
async def register_user(
    user_data: UserCreate,
    request: Request,
    db: Session = Depends(get_db)
):
    """Register a new user account with maximum security 🦇"""

    device_info = get_device_info(request)
    security_logger.info(
        "Registration attempt for %s from %s",
        user_data.username, device_info['ip_address']
    )

    # Check if user already exists
    existing_user = db.query(User).filter(
        User.username == user_data.username
    ).first()

    if existing_user:
        # Check encrypted email too (this requires decryption, but worth it for security)
        users_with_email = db.query(User).all()
        for user in users_with_email:
            if user.email == user_data.email:  # This will decrypt and compare

                security_logger.warning(
                    "Attempted registration with existing email from %s",
                    device_info['ip_address']
                )
                raise HTTPException(
                    status_code=400,
                    detail="Username or email already registered in the graveyard!"
                )

    # Create new user with encrypted data
    hashed_password = get_password_hash(user_data.password)
    db_user = User(
        username=user_data.username,
        email=user_data.email,  # Will be encrypted automatically
        display_name=user_data.display_name,  # Will be encrypted automatically
        hashed_password=hashed_password
    )

    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    security_logger.info("New user registered: %s", user_data.username)

    return UserResponse(
        id=db_user.id,
        username=db_user.username,
        email=db_user.email,  # Will be decrypted automatically
        display_name=db_user.display_name,  # Will be decrypted automatically
        is_active=db_user.is_active,
        created_at=db_user.created_at
    )

@router.post("/login", response_model=Token)
async def login_user(
    user_data: UserLogin,
    request: Request,
    response: Response,
    remember_me: bool = False,
    db: Session = Depends(get_db)
):
    """Login user with secure server-side session 👻"""

    device_info = get_device_info(request)
    security_logger.info(
        "Login attempt for %s from %s",
        user_data.username, device_info['ip_address']
    )

    # Find user
    user = db.query(User).filter(User.username == user_data.username).first()

    if not user:
        security_logger.warning("Login attempt for non-existent user: %s", user_data.username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password - the spirits reject you!"
        )

    # Check if account is locked
    if user.is_account_locked():
        security_logger.warning("Login attempt for locked account: %s", user_data.username)
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail="Account temporarily locked due to failed login attempts"
        )

    # Verify password
    if not verify_password(user_data.password, user.hashed_password):
        user.increment_failed_login()
        db.commit()
        security_logger.warning(
            "Failed login for %s from %s",
            user_data.username, device_info['ip_address']
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password - the spirits reject you!"
        )

    if not user.is_active:
        security_logger.warning("Login attempt for inactive user: %s", user_data.username)
        raise HTTPException(status_code=400, detail="This soul has been banished!")

    # Successful login - reset failed attempts
    user.reset_failed_login()

    # Create secure server-side session
    session = UserSession.create_session(
        user_id=user.id,
        device_info=device_info,
        remember_me=remember_me
    )

    db.add(session)
    db.commit()

    # Set secure httpOnly cookie - NO DATA ON CLIENT!
    cookie_max_age = 30 * 24 * 3600 if remember_me else 24 * 3600  # 30 days or 24 hours

    response.set_cookie(
        key="session_id",
        value=session.session_id,
        max_age=cookie_max_age,
        httponly=True,      # Can't be accessed by JavaScript - XSS protection
        secure=False,       # Set to True in production with HTTPS
        samesite="lax",     # CSRF protection (lax for development)
        path="/"
    )

    security_logger.info("Successful login for %s", user_data.username)

    return Token(
        message="Login successful",
        user=UserResponse(
            id=user.id,
            username=user.username,
            email=user.email,  # Decrypted automatically
            display_name=user.display_name,  # Decrypted automatically
            is_active=user.is_active,
            created_at=user.created_at
        )
    )

@router.post("/logout")
async def logout(
    response: Response,
    session: UserSession = Depends(get_current_session),
    db: Session = Depends(get_db)
):
    """Logout from current session"""

    # Revoke session in database
    session.revoke()
    db.commit()

    # Clear cookie
    response.delete_cookie(key="session_id", path="/")

    security_logger.info("User logged out: user_id=%s", session.user_id)

    return {"message": "Successfully logged out! 👻"}

@router.post("/logout-all")
async def logout_all_devices(
    response: Response,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Logout from ALL devices (revoke all sessions)"""

    # Revoke all user sessions
    current_user.revoke_all_sessions(db)

    # Clear current cookie
    response.delete_cookie(key="session_id", path="/")

    security_logger.info("All sessions revoked for user_id=%s", current_user.id)

    return {"message": "Successfully logged out from all devices! 🦇"}

@router.get("/me", response_model=UserResponse)
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    """Get current user information"""

    return UserResponse(
        id=current_user.id,
        username=current_user.username,
        email=current_user.email,  # Decrypted automatically
        display_name=current_user.display_name,  # Decrypted automatically
        is_active=current_user.is_active,
        created_at=current_user.created_at
    )

@router.get("/check-session")
async def check_session(current_user: User = Depends(get_current_user)):
    """Check if current session is valid (for frontend)"""

    return {
        "authenticated": True,
        "user": UserResponse(
            id=current_user.id,
            username=current_user.username,
            email=current_user.email,
            display_name=current_user.display_name,
            is_active=current_user.is_active,
            created_at=current_user.created_at
        )
    }

@router.get("/sessions", response_model=List[SessionInfo])
async def get_active_sessions(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get all active sessions for current user"""

    sessions = db.query(UserSession).filter(
        UserSession.user_id == current_user.id,
        UserSession.is_active is True
    ).all()

    return [
        SessionInfo(
            session_id=session.session_id[:8] + "...",  # Partial ID for security
            created_at=session.created_at,
            last_accessed=session.last_accessed,
            expires_at=session.expires_at,
            device_info=session.user_agent[:50] + "..." if session.user_agent else "Unknown",
            ip_address=session.ip_address,
            is_current=False  # You'd need to track this
        )
        for session in sessions
    ]

@router.delete("/sessions/{session_id}")
async def revoke_session(
    session_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Revoke a specific session"""

    session = db.query(UserSession).filter(
        UserSession.session_id == session_id,
        UserSession.user_id == current_user.id,
        UserSession.is_active is True
    ).first()

    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    session.revoke()
    db.commit()

    security_logger.info("Session %s revoked by user_id=%s", session_id[:8], current_user.id)

    return {"message": "Session revoked successfully"}

# EMERGENCY ADMIN ENDPOINTS
@router.post("/emergency/revoke-all-sessions")
async def emergency_revoke_all_sessions(
    admin_key: str,
    db: Session = Depends(get_db)
):
    """EMERGENCY: Revoke ALL sessions (admin only)"""

    if admin_key != os.getenv("EMERGENCY_ADMIN_KEY"):
        security_logger.critical("Unauthorized emergency admin access attempt!")
        raise HTTPException(status_code=401, detail="Unauthorized")

    # Revoke ALL active sessions
    db.query(UserSession).filter(UserSession.is_active is True).update({"is_active": False})
    db.commit()

    security_logger.critical("EMERGENCY: All sessions revoked by admin")

    return {"message": "ALL sessions revoked successfully"}
