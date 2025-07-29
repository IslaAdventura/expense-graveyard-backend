# app/models/session.py - CREATE THIS NEW FILE
"""
Secure server-side session model
"""
import secrets
from datetime import datetime, timezone, timedelta
from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, Text
from sqlalchemy.orm import relationship
from app.database import Base

class UserSession(Base):
    """
    Server-side session storage - no sensitive data on client!
    """
    __tablename__ = "user_sessions"

    # Session ID - this is the ONLY thing stored on user's computer
    session_id = Column(String(64), primary_key=True)

    # Link to user
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    user = relationship("User", back_populates="sessions")

    # Session management
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime, nullable=False)
    last_accessed = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    is_active = Column(Boolean, default=True)

    # Device tracking for security
    device_fingerprint = Column(String(255))  # Browser/device info
    ip_address = Column(String(45))  # Support IPv6
    user_agent = Column(Text)

    # Security flags
    is_remember_me = Column(Boolean, default=False)  # Long vs short session
    login_method = Column(String(50), default="password")  # password, oauth, etc.

    @classmethod
    def create_session(cls, user_id: int, device_info: dict, remember_me: bool = False):
        """Create a new secure session"""
        session_id = secrets.token_urlsafe(48)  # Cryptographically secure

        # Session duration based on remember_me
        if remember_me:
            expires_at = datetime.now(timezone.utc) + timedelta(days=30)
        else:
            expires_at = datetime.now(timezone.utc) + timedelta(hours=24)

        return cls(
            session_id=session_id,
            user_id=user_id,
            expires_at=expires_at,
            device_fingerprint=device_info.get('fingerprint'),
            ip_address=device_info.get('ip_address'),
            user_agent=device_info.get('user_agent'),
            is_remember_me=remember_me
        )

    def is_valid(self) -> bool:
        """Check if session is still valid"""
        return (
            self.is_active and
            datetime.now(timezone.utc) < self.expires_at
        )

    def extend_session(self, hours: int = 24):
        """Extend session expiration"""
        self.expires_at = datetime.now(timezone.utc) + timedelta(hours=hours)
        self.last_accessed = datetime.now(timezone.utc)

    def revoke(self):
        """Revoke this session"""
        self.is_active = False
