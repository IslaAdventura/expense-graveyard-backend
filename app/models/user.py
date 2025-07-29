# app/models/user.py
"""
Enhanced user model with encryption and security features
"""
import os
from datetime import datetime, timezone, timedelta
from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text
from sqlalchemy.orm import relationship
from app.database import Base

class User(Base):
    """
    User model with encrypted sensitive data and security features
    """
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    # Not encrypted - needed for queries

    # ENCRYPTED FIELDS - sensitive data protected!
    email_encrypted = Column(Text, nullable=False)
    display_name_encrypted = Column(Text, nullable=False)

    # Password is hashed (different from encryption)
    hashed_password = Column(String, nullable=False)

    # Account status and security
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_login = Column(DateTime)
    failed_login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime)  # Account lockout for security

    # Relationships
    sessions = relationship("UserSession", back_populates="user")

    def __init__(self, username: str, email: str, display_name: str, hashed_password: str):
        self.username = username
        self.email = email  # This will encrypt automatically
        self.display_name = display_name  # This will encrypt automatically
        self.hashed_password = hashed_password

    @property
    def email(self) -> str:
        """Decrypt email when accessing"""
        return self._decrypt_field(self.email_encrypted)

    @email.setter
    def email(self, value: str):
        """Encrypt email when storing"""
        self.email_encrypted = self._encrypt_field(value)

    @property
    def display_name(self) -> str:
        """Decrypt display name when accessing"""
        return self._decrypt_field(self.display_name_encrypted)

    @display_name.setter
    def display_name(self, value: str):
        """Encrypt display name when storing"""
        self.display_name_encrypted = self._encrypt_field(value)

    def _get_encryption_key(self) -> bytes:
        """Get encryption key from environment"""
        key = os.getenv("USER_DATA_ENCRYPTION_KEY")
        if not key:
            raise ValueError("USER_DATA_ENCRYPTION_KEY environment variable not set!")
        return key.encode()

    def _encrypt_field(self, value: str) -> str:
        """Encrypt a field value"""
        if not value:
            return ""

        key = self._get_encryption_key()
        f = Fernet(key)
        return f.encrypt(value.encode()).decode()

    def _decrypt_field(self, encrypted_value: str) -> str:
        """Decrypt a field value"""
        if not encrypted_value:
            return ""

        try:
            key = self._get_encryption_key()
            f = Fernet(key)
            return f.decrypt(encrypted_value.encode()).decode()
        except (ValueError, TypeError, InvalidToken) as e:
            # Log this error - it's serious!
            print(f"Decryption error: {e}")
            return "[DECRYPTION_ERROR]"

    def is_account_locked(self) -> bool:
        """Check if account is temporarily locked"""
        if not self.locked_until:
            return False
        return datetime.now(timezone.utc) < self.locked_until

    def increment_failed_login(self):
        """Track failed login attempts"""
        self.failed_login_attempts += 1

        # Lock account after 5 failed attempts
        if self.failed_login_attempts >= 5:
            self.locked_until = datetime.now(timezone.utc) + timedelta(minutes=30)

    def reset_failed_login(self):
        """Reset failed login counter on successful login"""
        self.failed_login_attempts = 0
        self.locked_until = None
        self.last_login = datetime.now(timezone.utc)

    def revoke_all_sessions(self, db_session):
        """Revoke all active sessions for this user"""
        for session in self.sessions:
            if session.is_active:
                session.revoke()
        db_session.commit()

    def __repr__(self):
        return f"<User(username='{self.username}', display_name='[ENCRYPTED]')>"
