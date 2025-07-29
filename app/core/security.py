# app/core/security.py
"""
Security functions for password hashing and server-side session management
"""
import os
import secrets
from passlib.context import CryptContext
from cryptography.fernet import Fernet, InvalidToken

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Check if a plain password matches the hashed version"""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """Hash a password for storing in the database"""
    return pwd_context.hash(password)

def generate_session_id() -> str:
    """Generate a cryptographically secure session ID"""
    return secrets.token_urlsafe(32)

def get_encryption_key() -> bytes:
    """Get encryption key from environment variable"""
    key = os.getenv("USER_DATA_ENCRYPTION_KEY")
    if not key:
        raise ValueError("USER_DATA_ENCRYPTION_KEY environment variable not set")
    return key.encode()

def encrypt_data(data: str) -> str:
    """Encrypt sensitive data for database storage"""
    if not data:
        return data

    fernet = Fernet(get_encryption_key())
    encrypted_data = fernet.encrypt(data.encode())
    return encrypted_data.decode()

def decrypt_data(encrypted_data: str) -> str:
    """Decrypt sensitive data from database"""
    if not encrypted_data:
        return encrypted_data

    try:
        fernet = Fernet(get_encryption_key())
        decrypted_data = fernet.decrypt(encrypted_data.encode())
        return decrypted_data.decode()
    except (ValueError, TypeError, InvalidToken):
        # If decryption fails, return empty string
        return ""

# Security configuration
SESSION_EXPIRE_HOURS = 24  # Regular sessions expire in 24 hours
REMEMBER_ME_EXPIRE_DAYS = 30  # Remember me sessions last 30 days
MAX_FAILED_ATTEMPTS = 5  # Account locks after 5 failed attempts
LOCKOUT_DURATION_MINUTES = 15  # Account locked for 15 minutes

# Rate limiting configuration
RATE_LIMIT_REQUESTS = 100  # Max requests per window
RATE_LIMIT_WINDOW_MINUTES = 15  # Rate limit window

def generate_secure_key() -> str:
    """Generate a secure key for encryption (use this to create ENCRYPTION_KEY)"""
    return Fernet.generate_key().decode()

def is_password_strong(password: str) -> tuple[bool, list[str]]:
    """
    Check if password meets security requirements
    Returns (is_valid, list_of_issues)
    """
    issues = []

    if len(password) < 8:
        issues.append("Password must be at least 8 characters long")

    if not any(c.isupper() for c in password):
        issues.append("Password must contain at least one uppercase letter")

    if not any(c.islower() for c in password):
        issues.append("Password must contain at least one lowercase letter")

    if not any(c.isdigit() for c in password):
        issues.append("Password must contain at least one number")

    if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
        issues.append("Password must contain at least one special character")

    return len(issues) == 0, issues
