# app/schemas/user.py
"""
Enhanced Pydantic schemas for secure user data validation
"""
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr

# What data we expect when someone registers
class UserCreate(BaseModel):
    """Schema for user registration"""
    username: str
    email: EmailStr  # Better email validation
    display_name: str
    password: str

# What data we expect when someone logs in
class UserLogin(BaseModel):
    """Schema for user login"""
    username: str
    password: str

# What data we send back to the user (no password!)
class UserResponse(BaseModel):
    """Schema for user response data"""
    id: int
    username: str
    email: str
    display_name: str
    is_active: bool
    created_at: datetime

    class Config:
        """Pydantic configuration for SQLAlchemy model compatibility"""
        from_attributes = True

# ENHANCED: Token response for login with session info
class Token(BaseModel):
    """Schema for authentication token response"""
    message: str
    user: UserResponse

# NEW: Session information for security management
class SessionInfo(BaseModel):
    """Schema for session information"""
    session_id: str  # Partial ID for security
    created_at: datetime
    last_accessed: datetime
    expires_at: datetime
    device_info: str
    ip_address: str
    is_current: bool = False

# NEW: Schema for updating user profile
class UserUpdate(BaseModel):
    """Schema for user profile updates"""
    display_name: Optional[str] = None
    email: Optional[EmailStr] = None
    current_password: Optional[str] = None  # Required for password change
    new_password: Optional[str] = None

# NEW: Schema for password change
class PasswordChange(BaseModel):
    """Schema for password change requests"""
    current_password: str
    new_password: str
