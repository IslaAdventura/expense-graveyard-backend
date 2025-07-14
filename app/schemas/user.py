# app/schemas/user.py
"""
Pydantic schemas for user data validation
"""
from pydantic import BaseModel
from datetime import datetime

# What data we expect when someone registers
class UserCreate(BaseModel):
    username: str
    email: str
    display_name: str  # NEW FIELD!
    password: str

# What data we expect when someone logs in
class UserLogin(BaseModel):
    username: str
    password: str

# What data we send back to the user (no password!)
class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    display_name: str  # NEW FIELD!
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True

# Token response for login
class Token(BaseModel):
    access_token: str
    token_type: str
    user: UserResponse
