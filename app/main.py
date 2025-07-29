# app/main.py
"""
Enhanced FastAPI main application with secure session-based authentication
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Import database components
from app.database import engine, Base

# Import models to register them with SQLAlchemy
from app.models import user, session    # pylint: disable=unused-import

# Import routers
from app.routers import auth

# Create all database tables on startup
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Expense Graveyard API",
    description="Ultra-secure expense tracking with encrypted data and server-side sessions",
    version="2.0.0"
)

# CORS configuration for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",  # React dev server
        "http://localhost:5173",  # Vite dev server
        "https://your-frontend-domain.com",  # Production frontend
    ],
    allow_credentials=True,  # Important for session cookies!
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)

# Include authentication routes - NOTE: prefix is /auth not /api/auth
app.include_router(auth.router, prefix="/auth", tags=["authentication"])

@app.get("/")
async def root():
    """Welcome message for the API"""
    return {"message": "Welcome to the Expense Graveyard API 🪦"}

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "alive", "message": "The graveyard spirits are active! 👻"}
