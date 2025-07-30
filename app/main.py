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


# CRITICAL: CORS configuration for session cookies across domains
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",  # For npm start development
        "https://expense-graveyard.netlify.app",  # Netlify deployment
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include authentication routes
app.include_router(auth.router, prefix="/auth", tags=["authentication"])

@app.get("/")
async def root():
    """Welcome message for the API"""
    return {"message": "Welcome to the Expense Graveyard API 🪦"}

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "alive", "message": "The graveyard spirits are active! 👻"}
