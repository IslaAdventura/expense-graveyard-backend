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
        "http://localhost:3000",  # React dev server
        "http://localhost:5173",  # Vite dev server
        "https://localhost:3000", # HTTPS localhost
        "https://localhost:5173", # HTTPS Vite
        # Add your production frontend domain when you deploy
    ],
    allow_credentials=True,  # CRITICAL: Allows cookies to be sent cross-domain
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["*"],  # Expose all headers
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
