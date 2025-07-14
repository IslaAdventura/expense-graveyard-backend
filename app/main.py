# app/main.py
"""
Expense Graveyard API - A spooky expense tracking API for group trips
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Import our database and models
from app.database import engine
from app.models import user
from app.routers import auth

# Create the database tables when the app starts
user.Base.metadata.create_all(bind=engine)

# Create the FastAPI app
app = FastAPI(
    title="Expense Graveyard API",
    description="A spooky expense tracking API for group trips 🦇",
    version="1.0.0"
)

# CRITICAL: Add CORS FIRST, before any routers
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)

# AFTER CORS, include routers
app.include_router(auth.router, prefix="/api/auth", tags=["authentication"])

# Your endpoints
@app.get("/")
async def root():
    return {"message": "Welcome to the Expense Graveyard API 🦇"}

@app.get("/health")
async def health_check():
    return {"status": "alive", "message": "The spirits are restless but the API lives! 👻"}

@app.get("/test")
async def test():
    return {
        "message": "If you can see this, your API is working!",
        "spooky_fact": "Did you know bats can live over 30 years? 🦇",
        "database": "Database connected and ready to store souls! 🗄️💀"
    }
