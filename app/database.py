# app/database.py
"""
Database configuration for Expense Graveyard API
"""
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# SQLite database (creates a file called 'expense_graveyard.db')
SQLALCHEMY_DATABASE_URL = "sqlite:///./expense_graveyard.db"

# Create the database engine
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False}  # Only needed for SQLite
)

# Create a session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for our database models
Base = declarative_base()

def get_db():
    """
    Create a database session
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

