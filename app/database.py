"""Ce module gère la connexion à la base de données et les sessions."""

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

DATABASE_URL = "sqlite:///./vault.db"  # Tu peux switcher vers PostgreSQL

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    """Permet d'obtenir une session de base de données.

    Returns:
        Session: La session de base de données.

    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
