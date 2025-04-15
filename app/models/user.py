from sqlalchemy import Column, Integer, String, LargeBinary
from sqlalchemy.orm import relationship

from app.database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    totp_secret = Column(String, nullable=False)

    passwords = relationship("PasswordEntry", back_populates="owner", cascade="all, delete")
