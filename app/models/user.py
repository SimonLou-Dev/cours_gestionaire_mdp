from sqlalchemy import Column, Integer, String, LargeBinary
from app.database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    totp_secret = Column(String, nullable=False)

    hashed_pin = Column(String, nullable=False)
    encrypted_aes_key = Column(LargeBinary, nullable=False)
