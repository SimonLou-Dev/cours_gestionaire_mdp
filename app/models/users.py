from datetime import datetime
from pydantic import BaseModel, EmailStr
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.orm import relationship, mapped_column, Mapped
from typing import List
from models.credential import Credential
from database import Base


class User(Base):
    __tablename__ = "users"
    id = mapped_column(Integer, primary_key=True, index=True)
    email: str = Column(String)
    password: str = Column(String)
    pseudo: str = Column(String)
    salt: str = Column(String)
    public_key: str = Column(String)
    private_key: str = Column(String)
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)

    tokens: Mapped[List["AccessToken"]] = relationship(
        back_populates="owner", cascade="all, delete, delete-orphan"
    )

    creds: Mapped[List["Credential"]] = relationship(
        back_populates="user", cascade="all, delete, delete-orphan"
    )

    def render(self):
        return UserOut(
            email=self.email,
            pseudo=self.pseudo
        )


class UserIn(BaseModel):
    email: EmailStr
    password: str
    pseudo: str

class UserOut(BaseModel):
    email: EmailStr
    pseudo: str

