from datetime import datetime, timedelta
from typing import Any

import uuid
from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, Boolean, UUID
from sqlalchemy.orm import relationship
from app.database import Base
from app.dto.passwords import PasswordOut
from app.models.user import User
from app.services import crypto, password_utils


class PasswordEntry(Base):
    __tablename__ = "passwords"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    username = Column(String, nullable=False)
    email = Column(String, nullable=False)
    encrypted_password = Column(String, nullable=False)
    url = Column(String, nullable=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    complexity = Column(Integer, nullable=True)

    owner = relationship("User", back_populates="passwords")

    def __init__(self, title: str, username: str, email: str, url: str, password: str, user: User, aes_key: bytes,  **kw: Any):
        super().__init__(**kw)
        self.title = crypto.encrypt_password(title, aes_key)
        self.encrypted_password = crypto.encrypt_password(password, aes_key)
        self.username = crypto.encrypt_password(username, aes_key)
        self.email = crypto.encrypt_password(email, aes_key)
        self.url = crypto.encrypt_password(url, aes_key)
        self.complexity = password_utils.calculate_password_strength(password)
        self.owner = user


    def get_decrypted(self, aes_key: bytes) -> "PasswordOut":
        return PasswordOut(
            id=self.id,
            password=crypto.decrypt_password(self.encrypted_password, aes_key),
            title=crypto.decrypt_password(self.title, aes_key),
            username=crypto.decrypt_password(self.username, aes_key),
            email=crypto.decrypt_password(self.email, aes_key),
            url=crypto.decrypt_password(self.url, aes_key),
            complexity=self.complexity
        )


class SharedPasswordEntry(Base):
    __tablename__ = "shared_password_entries"

    id = Column(Integer, primary_key=True, index=True)
    uuid = Column(UUID(as_uuid=True), default=uuid.uuid4, unique=True, index=True, nullable=False)

    # Données chiffrées
    encrypted_title = Column(String, nullable=False)
    encrypted_username = Column(String, nullable=False)
    encrypted_email = Column(String, nullable=False)
    encrypted_password = Column(String, nullable=False)
    encrypted_url = Column(String, nullable=True)

    # Métadonnées
    expiry_date = Column(DateTime, nullable=False)
    original_entry_id = Column(Integer, ForeignKey("passwords.id"))

    # Identifiant unique pour le système de partage
    share_token_id = Column(String, nullable=False)  # Un identifiant pour retrouver le token, pas le token lui-même