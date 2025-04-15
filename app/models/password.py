from sqlalchemy import Column, Integer, String, ForeignKey, LargeBinary
from sqlalchemy.orm import relationship
from app.database import Base
from app.dto.passwords import PasswordOut
from app.models.user import User
from app.services import crypto


class Category(Base):
    __tablename__ = "categories"
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"))

class PasswordEntry(Base):
    __tablename__ = "passwords"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    username = Column(String, nullable=False)
    email = Column(String, nullable=False)
    encrypted_password = Column(String, nullable=False)
    url = Column(String, nullable=True)
    user_id = Column(Integer, ForeignKey("users.id"))

    owner = relationship("User", back_populates="passwords")

    def __init__(self, title: str, username: str, email: str, url: str, password: str, user: User, aes_key: bytes):
        self.title = crypto.encrypt_password(title, aes_key)
        self.encrypted_password = crypto.encrypt_password(password, aes_key)
        self.username = crypto.encrypt_password(username, aes_key)
        self.email = crypto.encrypt_password(email, aes_key)
        self.url = crypto.encrypt_password(url, aes_key)
        self.owner = user

    def get_decrypted(self, aes_key: str) -> "PasswordOut":
        return PasswordOut(
            id=self.id,
            password=crypto.decrypt_password(self.encrypted_password, aes_key),
            title=crypto.decrypt_password(self.title, aes_key),
            username=crypto.decrypt_password(self.username, aes_key),
            email=crypto.decrypt_password(self.email, aes_key),
            url=crypto.decrypt_password(self.url, aes_key),
        )


