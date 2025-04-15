from sqlalchemy import Column, Integer, String, ForeignKey, LargeBinary
from sqlalchemy.orm import relationship
from app.database import Base
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
    encrypted_password = Column(LargeBinary, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"))
    category_id = Column(Integer, ForeignKey("categories.id"), nullable=True)

    owner = relationship("User", back_populates="passwords")
    category = relationship("Category")

    def __init__(self, title: str, password: str, category: Category, user: User, user_password: str):
        self.title = title
        self.encrypted_password = crypto.encrypt_password(password, user_password)
        self.category = category
        self.owner = user

    def get_decrypted_password(self, user_password: str) -> str:
        return crypto.decrypt_password(self.encrypted_password, user_password)


