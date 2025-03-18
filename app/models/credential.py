from pydantic import BaseModel, EmailStr
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import relationship, mapped_column, Mapped
from database import Base


class Credential(Base):

    __tablename__ = "credentials"
    id = Column(Integer, primary_key=True, index=True)
    user_id = mapped_column(Integer, ForeignKey("users.id"))
    name: str = Column(String, index=True)
    email: EmailStr = Column(String, index=True)
    pseudo: str = Column(String, index=True)
    password: str = Column(String, index=True)
    iv: str = Column(String, index=True)
    url: str = Column(String, index=True)

    user: Mapped["User"] = relationship(back_populates="creds")

    def render(self):
        return CredentialOut(
            name=self.name,
            email=self.email,
            pseudo=self.pseudo,
            password=self.password,
            iv=self.iv,
            url=self.url,
            id=self.id
        )

class CredentialIn(BaseModel):
    name: str
    email: EmailStr
    pseudo: str
    password: str
    iv: str
    url: str

class CredentialOut(CredentialIn):
    id: int
    pass