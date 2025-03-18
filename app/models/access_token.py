from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import relationship, mapped_column, Mapped
from database import Base

class AccessToken(Base):
    __tablename__ = "accessTokens"
    id = Column(Integer, primary_key=True, index=True)
    user_id = mapped_column(Integer, ForeignKey("users.id"))
    access_token = Column(String(200), index=True)
    expires_at = Column(DateTime, index=True)

    owner: Mapped["User"]  = relationship( back_populates="tokens")

