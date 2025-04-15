from pydantic import BaseModel, EmailStr, Field
from typing import Optional
import datetime

# DTO pour la création d'un utilisateur
class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8)
    email: Optional[EmailStr] = None

    class Config:
        orm_mode = True

# DTO pour la réponse de l'utilisateur (après création)
class UserResponse(BaseModel):
    id: int
    username: str
    email: Optional[EmailStr]
    created_at: datetime.datetime

    class Config:
        orm_mode = True

# DTO pour la mise à jour d'un utilisateur
class UserUpdate(BaseModel):
    username: Optional[str] = None
    password: Optional[str] = None
    email: Optional[EmailStr] = None

    class Config:
        orm_mode = True

from pydantic import BaseModel, Field

# DTO pour le login de l'utilisateur
class UserLogin(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8)

    class Config:
        orm_mode = True
