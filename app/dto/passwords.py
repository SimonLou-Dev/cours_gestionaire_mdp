from pydantic import BaseModel

class PasswordOut(BaseModel):
    id: int
    title: str
    username: str
    url: str
    category_id: int

    class Config:
        orm_mode = True  # Très important pour convertir depuis un modèle SQLAlchemy

class PasswordCreate(BaseModel):
    title: str
    username: str
    password: str
    url: str
    category_id: int
