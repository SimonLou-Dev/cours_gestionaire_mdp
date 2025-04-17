from pydantic import BaseModel

class PasswordOut(BaseModel):
    id: int
    title: str
    username: str
    url: str
    email: str
    password: str
    complexity: int

    class Config:
        from_attributes = True

class PasswordCreate(BaseModel):
    title: str
    username: str
    password: str
    url: str
    category_id: int
