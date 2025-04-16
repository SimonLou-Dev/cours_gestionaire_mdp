from fastapi import FastAPI

from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from itsdangerous import URLSafeTimedSerializer
from starlette.middleware.sessions import SessionMiddleware
from app.database import engine, Base

# Imports des modèles pour créer les tables
from app.models.user import User
from app.models.password import PasswordEntry

app = FastAPI()

# Register des middleware
app.add_middleware(SessionMiddleware, secret_key="your-secret-key")

# Database setup
Base.metadata.create_all(bind=engine)

# Include routers

from app.routers import auth, vault, vue
app.include_router(auth.auth_router)
app.include_router(vault.vault_router)
app.include_router(vue.view_router)


# Register template & static files
serializer = URLSafeTimedSerializer("SECRET_KEY")
templates = Jinja2Templates(directory="app/templates")
app.mount("/static", StaticFiles(directory="app/static"), name="static")