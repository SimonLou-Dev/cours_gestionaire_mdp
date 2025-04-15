from fastapi import FastAPI, Depends, HTTPException, status, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from itsdangerous import URLSafeTimedSerializer
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import RedirectResponse

from app import models, services, database
from app.dto.passwords import PasswordCreate
from app.database import SessionLocal, engine, Base
from app.models.user import User
from app.services import crypto, totp, auth


# Database setup
Base.metadata.create_all(bind=engine)
app = FastAPI()

# Register des middleware
app.add_middleware(SessionMiddleware, secret_key="your-secret-key")

# Include routers

from app.routers import auth, vault, vue
app.include_router(auth.auth_router)
app.include_router(vault.vault_router)
app.include_router(vue.view_router)


# Register template & static files
serializer = URLSafeTimedSerializer("SECRET_KEY")
templates = Jinja2Templates(directory="app/templates")
app.mount("/static", StaticFiles(directory="app/static"), name="static")