from fastapi import FastAPI, Request, HTTPException
from fastapi.exceptions import RequestValidationError

from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from itsdangerous import URLSafeTimedSerializer
from starlette.middleware.sessions import SessionMiddleware
from app.database import engine, Base

# Imports des modèles pour créer les tables
from app.models.user import User
from app.models.password import PasswordEntry, SharedPasswordEntry

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

# Error handling

@app.exception_handler(404)
async def custom_404_error(request: Request, exc: HTTPException):
    return templates.TemplateResponse("errors/error_404.html.j2", {
        "request": request,
        "status_code": 404,
        "message": "Page non trouvée"
    })

@app.exception_handler(500)
async def custom_500_error(request: Request, exc: HTTPException):
    return templates.TemplateResponse("errors/error_500.html.j2", {
        "request": request,
        "status_code": 500,
        "message": "Une erreur interne est survenue"
    })

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return templates.TemplateResponse("error_404.html.j2", {
        "request": request,
        "status_code": 400,
        "message": "Requête invalide"
    })