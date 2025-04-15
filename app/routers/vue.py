from http.client import HTTPException

from fastapi import Depends, status, Request, APIRouter
from fastapi.responses import HTMLResponse
from itsdangerous import URLSafeTimedSerializer
from sqlalchemy.orm import Session
from starlette.responses import RedirectResponse
from starlette.templating import Jinja2Templates
from app import database
from app.models import PasswordEntry
from app.models.user import User
from app.services import auth


serializer = URLSafeTimedSerializer("SECRET_KEY")
templates = Jinja2Templates(directory="app/templates")
view_router = APIRouter()



@view_router.get("/", response_class=HTMLResponse)
async def login(request: Request, db: Session = Depends(database.get_db)):
    if auth.check_session(db, request, serializer) is not None:
        return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)
    return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

# VUES

@view_router.get("/register", response_class=HTMLResponse)
async def register(request: Request, db: Session = Depends(database.get_db)):
    if auth.check_session(db, request, serializer) is not None:
        return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse("register.html.j2", {"request": request})

@view_router.get("/login", response_class=HTMLResponse)
async def login_view(request: Request, db: Session = Depends(database.get_db)):
    # Vérifier la session de l'utilisateur
    if auth.check_session(db, request, serializer) is not None:
        return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse("login.html.j2", {"request": request})


@view_router.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, db: Session = Depends(database.get_db)):
    # Vérifier la session de l'utilisateur
    if auth.check_session(db, request, serializer) is None:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    # Récupérer le salt en session
    aes_key = bytes.fromhex(request.session.get("key"))

    # Vérifier si la clé AES est présente dans la session
    if aes_key is None:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)


    user = db.query(User).filter(User.id == 1).first() # Replace with actual user lookup

    # Récupère tous les mots de passe de l'utilisateur
    passwords = db.query(PasswordEntry).filter(PasswordEntry.user_id == user.id).all()

    # Déchiffre les mots de passe avec la clé AES dérivée de la session
    decrypted_passwords = [ entry.get_decrypted(aes_key) for entry in passwords ]

    if not aes_key:
        raise HTTPException(status_code=401, detail="AES key missing from session")

    for password_entry in passwords:
        decrypted_passwords.append(password_entry.get_decrypted(aes_key))

    return templates.TemplateResponse("dashboard.html.j2", {"request": request, "user": user, "passwords": decrypted_passwords})


@view_router.get("/analyze", response_class=HTMLResponse)
async def analyze(request: Request, db: Session = Depends(database.get_db)):
    user =  {} #.query(models.User).filter(models.User.id == 1).first()  # Replace with actual user lookup
    entries = {} #db.query(models.PasswordEntry).filter(models.PasswordEntry.user_id == user.id).all()
    analysis = {} #services.password_utils.analyze_passwords(entries)
    return templates.TemplateResponse("analyze.html.j2", {"request": request, "analysis": analysis})
