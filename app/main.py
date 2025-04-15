from fastapi import FastAPI, Depends, HTTPException, status, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from itsdangerous import URLSafeTimedSerializer
from sqlalchemy.orm import Session
from starlette.responses import RedirectResponse

from app import models, services
from app.dto.passwords import PasswordCreate
from app.database import SessionLocal, engine, Base
from app.models.user import User
from app.services import crypto, totp, auth

app = FastAPI()

app.mount("/static", StaticFiles(directory="app/static"), name="static")
serializer = URLSafeTimedSerializer("SECRET_KEY")
templates = Jinja2Templates(directory="app/templates")

# Database setup
Base.metadata.create_all(bind=engine)


# Dependency to get the database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# HOME
@app.get("/", response_class=HTMLResponse)
async def login(request: Request, db: Session = Depends(get_db)):
    if auth.check_session(db, request, serializer) is not None:
        return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)
    return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

# VUES

@app.get("/register", response_class=HTMLResponse)
async def register(request: Request, db: Session = Depends(get_db)):
    if auth.check_session(db, request, serializer) is not None:
        return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse("register.html.j2", {"request": request})

@app.get("/login", response_class=HTMLResponse)
async def login_view(request: Request, db: Session = Depends(get_db)):
    # Vérifier la session de l'utilisateur
    if auth.check_session(db, request, serializer) is not None:
        return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse("login.html.j2", {"request": request})


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, db: Session = Depends(get_db)):
    # Vérifier la session de l'utilisateur
    if auth.check_session(db, request, serializer) is None:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    user = {} #db.query(User).filter(User.id == 1).first()  # Replace with actual user lookup
    passwords = [] #db.query(PasswordEntry).filter(PasswordEntry.user_id == user.id).all()
    return templates.TemplateResponse("dashboard.html.j2", {"request": request, "user": user, "passwords": passwords})

@app.get("/analyze", response_class=HTMLResponse)
async def analyze(request: Request, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.id == 1).first()  # Replace with actual user lookup
    entries = db.query(models.PasswordEntry).filter(models.PasswordEntry.user_id == user.id).all()
    analysis = services.password_utils.analyze_passwords(entries)
    return templates.TemplateResponse("analyze.html.j2", {"request": request, "analysis": analysis})

@app.get("/logout")
def logout(request: Request):
    response = RedirectResponse(url="/login")
    response.delete_cookie("session_token")
    return response

# Methodes de gestion des mots de passe


@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...), totp_token: str = Form(...), db: Session = Depends(get_db)):
    # Chercher l'utilisateur dans la base de données
    errors = []
    db_user: User = db.query(User).filter(User.username == username).first()
    if not db_user:
        errors.append("Nom d'utilisateur ou mot de passe incorrect.")

    # Vérifier le mot de passe
    if not auth.verify_password(password, db_user.hashed_password):
        errors.append("Nom d'utilisateur ou mot de passe incorrect.")

    # Vérifier le code TOTP
    if not totp.verify_totp(db_user.totp_secret, totp_token):
        errors.append("Code TOTP invalide.")

    if errors:
        return templates.TemplateResponse("login.html.j2", {"request": request, "errors": errors})

    # Authentification réussie
    response = RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)
    auth.register_session_cookie(response, db_user, serializer)

    # Enregistrer le cookie de session et rediriger l'utilisateur
    return response


@app.post("/add_password")
def add_password(user_password: str, password: PasswordCreate, db: Session = Depends(get_db)):
    # Lors de l'ajout d'un mot de passe, on chiffre le mot de passe de l'utilisateur
    encrypted_password = services.encrypt_password(password.password, user_password)
    new_entry = models.PasswordEntry(title=password.title, encrypted_password=encrypted_password,
                                     category=password.category, user_id=password.user_id)
    db.add(new_entry)
    db.commit()
    return {"message": "Password added successfully"}
@app.post("/register")
async def register(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    errors = []

    # vérification de la session
    if auth.check_session(db, request, serializer) is not None:
        return templates.TemplateResponse("dashboard.html.j2", {"request": request})

    # Vérification des champs

    if not username or not password:
        errors.append("Tous les champs sont requis.")
    elif db.query(User).filter(User.username == username).first():
        errors.append("Ce nom d'utilisateur existe déjà.")

    if errors:
        return templates.TemplateResponse("register.html.j2", {"request": request, "errors": errors})

    hashed_password = crypto.hash_password(password)
    totp_secret = totp.generate_totp_secret()

    new_user = User(
        username=username,
        hashed_password=hashed_password,
        totp_secret=totp_secret,

    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    qr_code = totp.generate_qr_code(totp_secret, username)

    return templates.TemplateResponse("register_done.html.j2", {
        "request": request,
        "qr_code": qr_code,
        "secret": totp_secret,
        "user_id": new_user.id,
    })

@app.post("/verify_totp")
def verify_totp(request: Request, totp_token: str = Form(...), qr_code: str = Form(...), secret: str = Form(...), user_id: str = Form(...), db: Session = Depends(get_db)):
    # vérification de la session
    if auth.check_session(db, request, serializer) is not None:
        return templates.TemplateResponse("dashboard.html.j2", {"request": request})

    db_user = db.query(User).filter(User.id == user_id).first()
    if not db_user:
        return templates.TemplateResponse("register_done.html.j2", {"error_message": "Utilisateur non trouvé", "request": request, "user_id": user_id,"qr_code": qr_code,"secret": secret,})

    if not totp.verify_totp(db_user.totp_secret, totp_token):
        return templates.TemplateResponse("register_done.html.j2", {"error_message": "Code TOTP invalide", "request": request, "user_id": user_id, "qr_code": qr_code,"secret": secret})

    response = RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)
    auth.register_session_cookie(response, db_user, serializer)

    # Enregistrer le cookie de session et rediriger l'utilisateur
    return response



@app.get("/share/{password_id}", response_class=HTMLResponse)
async def share(request: Request, password_id: int, db: Session = Depends(get_db)):
    password = db.query(models.PasswordEntry).filter(models.PasswordEntry.id == password_id).first()
    if not password:
        raise HTTPException(status_code=404, detail="Password not found")
    url = f"/shared/{password_id}"  # Link logic for sharing (placeholder)
    return templates.TemplateResponse("share.html.j2", {"request": request, "url": url})
