from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from starlette import schemas

from database import SessionLocal, engine
import models
import services
import pyotp
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import os

app = FastAPI()

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Database setup
models.Base.metadata.create_all(bind=engine)

# Dependency to get the database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Routes
@app.get("/", response_class=HTMLResponse)
async def login(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@app.post("/login")
def login(user: schemas.UserLogin, db: Session = Depends(get_db)):
    # Chercher l'utilisateur dans la base de données
    db_user = db.query(models.User).filter(models.User.username == user.username).first()
    if not db_user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Vérifier le mot de passe
    if not services.verify_password(db_user.password_hash, user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Vérifier le code TOTP
    if not services.verify_totp(db_user.totp_secret, user.totp_token):
        raise HTTPException(status_code=401, detail="Invalid TOTP code")

    # Authentification réussie
    return {"message": "Login successful"}

@app.post("/add_password")
def add_password(user_password: str, password_entry: schemas.PasswordEntry, db: Session = Depends(get_db)):
    # Lors de l'ajout d'un mot de passe, on chiffre le mot de passe de l'utilisateur
    encrypted_password = services.encrypt_password(password_entry.password, user_password)
    new_entry = models.PasswordEntry(title=password_entry.title, encrypted_password=encrypted_password,
                                     category=password_entry.category, user_id=password_entry.user_id)
    db.add(new_entry)
    db.commit()
    return {"message": "Password added successfully"}

@app.get("/register", response_class=HTMLResponse)
async def register(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})


@app.post("/register")
def register(user: schemas.UserCreate, db: Session = Depends(get_db)):
    # Vérifier si l'utilisateur existe déjà
    db_user = db.query(models.User).filter(models.User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")

    # Hash du mot de passe
    hashed_password = services.hash_password(user.password)

    # Générer le secret TOTP
    totp_secret = services.generate_totp_secret()

    # Ajouter l'utilisateur à la base de données
    db_user = models.User(username=user.username, password_hash=hashed_password, totp_secret=totp_secret)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    # Générer le QR code à afficher pour l'application d'authentification
    qr_code = services.generate_qr_code(totp_secret, user.username)

    return templates

    return {"message": "User registered successfully", "qr_code": qr_code}


@app.get("/unlock", response_class=HTMLResponse)
async def unlock(request: Request):
    return templates.TemplateResponse("unlock.html", {"request": request})

@app.post("/unlock")
async def unlock_post(request: Request, pin: str, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.pin == pin).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid PIN")
    return templates.TemplateResponse("dashboard.html", {"request": request, "user": user})

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.id == 1).first()  # Replace with actual user lookup
    passwords = db.query(models.PasswordEntry).filter(models.PasswordEntry.user_id == user.id).all()
    return templates.TemplateResponse("dashboard.html", {"request": request, "user": user, "passwords": passwords})

@app.get("/analyze", response_class=HTMLResponse)
async def analyze(request: Request, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.id == 1).first()  # Replace with actual user lookup
    entries = db.query(models.PasswordEntry).filter(models.PasswordEntry.user_id == user.id).all()
    analysis = services.password_utils.analyze_passwords(entries)
    return templates.TemplateResponse("analyze.html", {"request": request, "analysis": analysis})

@app.get("/share/{password_id}", response_class=HTMLResponse)
async def share(request: Request, password_id: int, db: Session = Depends(get_db)):
    password = db.query(models.PasswordEntry).filter(models.PasswordEntry.id == password_id).first()
    if not password:
        raise HTTPException(status_code=404, detail="Password not found")
    url = f"/shared/{password_id}"  # Link logic for sharing (placeholder)
    return templates.TemplateResponse("share.html", {"request": request, "url": url})
