import logging

from fastapi import APIRouter, Depends
from fastapi.params import Form
from itsdangerous import URLSafeTimedSerializer
from sqlalchemy.orm import Session
from starlette import status
from starlette.requests import Request
from starlette.responses import RedirectResponse

from app import database
from app.models import PasswordEntry
from app.services import auth, crypto

vault_router = APIRouter()
serializer = URLSafeTimedSerializer("SECRET_KEY")

@vault_router.post("/add_password")
async def add_password(
    request: Request,
    title: str = Form(...),
    password: str = Form(...),
    username: str = Form(...),
    email: str = Form(...),
    url: str = Form(...),
    db: Session = Depends(database.get_db)
):
    # Vérifier la session de l'utilisateur
    if (user := auth.check_session(db, request, serializer)) is None:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    aes_key = bytes.fromhex(request.session.get("key"))



    new_password_entry = PasswordEntry(
        title=title,
        password=password,
        user=user,
        aes_key=aes_key,
        username=username,
        email=email,
        url=url
    )

    # Ajouter à la DB
    db.add(new_password_entry)
    db.commit()
    db.refresh(new_password_entry)

    return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)

@vault_router.post("/delete_password/{password_id}")
async def delete_password(
    request: Request,
    password_id: int,
    db: Session = Depends(database.get_db)
):
    # Vérifier la session de l'utilisateur
    if (user := auth.check_session(db, request, serializer)) is None:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    # Récupérer le mot de passe à supprimer
    password_entry = db.query(PasswordEntry).filter(PasswordEntry.id == password_id).first()

    if not password_entry:
        return {"message": "Password entry not found"}

    # Supprimer le mot de passe de la DB
    db.delete(password_entry)
    db.commit()

    return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)

@vault_router.post("/update_password/{password_id}")
async def update_password(
    request: Request,
    password_id: int,
    title: str = Form(...),
    password: str = Form(...),
    username: str = Form(...),
    email: str = Form(...),
    url: str = Form(...),
    db: Session = Depends(database.get_db)
):
    # Vérifier la session de l'utilisateur
    if (user := auth.check_session(db, request, serializer)) is None:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    # Récupérer le mot de passe à mettre à jour
    password_entry = db.query(PasswordEntry).filter(PasswordEntry.id == password_id).first()

    if not password_entry:
        return {"message": "Password entry not found"}

    aes_key = bytes.fromhex(request.session.get("key"))

    # Mettre à jour les champs
    password_entry.title = crypto.encrypt_password(title, aes_key)
    password_entry.encrypted_password = crypto.encrypt_password(password, aes_key)
    password_entry.username = crypto.encrypt_password(username, aes_key)
    password_entry.email = crypto.encrypt_password(email, aes_key)
    password_entry.url = crypto.encrypt_password(url, aes_key)

    # Enregistrer les modifications
    db.commit()

    return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)






