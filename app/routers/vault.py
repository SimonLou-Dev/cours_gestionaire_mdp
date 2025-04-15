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

    # Récupérer le salt en session
    aes_key = bytes.fromhex(request.session.get("key"))

    # Enregistrer le mot de passe dans la base de données

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







