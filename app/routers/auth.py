"""Contient de l'authentification et de l'autorisation."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated

from fastapi import APIRouter, Depends, Form, Request, status
from itsdangerous import URLSafeTimedSerializer
from starlette.responses import HTMLResponse, RedirectResponse
from starlette.templating import Jinja2Templates

from app import database
from app.models.user import User
from app.services import auth, totp
from app.services.crypto import PasswordAESEncryption

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

serializer = URLSafeTimedSerializer("SECRET_KEY")
templates = Jinja2Templates(directory="app/templates")

auth_router = APIRouter()


# Logout
@auth_router.get("/logout")
def logout(request: Request) -> HTMLResponse:
    """Déconnexion de l'utilisateur et suppression de la session.

    Arguments:
        request (Request): La requête HTTP.

    Returns:
        HTMLResponse : Redirection vers la page de connexion.

    """
    response = RedirectResponse(url="/login")
    response.delete_cookie("session_token")
    request.session.clear()  # Supprime toute la session
    return response


@auth_router.post("/login")
def login(
    request: Request,
    username: Annotated[str, Form()] = ...,
    password: Annotated[str, Form()] = ...,
    totp_token: Annotated[str, Form()] = ...,
    db: Session = Depends(database.get_db),
) -> HTMLResponse:
    """Authentifie l'utilisateur.

    Arguments:
        request (Request): La requête HTTP.
        username (str): Nom d'utilisateur.
        password (str): Mot de passe.
        totp_token (str): Code TOTP.
        db (Session): Session de base de données.

    Returns:
        HTMLResponse: Redirection vers le dashboard ou la page de connexion en cas d'erreur.

    """
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
        return templates.TemplateResponse(
            "login.html.j2",
            {"request": request, "errors": errors},
        )

    # Authentification réussie
    aes_key = PasswordAESEncryption.derive_key(
        password,
        bytes.fromhex(db_user.user_salt),
    )
    response = RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)
    auth.register_session_cookie(response, db_user, serializer)

    request.session["key"] = aes_key.hex()  # Stocker la clé AES dans la session

    # Enregistrer le cookie de session et rediriger l'utilisateur
    return response


@auth_router.post("/register")
async def register(
    request: Request,
    username: Annotated[str, Form()] = ...,
    password: Annotated[str, Form()] = ...,
    db: Session = Depends(database.get_db),
) -> HTMLResponse:
    """Permet de créer un nouvel utilisateur.

    Arguments:
        request (Request) : La requête HTTP.
        username (str) : Nom d'utilisateur.
        password (str) : Mot de passe.
        db (Session) : Session de base de données.

    Returns:
        HTMLResponse : Redirection vers la page de confirmation ou affichage des erreurs.

    """
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
        return templates.TemplateResponse(
            "register.html.j2",
            {"request": request, "errors": errors},
        )

    totp_secret = totp.generate_totp_secret()

    new_user = User(
        username=username,
        password=password,
        totp_secret=totp_secret,
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    qr_code = totp.generate_qr_code(totp_secret, username)

    aes_key = PasswordAESEncryption.derive_key(
        password,
        bytes.fromhex(new_user.user_salt),
    )
    request.session["key"] = aes_key.hex()  # Stocker la clé AES dans la session

    return templates.TemplateResponse(
        "register_done.html.j2",
        {
            "request": request,
            "qr_code": qr_code,
            "secret": totp_secret,
            "user_id": new_user.id,
        },
    )


@auth_router.post("/verify_totp")
def verify_totp(
    request: Request,
    totp_token: Annotated[str, Form()] = ...,
    qr_code: Annotated[str, Form()] = ...,
    secret: Annotated[str, Form()] = ...,
    user_id: Annotated[str, Form()] = ...,
    db: Session = Depends(database.get_db),
) -> HTMLResponse:
    """Vérifie le code TOTP fourni par l'utilisateur lors de l'enregistrement.

    Arguments:
        request (Request): La requête HTTP.
        totp_token (str): Code TOTP fourni par l'utilisateur.
        qr_code (str): Code QR pour TOTP.
        secret (str): Secret TOTP.
        user_id (str): ID de l'utilisateur.
        db (Session): Session de base de données.

    Returns:
        HTMLResponse: Redirection vers le tableau de bord ou affichage des erreurs.

    """
    # vérification de la session
    if auth.check_session(db, request, serializer) is not None:
        return templates.TemplateResponse("dashboard.html.j2", {"request": request})

    db_user = db.query(User).filter(User.id == user_id).first()
    if not db_user:
        return templates.TemplateResponse(
            "register_done.html.j2",
            {
                "error_message": "Utilisateur non trouvé",
                "request": request,
                "user_id": user_id,
                "qr_code": qr_code,
                "secret": secret,
            },
        )

    if not totp.verify_totp(db_user.totp_secret, totp_token):
        return templates.TemplateResponse(
            "register_done.html.j2",
            {
                "error_message": "Code TOTP invalide",
                "request": request,
                "user_id": user_id,
                "qr_code": qr_code,
                "secret": secret,
            },
        )

    response = RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)
    auth.register_session_cookie(response, db_user, serializer)

    # Enregistrer le cookie de session et rediriger l'utilisateur
    return response
