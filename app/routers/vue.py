"""Ce routeur gère l'acès et le rendu des vues de l'application."""
from http.client import HTTPException

from fastapi import APIRouter, Depends, Request, Response, status
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
async def login(
    request: Request,
    db: Session = Depends(database.get_db),
) -> RedirectResponse:
    """Affiche la page d'accueil de l'application.

    Arguments:
        request (Request): La requête HTTP.
        db (Session): Session de base de données.

    Returns:
        RedirectResponse: Redirection vers la page de connexion ou le tableau de bord.

    """
    if auth.check_session(db, request, serializer) is not None:
        return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)
    return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)


# VUES


@view_router.get("/register", response_class=HTMLResponse)
async def register(
    request: Request,
    db: Session = Depends(database.get_db),
) -> Response:
    """Affiche la page d'inscription de l'application.

    Arguments:
        request (Request): La requête HTTP.
        db (Session): Session de base de données.

    Returns:
        Response: La page d'inscription.

    """
    if auth.check_session(db, request, serializer) is not None:
        return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse("register.html.j2", {"request": request})


@view_router.get("/login", response_class=HTMLResponse)
async def login_view(
    request: Request,
    db: Session = Depends(database.get_db),
) -> Response:
    """Affiche la page de connexion de l'application.

    Arguments:
        request (Request): La requête HTTP.
        db (Session): Session de base de données.

    Returns:
        Response: La page de connexion.

    """
    # Vérifier la session de l'utilisateur
    if auth.check_session(db, request, serializer) is not None:
        return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse("login.html.j2", {"request": request})


@view_router.get("/dashboard", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    db: Session = Depends(database.get_db),
) -> Response:
    """Affiche le tableau de bord de l'application.

    Arguments:
        request (Request): La requête HTTP.
        db (Session): Session de base de données.

    Returns:
        Response: Le tableau de bord de l'application.

    """
    # Vérifier la session de l'utilisateur
    if (user :=auth.check_session(db, request, serializer)) is None:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    # Récupérer le salt en session
    aes_key = bytes.fromhex(request.session.get("key"))


    # Récupère tous les mots de passe de l'utilisateur
    passwords = db.query(PasswordEntry).filter(PasswordEntry.user_id == user.id).all()

    if not aes_key:
        raise HTTPException(status_code=401, detail="AES key missing from session")

    # Déchiffre les mots de passe avec la clé AES dérivée de la session
    decrypted_passwords = [entry.get_decrypted(aes_key) for entry in passwords]

    return templates.TemplateResponse(
        "dashboard.html.j2",
        {"request": request, "user": user, "passwords": decrypted_passwords},
    )


@view_router.get("/generator", response_class=HTMLResponse)
def generator(request: Request, db: Session = Depends(database.get_db)) -> Response:
    """Affiche la page de génération de mots de passe.

    Arguments:
        request (Request): La requête HTTP.
        db (Session): Session de base de données.

    Returns:
        Response: La page de génération de mots de passe.

    """
    if auth.check_session(db, request, serializer) is None:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    return templates.TemplateResponse(
        "generator.html.j2",
        {
            "request": request,
            "criteria": {
                "length": 16,
                "use_special_chars": "on",
                "use_digits": "on",
                "use_uppercase": "on",
                "use_lowercase": "on",
                "num_passwords": 5,
            },
            "password": [],
        },
    )
