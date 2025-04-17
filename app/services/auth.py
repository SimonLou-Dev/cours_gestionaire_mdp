"""Ce service gère l'authentification des utilisateurs et la gestion des sessions."""
from typing import Optional

from fastapi import Response
from itsdangerous import URLSafeTimedSerializer as Serializer
from passlib.context import CryptContext

from app.models import user as models
from app.models.user import User

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    """Hache le mot de passe en utilisant bcrypt.

    Arguments:
        password (str): Le mot de passe à hacher.

    Returns:
        str: Le mot de passe haché.

    """
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Vérifie si le mot de passe en clair correspond au mot de passe haché.

    Arguments:
        plain_password (str): Le mot de passe en clair à vérifier.
        hashed_password (str): Le mot de passe haché à comparer.

    Returns:
        bool: True si les mots de passe correspondent, False sinon.

    """
    return pwd_context.verify(plain_password, hashed_password)


def authenticate_user(db, username: str, password: str) -> Optional[User]:
    """Authentifie l'utilisateur en vérifiant son nom d'utilisateur et son mot de passe.

    Arguments:
        db (Session): La session de base de données.
        username (str): Le nom d'utilisateur à authentifier.
        password (str): Le mot de passe à vérifier.

    Returns:
        Optional[User]: L'utilisateur authentifié si les informations sont correctes, None sinon.

    """
    user = db.query(models.User).filter(models.User.username == username).first()
    if not user or not verify_password(password, user.hashed_password):
        return None
    return user


def check_session(db, request, serializer: Serializer) -> Optional[User]:
    """Vérifie si l'utilisateur est authentifié en vérifiant le cookie de session.

    Arguments:
        db (Session): La session de base de données.
        request: La requête HTTP contenant le cookie de session.
        serializer (Serializer): Le sérialiseur pour gérer les cookies de session.

    Returns:
        Optional[User]: L'utilisateur authentifié si le cookie est valide, None sinon.

    """
    session_token = request.cookies.get("session_token")
    if not session_token:
        return None

    # Désérialiser le jeton pour obtenir l'ID utilisateur
    user_data = serializer.loads(session_token)
    user_id = user_data.get("user_id")

    # Chercher l'utilisateur dans la base de données
    user = db.query(User).filter(models.User.id == user_id).first()
    if not user:
        return None

    return user


def register_session_cookie(
    response: Response,
    user: User,
    serializer: Serializer,
) -> Response:
    """Enregistre le cookie de session pour l'utilisateur.

    Arguments:
        response (Response): La réponse HTTP à laquelle ajouter le cookie.
        user (User): L'utilisateur pour lequel enregistrer le cookie.
        serializer (Serializer): Le sérialiseur pour gérer les cookies de session.

    Returns:
        Response: La réponse HTTP avec le cookie de session ajouté.

    """
    # Sérialiser l'ID utilisateur pour le cookie
    user_data = {"user_id": user.id}
    session_token = serializer.dumps(obj=user_data)

    # Enregistrer le jeton dans un cookie
    response.set_cookie(
        key="session_token",
        value=session_token,
        httponly=True,  # Empêche l'accès via JavaScript
        max_age=3600,  # Durée de vie de 1 heure
        secure=True,  # Assure que le cookie soit envoyé uniquement via HTTPS
        samesite="Strict",  # Sécurise le cookie pour éviter les attaques CSRF
    )
    return response
