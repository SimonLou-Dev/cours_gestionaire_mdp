import logging

from itsdangerous import URLSafeTimedSerializer as Serializer
from passlib.context import CryptContext
from app.models import user as models
from app.models.user import User

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def authenticate_user(db, username: str, password: str):
    user = db.query(models.User).filter(models.User.username == username).first()
    if not user or not verify_password(password, user.hashed_password):
        return None
    return user

def check_session(db, request, serializer: Serializer)-> User:
    session_token = request.cookies.get("session_token")
    logging.warn(f"Session token: {session_token}")
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

def register_session_cookie(response, user: User, serializer: Serializer):
    # Sérialiser l'ID utilisateur pour le cookie
    user_data = {"user_id": user.id}
    session_token = serializer.dumps(obj=user_data)

    # Enregistrer le jeton dans un cookie
    response.set_cookie(
        key="session_token",
        value=session_token,
        httponly=True,  # Empêche l'accès via JavaScript
        max_age=3600,  # Durée de vie de 1 heure
        secure=True,   # Assure que le cookie soit envoyé uniquement via HTTPS
        samesite="Strict"  # Sécurise le cookie pour éviter les attaques CSRF
    )
    return response