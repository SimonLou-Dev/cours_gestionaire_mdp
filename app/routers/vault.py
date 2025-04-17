"""Ce fichier contient toutes les routes relatives au coffre fort."""

import multiprocessing
import uuid
from base64 import urlsafe_b64decode
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.params import Form
from itsdangerous import URLSafeTimedSerializer
from sqlalchemy.orm import Session
from starlette import status
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse
from starlette.templating import Jinja2Templates

from app import database
from app.models import PasswordEntry
from app.models.password import SharedPasswordEntry
from app.services import auth, password_utils
from app.services.crypto import PasswordAESEncryption, SharedPasswordEncryption

vault_router = APIRouter()
serializer = URLSafeTimedSerializer("SECRET_KEY")
templates = Jinja2Templates(directory="app/templates")


@vault_router.post("/add_password")
async def add_password(
    request: Request,
    title: Annotated[str, Form()] = ...,
    password: Annotated[str, Form()] = ...,
    username: Annotated[str, Form()] = ...,
    email: Annotated[str, Form()] = ...,
    url: Annotated[str, Form()] = ...,
    db: Session = Depends(database.get_db),
) -> RedirectResponse:
    """Enregistre un mot de passe dans la base de données.

    Arguments:
        request: Requête FastAPI
        title: Titre du mot de passe
        password: Mot de passe à enregistrer
        username: Nom d'utilisateur associé
        email: Email associé
        url: URL associée
        db: Session de base de données

    Returns:
        RedirectResponse: Redirection vers le tableau de bord

    """
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
        url=url,
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
    db: Session = Depends(database.get_db),
) -> RedirectResponse:
    """Permet de supprimer un mot de passe de la base de données.

    Arguments:
        request: Requête FastAPI
        password_id: ID du mot de passe à supprimer
        db: Session de base de données

    Returns:
        RedirectResponse: Redirection vers le tableau de bord

    """
    # Vérifier la session de l'utilisateur
    if (auth.check_session(db, request, serializer)) is None:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    # Récupérer le mot de passe à supprimer
    password_entry = (
        db.query(PasswordEntry).filter(PasswordEntry.id == password_id).first()
    )

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
    title: Annotated[str, Form()] = ...,
    password: Annotated[str, Form()] = ...,
    username: Annotated[str, Form()] = ...,
    email: Annotated[str, Form()] = ...,
    url: Annotated[str, Form()] = ...,
    db: Session = Depends(database.get_db),
) -> RedirectResponse:
    """Met à jour un mot de passe dans la base de données.

    Arguments:
        request: Requête FastAPI
        password_id: ID du mot de passe à mettre à jour
        title: Nouveau titre du mot de passe
        password: Nouveau mot de passe
        username: Nouveau nom d'utilisateur
        email: Nouvel email
        url: Nouvelle URL
        db: Session de base de données

    Returns:
        RedirectResponse: Redirection vers le tableau de bord

    """
    # Vérifier la session de l'utilisateur
    if auth.check_session(db, request, serializer) is None:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    # Récupérer le mot de passe à mettre à jour
    password_entry = (
        db.query(PasswordEntry).filter(PasswordEntry.id == password_id).first()
    )

    if not password_entry:
        return {"message": "Password entry not found"}

    aes_key = bytes.fromhex(request.session.get("key"))

    # Mettre à jour les champs
    password_entry.title = PasswordAESEncryption.encrypt_password(title, aes_key)
    password_entry.encrypted_password = PasswordAESEncryption.encrypt_password(
        password,
        aes_key,
    )
    password_entry.username = PasswordAESEncryption.encrypt_password(username, aes_key)
    password_entry.email = PasswordAESEncryption.encrypt_password(email, aes_key)
    password_entry.url = PasswordAESEncryption.encrypt_password(url, aes_key)
    password_entry.complexity = password_utils.calculate_password_strength(password)

    # Enregistrer les modifications
    db.commit()

    return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)


@vault_router.post("/generator")
async def generator(
    request: Request,
    length: int = Form(...),
    use_special_chars: Annotated[bool, Form()] = False,
    use_digits: Annotated[bool, Form()] = False,
    use_uppercase: Annotated[bool, Form()] = False,
    use_lowercase: Annotated[bool, Form()] = False,
    num_passwords: Annotated[int, Form()] = ...,
) -> HTMLResponse:
    """Génère un mot de passe aléatoire en fonction des critères spécifiés.

    Arguments:
        request (Request): Requête FastAPI
        length (int): Longueur du mot de passe
        use_special_chars (bool): Inclure des caractères spéciaux
        use_digits (bool): Inclure des chiffres
        use_uppercase (bool): Inclure des lettres majuscules
        use_lowercase (bool): Inclure des lettres minuscules
        num_passwords (int): Nombre de mots de passe à générer

    Returns:
        HTMLResponse: Réponse HTML avec les mots de passe générés

    """
    with multiprocessing.Pool(processes=multiprocessing.cpu_count()) as pool:
        # Création d'une liste de paramètres pour chaque mot de passe à générer
        try:
            args = [
                (length, use_special_chars, use_digits, use_uppercase, use_lowercase),
            ] * num_passwords
            passwords = pool.starmap(password_utils.generate_password, args)
        except ValueError:
            return templates.TemplateResponse(
                "generator.html.j2",
                {
                    "request": request,
                    "errors": [
                        "Vous devez sélectionner au moins un critère de caractère pour générer un mot de passe.",
                    ],
                    "criteria": {
                        "length": length,
                        "num_passwords": "on" if num_passwords else "off",
                        "use_special_chars": "on" if use_special_chars else "off",
                        "use_digits": "on" if use_digits else "off",
                        "use_uppercase": "on" if use_uppercase else "off",
                        "use_lowercase": "on" if use_lowercase else "off",
                    },
                },
            )

    return templates.TemplateResponse(
        "generator.html.j2",
        {
            "request": request,
            "criteria": {
                "length": length,
                "num_passwords": "on" if num_passwords else "off",
                "use_special_chars": "on" if use_special_chars else "off",
                "use_digits": "on" if use_digits else "off",
                "use_uppercase": "on" if use_uppercase else "off",
                "use_lowercase": "on" if use_lowercase else "off",
            },
            "passwords": passwords,
        },
    )


@vault_router.post("/passwords/{password_id}/share")
async def share_password(
    request: Request,
    password_id: int,
    validity_hours: Annotated[int, Form()] = ...,
    db: Session = Depends(database.get_db),
) -> Response:
    """Permet de partager un mot de passe avec un lien temporaire.

    Arguments:
        request: Requête FastAPI
        password_id: ID du mot de passe à partager
        validity_hours: Durée de validité du lien en heures
        db: Session de base de données

    Returns:
        HTMLResponse: Réponse HTML avec le lien de partage

    """
    if (user := auth.check_session(db, request, serializer)) is None:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    # Vérifier que l'entrée appartient à l'utilisateur
    password_entry = (
        db.query(PasswordEntry)
        .filter(
            PasswordEntry.id == password_id,
            PasswordEntry.user_id == user.id,
        )
        .first()
    )

    if not password_entry:
        raise HTTPException(
            status_code=404,
            detail="Entrée de mot de passe introuvable",
        )

    # Récupérér la clée de l'user
    aes_key = bytes.fromhex(request.session.get("key"))

    if not aes_key:
        raise HTTPException(status_code=401, detail="AES key missing from session")

    shared_entry, token = SharedPasswordEncryption.encrypt_shared_password(
        password_entry=password_entry,
        aes_key=aes_key,
        db=db,
        validity_hours=validity_hours,
    )

    share_link = f"{request.base_url}share/{shared_entry.uuid}/{token}"

    return templates.TemplateResponse(
        "share_confirmation.html.j2",
        {
            "share_link": share_link,
            "expiry_date": shared_entry.expiry_date,
            "request": request,
            "shared_entry": shared_entry,
            "token": token,
        },
    )


@vault_router.get("/share/{p_uuid}/{token}")
async def retrieve_shared_password(
    request: Request,
    p_uuid: str,
    token: str,
    db: Session = Depends(database.get_db),
) -> HTMLResponse:
    """Permet de récupérer un mot de passe partagé.

    Arguments:
        request: Requête FastAPI
        p_uuid: UUID de l'entrée partagée
        token: Token de partage
        db: Session de base de données

    Returns:
        HTMLResponse: Réponse HTML avec le mot de passe partagé

    """
    # Récupérer l'entrée partagée
    shared_entry = (
        db.query(SharedPasswordEntry)
        .filter(
            SharedPasswordEntry.uuid == uuid.UUID(p_uuid),
            SharedPasswordEntry.expiry_date > datetime.utcnow(),
        )
        .first()
    )

    if not shared_entry:
        raise HTTPException(
            status_code=404,
            detail="Entrée partagée introuvable ou expirée",
        )

    # Décoder le token pour récupérer l'UUID
    try:
        padding = "=" * (-len(token) % 4)
        decoded_token = urlsafe_b64decode(token + padding)
        share_token = decoded_token.decode()
    except Exception:
        raise HTTPException(status_code=400, detail="Token invalide")

    try:
        shared_key = SharedPasswordEncryption.derive_share_token(
            shared_entry.share_token_id,
            share_token,
        )

        # Déchiffrer les données
        decrypted_data = {
            "title": PasswordAESEncryption.decrypt_password(
                shared_entry.encrypted_title,
                shared_key,
            ),
            "username": PasswordAESEncryption.decrypt_password(
                shared_entry.encrypted_username,
                shared_key,
            ),
            "email": PasswordAESEncryption.decrypt_password(
                shared_entry.encrypted_email,
                shared_key,
            ),
            "password": PasswordAESEncryption.decrypt_password(
                shared_entry.encrypted_password,
                shared_key,
            ),
            "url": PasswordAESEncryption.decrypt_password(
                shared_entry.encrypted_url,
                shared_key,
            ),
            "expiry_date": shared_entry.expiry_date,
        }

        return templates.TemplateResponse(
            "shared_password.html.j2",
            {"request": request, "shared_entry": decrypted_data},
        )
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Erreur lors de la récupération de l'entrée partagée",
        )
