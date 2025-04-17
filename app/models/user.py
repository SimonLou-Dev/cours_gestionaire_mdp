"""Contient la définition du modèle User."""

import os
from typing import Any

from sqlalchemy import Column, Integer, String
from sqlalchemy.orm import relationship

from app.database import Base


class User(Base):
    """Représente un utilisateur dans la base de données.

    Attributs :
        username (str) : Nom d'utilisateur de l'utilisateur.
        password (str) : Mot de passe de l'utilisateur.
        totp_secret (str) : Secret TOTP pour l'authentification à deux facteurs.
        id (int) : Identifiant unique de l'utilisateur (généré automatiquement).
        user_salt (str) : Sel utilisé pour le hachage du mot de passe.
        passwords (list) : Liste des entrées de mot de passe associées à l'utilisateur.
    """

    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    totp_secret = Column(String, nullable=False)
    user_salt = Column(String, nullable=False)

    passwords = relationship(
        "PasswordEntry",
        back_populates="owner",
        cascade="all, delete",
    )

    def __init__(self, username: str, password: str, totp_secret: str, **kw: Any):
        """Initialise un nouvel utilisateur avec les informations fournies.

        Arguments:
            username (str) : Nom d'utilisateur de l'utilisateur.
            password (str) : Mot de passe de l'utilisateur.
            totp_secret (str) : Secret TOTP pour l'authentification à deux facteurs.
            **kw : Autres arguments supplémentaires.

        """
        super().__init__(**kw)
        self.username = username
        from app.services import auth

        self.hashed_password = auth.hash_password(password)
        self.totp_secret = totp_secret
        self.user_salt = os.urandom(16).hex()
