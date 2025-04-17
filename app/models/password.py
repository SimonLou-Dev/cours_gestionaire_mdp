""""Ici se trouvent les modèles de données pour les mots de passe et les entrées de mot de passe partagées."""
from typing import Any
import uuid
from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, Boolean, UUID
from sqlalchemy.orm import relationship
from app.database import Base
from app.dto.passwords import PasswordOut



class PasswordEntry(Base):
    """

    Attributs :
        id (int): Identifiant unique de l'entrée de mot de passe.
        title (str): Titre associé à l'entrée de mot de passe, comme le nom du service. (chiffré)
        username (str): Nom d'utilisateur associé à l'entrée. (chiffré)
        email (str): Adresse e-mail liée à l'entrée. (chiffré)
        encrypted_password (str): Mot de passe chiffré associé à l'entrée. (chiffré)
        url (str): URL du service lié à l'entrée de mot de passe. (chiffré)
        user_id (int): Identifiant de l'utilisateur auquel l'entrée appartient.
        complexity (int): Indicateur de la complexité du mot de passe, calculé lors de la création de l'entrée.
        owner (User): Relation avec l'utilisateur propriétaire de l'entrée de mot de passe.

    Méthodes:
        __init__(title, username, email, url, password, user, aes_key, **kw):
            Initialise une nouvelle entrée de mot de passe, en chiffrant les informations sensibles.

        get_decrypted(aes_key):
            Récupère les informations de l'entrée de mot de passe déchiffrées à l'aide de la clé AES fournie.
    """



    from app.models.user import User

    __tablename__ = "passwords"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    username = Column(String, nullable=False)
    email = Column(String, nullable=False)
    encrypted_password = Column(String, nullable=False)
    url = Column(String, nullable=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    complexity = Column(Integer, nullable=True)

    owner = relationship("User", back_populates="passwords")

    def __init__(self, title: str, username: str, email: str, url: str, password: str, user: User, aes_key: bytes,  **kw: Any):
        """
        Initialise une nouvelle entrée de mot de passe, en chiffrant les informations sensibles.
        Arguments:
            title (str): Titre de l'entrée de mot de passe.
            username (str): Nom d'utilisateur associé à l'entrée.
            email (str): Adresse e-mail liée à l'entrée.
            url (str): URL du service associé.
            password (str): Mot de passe à chiffrer.
            user (User): Utilisateur propriétaire de l'entrée de mot de passe.
            aes_key (bytes): Clé AES utilisée pour chiffrer les informations.
            **kw (Any): Autres arguments supplémentaires à passer au constructeur de la classe de base.
        """


        from app.services import password_utils
        super().__init__(**kw)

        from app.services.crypto import PasswordAESEncryption
        self.title = PasswordAESEncryption.encrypt_password(title, aes_key)
        self.encrypted_password = PasswordAESEncryption.encrypt_password(password, aes_key)
        self.username = PasswordAESEncryption.encrypt_password(username, aes_key)
        self.email = PasswordAESEncryption.encrypt_password(email, aes_key)
        self.url = PasswordAESEncryption.encrypt_password(url, aes_key)

        self.complexity = password_utils.calculate_password_strength(password)
        self.owner = user


    def get_decrypted(self, aes_key: bytes) -> "PasswordOut":
        """Récupère les informations de l'entrée de mot de passe déchiffrées à l'aide de la clé AES fournie.

        Arguments:
            aes_key (bytes): Clé AES utilisée pour déchiffrer les informations.
        Return:
            PasswordOut: Un objet contenant les informations déchiffrées de l'entrée de mot de passe.
        """

        from app.services.crypto import PasswordAESEncryption
        return PasswordOut(
            id=self.id,
            password=PasswordAESEncryption.decrypt_password(self.encrypted_password, aes_key),
            title=PasswordAESEncryption.decrypt_password(self.title, aes_key),
            username=PasswordAESEncryption.decrypt_password(self.username, aes_key),
            email=PasswordAESEncryption.decrypt_password(self.email, aes_key),
            url=PasswordAESEncryption.decrypt_password(self.url, aes_key),
            complexity=self.complexity
        )


class SharedPasswordEntry(Base):
    """
    Attributs :
        id (int): Identifiant unique de l'entrée de mot de passe partagée.
        uuid (UUID): Identifiant unique universel pour l'entrée partagée.
        encrypted_title (str): Titre chiffré de l'entrée de mot de passe partagée.
        encrypted_username (str): Nom d'utilisateur chiffré.
        encrypted_email (str): Adresse e-mail chiffrée.
        encrypted_password (str): Mot de passe chiffré.
        encrypted_url (str): URL chiffrée du service associé.
        expiry_date (datetime): Date d'expiration de l'entrée partagée.
        original_entry_id (int): Identifiant de l'entrée de mot de passe d'origine.
        share_token_id (str): Identifiant unique pour le système de partage.
    """


    __tablename__ = "shared_password_entries"

    id = Column(Integer, primary_key=True, index=True)
    uuid = Column(UUID(as_uuid=True), default=uuid.uuid4, unique=True, index=True, nullable=False)

    # Données chiffrées
    encrypted_title = Column(String, nullable=False)
    encrypted_username = Column(String, nullable=False)
    encrypted_email = Column(String, nullable=False)
    encrypted_password = Column(String, nullable=False)
    encrypted_url = Column(String, nullable=True)

    # Métadonnées
    expiry_date = Column(DateTime, nullable=False)
    original_entry_id = Column(Integer, ForeignKey("passwords.id"))

    # Identifiant unique pour le système de partage
    share_token_id = Column(String, nullable=False)  # Un identifiant pour retrouver le token, pas le token lui-même