"""Services de chiffrement pour le stockage sécurisé des données sensibles."""

import datetime
import os
import secrets
from base64 import b64decode, b64encode, urlsafe_b64encode
from datetime import timedelta

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from sqlalchemy.orm import Session

from app.models.password import PasswordEntry, SharedPasswordEntry


class PasswordAESEncryption:
    """Classe pour le chiffrement et le déchiffrement des mots de passe avec AES-256."""

    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        """Permet de dériver une clé AES à partir d'un mot de passe et d'un sel.

        Arguments:
            password (str): Le mot de passe de l'utilisateur.
            salt (bytes): Le sel utilisé pour dériver la clé.

        Returns:
            bytes: La clé AES dérivée.

        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend(),
        )
        return kdf.derive(password.encode())

    @staticmethod
    def encrypt_password(password: str, aes_key: bytes) -> str:
        """Chiffre le mot de passe pour le vault en utilisant AES-256 en mode CBC.

        Arguments:
            password (str): Le mot de passe à chiffrer.
            aes_key (bytes): La clé AES de l'utilisateur.

        Returns:
            str: Le mot de passe chiffré en base64.

        """
        iv = os.urandom(16)  # Générer un IV unique pour chaque mot de passe

        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(password.encode()) + padder.finalize()

        # Créer le chiffreur AES avec l'IV
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.CBC(iv),
            backend=default_backend(),
        )
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        # Concaténer l'IV et le mot de passe chiffré (encrypted_data)
        full_data = iv + encrypted_data
        return b64encode(full_data).decode()  # Encodé en base64 pour stocker facilement

    @staticmethod
    def decrypt_password(encrypted_password: str, aes_key: bytes) -> str:
        """Déchiffre le mot de passe chiffré en utilisant AES-256 en mode CBC.

        Arguments:
            encrypted_password (str): Le mot de passe chiffré en base64.
            aes_key (bytes): La clé AES de l'utilisateur.

        Returns:
            str: Le mot de passe déchiffré.

        """
        encrypted_data = b64decode(encrypted_password)

        iv = encrypted_data[:16]  # L'IV est dans les 16 premiers octets
        encrypted_content = encrypted_data[16:]  # Le reste est le mot de passe chiffré

        # Créer le déchiffreur AES avec l'IV
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.CBC(iv),
            backend=default_backend(),
        )
        decryptor = cipher.decryptor()
        decrypted_padded = decryptor.update(encrypted_content) + decryptor.finalize()

        # Supprimer le padding du mot de passe déchiffré
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(decrypted_padded) + unpadder.finalize()

        return data.decode()


class SharedPasswordEncryption:
    """Classe pour le chiffrement et le déchiffrement des mots de passe partagés."""

    @staticmethod
    def derive_share_token(share_token_id: str, token: str) -> bytes:
        """Dérive une clé de partage à partir de l'UUID et du token.

        Arguments:
            share_token_id (str): L'UUID du partage.
            token (str): Le token spécifique au partage.

        Returns:
            bytes: La clé de partage dérivée.

        """
        dkdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # Taille de la clé AES (256 bits)
            salt=(share_token_id + token).encode(),  # Combinaison de l'UUID et du token
            iterations=100000,
            backend=default_backend(),
        )
        return dkdf.derive(token.encode())

    @staticmethod
    def encrypt_shared_password(
        password_entry: type[PasswordEntry],
        aes_key: bytes,
        db: Session,
        validity_hours: int = 24,
    ) -> tuple[SharedPasswordEntry, str]:
        """Chiffre les données du mot de passe partagé et les enregistre.

        Arguments:
            password_entry (Type[PasswordEntry]): L'entrée de mot de passe à partager.
            aes_key (bytes): La clé AES de l'utilisateur.
            db (Session): La session de base de données.
            validity_hours (int): Durée de validité du partage en heures.

        Returns:
            tuple[SharedPasswordEntry, str]: L'entrée et le token URL.

        """
        # Déchiffrer les données originales
        decrypted_title = PasswordAESEncryption.decrypt_password(
            password_entry.title,
            aes_key,
        )
        decrypted_username = PasswordAESEncryption.decrypt_password(
            password_entry.username,
            aes_key,
        )
        decrypted_email = PasswordAESEncryption.decrypt_password(
            password_entry.email,
            aes_key,
        )
        decrypted_password = PasswordAESEncryption.decrypt_password(
            password_entry.encrypted_password,
            aes_key,
        )
        decrypted_url = (
            PasswordAESEncryption.decrypt_password(password_entry.url, aes_key)
            if password_entry.url
            else None
        )

        # Générer un identifiant unique pour ce partage
        share_token_id = secrets.token_urlsafe(16)

        # Générer un token spécifique pour chaque partage
        share_token = secrets.token_urlsafe(16)

        # Dériver une clé de partage unique à partir de l'UUID et du token
        shared_key = SharedPasswordEncryption.derive_share_token(
            share_token_id,
            share_token,
        )

        # Chiffrer les données
        shared_entry = SharedPasswordEntry(
            encrypted_title=PasswordAESEncryption.encrypt_password(
                decrypted_title,
                shared_key,
            ),
            encrypted_username=PasswordAESEncryption.encrypt_password(
                decrypted_username,
                shared_key,
            ),
            encrypted_email=PasswordAESEncryption.encrypt_password(
                decrypted_email,
                shared_key,
            ),
            encrypted_password=PasswordAESEncryption.encrypt_password(
                decrypted_password,
                shared_key,
            ),
            encrypted_url=PasswordAESEncryption.encrypt_password(
                decrypted_url,
                shared_key,
            )
            if decrypted_url
            else None,
            expiry_date=datetime.datetime.now(tz=datetime.timezone.utc)
            + timedelta(hours=validity_hours),
            original_entry_id=password_entry.id,
            share_token_id=share_token_id,  # Stocker l'identifiant, pas le token lui-même
        )

        # Enregistrer l'entrée partagée dans la base de données
        db.add(shared_entry)
        db.commit()
        db.refresh(shared_entry)

        url_token = urlsafe_b64encode(share_token.encode()).decode().rstrip("=")

        # Ré-encode le token pour l'URL
        return shared_entry, url_token
