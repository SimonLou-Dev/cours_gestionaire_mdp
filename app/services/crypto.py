import logging
import secrets
from datetime import timedelta, datetime
from hashlib import pbkdf2_hmac
from typing import Type

import bcrypt
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from base64 import b64encode, b64decode, urlsafe_b64encode, urlsafe_b64decode
import os

from sqlalchemy.orm import Session

from app.models.password import PasswordEntry, SharedPasswordEntry


class PasswordEncryption():
    """
    Classe pour le chiffrement et le déchiffrement des mots de passe (connection).
    """
    @staticmethod
    def hash_password(password: str) -> str:
        """
        Hash le mot de passe en utilisant bcrypt (pour le stockage sécurisé dans la DB)

        :param password: Le mot de passe à hasher

        :return: Le mot de passe hashé
        :rtype: str
        """
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    @staticmethod
    def verify_password(stored_hash: str, password: str) -> bool:
        """
        Vérifie si le mot de passe fourni correspond au hash stocké.


        :param stored_hash: Le hash du mot de passe stocké
        :param password: Le mot de passe à vérifier

        :return: True si le mot de passe correspond, sinon False
        :rtype: bool
        """
        return bcrypt.checkpw(password.encode(), stored_hash.encode())



class PasswordAESEncryption():
    """
    Classe pour le chiffrement et le déchiffrement des mots de passe avec AES-256 (pour  le vault)
    """

    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        """
        Permet de dériver une clé AES à partir d'un mot de passe et d'un sel.

        :param: password: Mot de passe de l'utilisateur (en clair)
        :param: salt: Sel utilisé pour dériver la clé

        :return bytes: La clé dérivée
        :rtype: bytes
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),  # Utilisation de SHA256 pour générer la clé
            length=32,  # La taille de la clé AES (256 bits)
            salt=salt,
            iterations=100000,  # Nombre d'itérations pour rendre l'attaque par force brute plus difficile
            backend=default_backend()
        )
        return kdf.derive(password.encode())


    @staticmethod
    def encrypt_password(password: str, aes_key: bytes) -> str:
        """
        Chiffre le mot de passe pour le vault en utilisant AES-256 en mode CBC.

        :param password: Le mot de passe à chiffrer
        :param aes_key: La clé AES dérivée à partir du mot de passe de l'utilisateur
        :return: Le mot de passe chiffré en base64
        :rtype: str
        """

        iv = os.urandom(16)  # Générer un IV unique pour chaque mot de passe

        # Padding pour que la longueur soit un multiple de 16 octets (taille de bloc AES)
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(password.encode()) + padder.finalize()

        # Créer le chiffreur AES avec l'IV
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        # Concaténer l'IV et le mot de passe chiffré (encrypted_data)
        full_data = iv + encrypted_data
        return b64encode(full_data).decode()  # Encodé en base64 pour stocker facilement

    @staticmethod
    def decrypt_password(encrypted_password: str, aes_key: bytes) -> str:

        """
        Déchiffre le mot de passe chiffré en utilisant AES-256 en mode CBC.
        :param encrypted_password: Mot de passe chiffré en base64
        :param aes_key: Clé AES dérivée à partir du mot de passe de l'utilisateur
        :return: mot de passe déchiffré
        :rtype: str
        """
        encrypted_data = b64decode(encrypted_password)

        iv = encrypted_data[:16]  # L'IV est dans les 16 premiers octets
        encrypted_content = encrypted_data[16:]  # Le reste est le mot de passe chiffré

        # Créer le déchiffreur AES avec l'IV
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded = decryptor.update(encrypted_content) + decryptor.finalize()

        # Supprimer le padding du mot de passe déchiffré
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(decrypted_padded) + unpadder.finalize()

        return data.decode()


class SharedPasswordEncryption():
    """
    Classe pour le chiffrement et le déchiffrement des mots de passe partagés.
    """

    @staticmethod
    def derive_share_token(share_token_id: str, token: str) -> bytes:

        """
        Dérive une clé de partage à partir de l'UUID (identifiant du partage) et du token.

        :param share_token_id: Identifiant unique du partage
        :param token: Token unique pour chaque partage, utilisé pour dériver la clé
        :return: Clé de partage dérivée
        :rtype: bytes
        """

        dkdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # Taille de la clé AES (256 bits)
            salt=(share_token_id + token).encode(),  # Combinaison de l'UUID et du token
            iterations=100000,
            backend=default_backend()
        )
        return dkdf.derive(token.encode())

    @staticmethod
    def encrypt_shared_password(
            password_entry: Type[PasswordEntry],
            aes_key: bytes,
            db: Session,
            validity_hours: int = 24,
    ) -> tuple[SharedPasswordEntry, str]:
        """
        Chiffre les données du mot de passe partagé et les enregistre dans la base de données.
        :param password_entry: "PasswordEntry" à partager
        :param aes_key: clé AES dérivée à partir du mot de passe de l'utilisateur
        :param db: "Session" de la base de données
        :param validity_hours: Durée de validité du partage en heures
        :return: Entrée partagée et token
        :rtype : tuple[SharedPasswordEntry, str] Entrée partagée et token
        """


        # Déchiffrer les données originales
        decrypted_title = PasswordAESEncryption.decrypt_password(password_entry.title, aes_key)
        decrypted_username = PasswordAESEncryption.decrypt_password(password_entry.username, aes_key)
        decrypted_email = PasswordAESEncryption.decrypt_password(password_entry.email, aes_key)
        decrypted_password = PasswordAESEncryption.decrypt_password(password_entry.encrypted_password, aes_key)
        decrypted_url = PasswordAESEncryption.decrypt_password(password_entry.url, aes_key) if password_entry.url else None

        # Générer un identifiant unique pour ce partage
        share_token_id = secrets.token_urlsafe(16)

        # Générer un token spécifique pour chaque partage
        share_token = secrets.token_urlsafe(16)

        # Dériver une clé de partage unique à partir de l'UUID et du token
        shared_key = SharedPasswordEncryption.derive_share_token(share_token_id, share_token)

        # Chiffrer les données
        shared_entry = SharedPasswordEntry(
            encrypted_title=PasswordAESEncryption.encrypt_password(decrypted_title, shared_key),
            encrypted_username=PasswordAESEncryption.encrypt_password(decrypted_username, shared_key),
            encrypted_email=PasswordAESEncryption.encrypt_password(decrypted_email, shared_key),
            encrypted_password=PasswordAESEncryption.encrypt_password(decrypted_password, shared_key),
            encrypted_url=PasswordAESEncryption.encrypt_password(decrypted_url, shared_key) if decrypted_url else None,
            expiry_date=datetime.utcnow() + timedelta(hours=validity_hours),
            original_entry_id=password_entry.id,
            share_token_id=share_token_id  # Stocker l'identifiant, pas le token lui-même
        )

        # Enregistrer l'entrée partagée dans la base de données
        db.add(shared_entry)
        db.commit()
        db.refresh(shared_entry)

        url_token = urlsafe_b64encode(share_token.encode()).decode().rstrip("=")

        logging.warn(f"Shared token URL: {url_token}")
        logging.warn(f"Shared token en clair: {share_token}")
        logging.warn(f"Token ID stocké : {shared_entry.share_token_id}")

        # Ré-encode le token pour l'URL
        return shared_entry, url_token

