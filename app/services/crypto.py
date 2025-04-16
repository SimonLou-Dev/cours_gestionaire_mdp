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
from base64 import b64encode, b64decode
import os

from sqlalchemy.orm import Session

from app.models import PasswordEntry
from app.models.password import SharedPasswordEntry


def derive_key(password: str, salt: bytes) -> bytes:
    # Création du KDF avec PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),  # Utilisation de SHA256 pour générer la clé
        length=32,  # La taille de la clé AES (256 bits)
        salt=salt,
        iterations=100000,  # Nombre d'itérations pour rendre l'attaque par force brute plus difficile
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Hashage du mot de passe avec bcrypt
def hash_password(password: str) -> str:
    """
    Hash le mot de passe en utilisant bcrypt (pour le stockage sécurisé dans la DB)
    """
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

# Vérification du mot de passe
def verify_password(stored_hash: str, password: str) -> bool:
    """
    Vérifie si le mot de passe fourni correspond au hash stocké.
    """
    return bcrypt.checkpw(password.encode(), stored_hash.encode())



# Chiffrement du mot de passe avec AES-256 et un code user_password
def encrypt_password(password: str, aes_key: bytes) -> str:
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

# Déchiffrement du mot de passe
def decrypt_password(encrypted_password: str, aes_key: bytes) -> str:
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

def derive_share_token(user_key: bytes, share_token_id: str) -> str:
    derived = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=share_token_id.encode(),
        info=b"password_share",
        backend=default_backend()
    )
    derived_key = derived.derive(user_key)

    # Convertir en token base64url pour l'URL
    return b64encode(derived_key).decode()

def encrypt_shared_password(
        password_entry: Type[PasswordEntry],
        aes_key: bytes,
        db: Session,
        validity_hours: int = 24,
) -> tuple[SharedPasswordEntry, str]:
    # Déchiffrer les données originales
    decrypted_title = decrypt_password(password_entry.title, aes_key)
    decrypted_username = decrypt_password(password_entry.username, aes_key)
    decrypted_email = decrypt_password(password_entry.email, aes_key)
    decrypted_password = decrypt_password(password_entry.encrypted_password, aes_key)
    decrypted_url = decrypt_password(password_entry.url, aes_key) if password_entry.url else None

    # Générer un identifiant unique pour ce partage
    share_token_id = secrets.token_urlsafe(16)

    token = derive_share_token(aes_key, share_token_id)
    shared_key = derive_key(token, share_token_id.encode())

    # Chiffrer les données
    shared_entry = SharedPasswordEntry(
        encrypted_title=encrypt_password(decrypted_title, shared_key),
        encrypted_username=encrypt_password(decrypted_username, shared_key),
        encrypted_email=encrypt_password(decrypted_email, shared_key),
        encrypted_password=encrypt_password(decrypted_password, shared_key),
        encrypted_url=encrypt_password(decrypted_url, shared_key) if decrypted_url else None,
        expiry_date=datetime.utcnow() + timedelta(hours=validity_hours),
        original_entry_id=password_entry.id,
        share_token_id=share_token_id  # Stocker l'identifiant, pas le token lui-même
    )

    # Enregistrer l'entrée partagée dans la base de données
    db.add(shared_entry)
    db.commit()
    db.refresh(shared_entry)

    return shared_entry, token

def update_shared_entries(
        original_entry: PasswordEntry,
        aes_key: bytes,
        db: Session
) -> int:
    # Déchiffrer les données originales mises à jour
    decrypted_title = decrypt_password(original_entry.title, aes_key)
    decrypted_username = decrypt_password(original_entry.username, aes_key)
    decrypted_email = decrypt_password(original_entry.email, aes_key)
    decrypted_password = decrypt_password(original_entry.encrypted_password, aes_key)
    decrypted_url = decrypt_password(original_entry.url, aes_key) if original_entry.url else None

    # Obtenir toutes les entrées partagées pour cette entrée originale
    shared_entries = db.query(SharedPasswordEntry).filter(
        SharedPasswordEntry.original_entry_id == original_entry.id,
        SharedPasswordEntry.expiry_date > datetime.utcnow()
    ).all()

    updated_count = 0

    for shared_entry in shared_entries:

        token = derive_share_token(aes_key, shared_entry.share_token_id)

        # Dériver la clé partagée à partir du token
        shared_key = derive_key(token, shared_entry.share_token_id.encode())

        # Mettre à jour les données chiffrées
        shared_entry.encrypted_title = encrypt_password(decrypted_title, shared_key)
        shared_entry.encrypted_username = encrypt_password(decrypted_username, shared_key)
        shared_entry.encrypted_email = encrypt_password(decrypted_email, shared_key)
        shared_entry.encrypted_password = encrypt_password(decrypted_password, shared_key)
        shared_entry.encrypted_url = encrypt_password(decrypted_url, shared_key) if decrypted_url else None

        updated_count += 1

        # Enregistrer les modifications dans la base de données
        db.commit()
        db.refresh(shared_entry)


    return updated_count


