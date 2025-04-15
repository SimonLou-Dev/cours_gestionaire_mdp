from hashlib import pbkdf2_hmac

import bcrypt
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from base64 import b64encode, b64decode
import os

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
def encrypt_password(password: str, user_password: str) -> str:
    # Générer un salt (sel) aléatoire pour chaque utilisateur
    salt = os.urandom(16)

    # Dériver la clé AES à partir du code user_password de l'utilisateur
    key = derive_key(user_password, salt)

    # Générer un iv (vecteur d'initialisation) aléatoire pour chaque chiffrement
    iv = os.urandom(16)

    # Compléter le mot de passe pour qu'il soit multiple de 16 (taille de bloc AES)
    padder = padding.PKCS7(128).padder()
    padded_password = padder.update(password.encode()) + padder.finalize()

    # Créer le chiffreur AES avec la clé et le mode CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Chiffrer le mot de passe
    encrypted_password = encryptor.update(padded_password) + encryptor.finalize()

    # Retourner le mot de passe chiffré sous forme de base64, avec le salt et l'IV pour pouvoir le déchiffrer plus tard
    return b64encode(salt + iv + encrypted_password).decode()


# Déchiffrement du mot de passe
def decrypt_password(encrypted_password: str, user_password: str) -> str:
    encrypted_data = b64decode(encrypted_password)
    salt = encrypted_data[:16]  # Les 16 premiers octets sont le salt
    iv = encrypted_data[16:32]  # Les 16 octets suivants sont l'IV
    encrypted_password_data = encrypted_data[32:]  # Le reste est le mot de passe chiffré
    key = derive_key(user_password, salt)

    # Créer le déchiffreur AES
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Déchiffrer le mot de passe
    decrypted_password = decryptor.update(encrypted_password_data) + decryptor.finalize()

    # Enlever le padding du mot de passe déchiffré
    unpadder = padding.PKCS7(128).unpadder()
    original_password = unpadder.update(decrypted_password) + unpadder.finalize()

    # Retourner le mot de passe original
    return original_password.decode()