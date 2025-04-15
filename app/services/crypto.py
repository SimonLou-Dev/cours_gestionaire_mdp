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
def decrypt_password(encrypted_password: str, user_password: str) -> str:
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