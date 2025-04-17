"""Ce service gère la génération et la vérification des codes TOTP pour l'A2F."""

from base64 import b64encode
from io import BytesIO

import pyotp
import qrcode


def generate_totp_secret() -> str:
    """Génère un secret TOTP unique pour l'utilisateur.

    Arguments:
        None

    Returns:
        str: Le secret TOTP généré.

    """
    totp = pyotp.TOTP(pyotp.random_base32())
    return totp.secret


def generate_qr_code(secret: str, username: str) -> str:
    """Génère un code QR à partir du secret TOTP.

    Arguments:
        secret (str): Le secret TOTP.
        username (str): Le nom d'utilisateur de l'utilisateur.

    Returns:
        str: Le code QR encodé en base64.

    """
    totp_uri = f"otpauth://totp/{username}?secret={secret}&issuer=MyApp"
    img = qrcode.make(totp_uri)
    buffer = BytesIO()
    img.save(buffer)
    buffer.seek(0)
    return b64encode(buffer.read()).decode("utf-8")


def verify_totp(secret: str, code: str) -> bool:
    """Vérifie le code TOTP fourni par l'utilisateur.

    Arguments:
        secret (str): Le secret TOTP de l'utilisateur.
        code (str): Le code TOTP à vérifier.

    Returns:
        bool: True si le code est valide, False sinon.

    """
    totp = pyotp.TOTP(secret)
    return totp.verify(code)
