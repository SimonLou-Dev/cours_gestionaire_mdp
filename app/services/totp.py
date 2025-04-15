import pyotp
import qrcode
from io import BytesIO
from base64 import b64encode

def generate_totp_secret() -> str:
    """
    Génère un secret TOTP unique pour l'utilisateur.
    """
    totp = pyotp.TOTP(pyotp.random_base32())
    return totp.secret


def generate_qr_code(secret: str, username: str) -> str:
    """
    Génère un code QR à partir du secret TOTP, à scanner dans une application comme Google Authenticator.
    """
    totp_uri = f"otpauth://totp/{username}?secret={secret}&issuer=MyApp"
    img = qrcode.make(totp_uri)
    buffer = BytesIO()
    img.save(buffer)
    buffer.seek(0)
    img_b64 = b64encode(buffer.read()).decode('utf-8')
    return img_b64

def verify_totp(secret: str, code: str) -> bool:
    totp = pyotp.TOTP(secret)
    return totp.verify(code)
