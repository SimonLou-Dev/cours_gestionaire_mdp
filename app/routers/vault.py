from fastapi import APIRouter, Form, Request, HTTPException, Depends
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from app.models.user import User
from app.services import crypto
from app.database import SessionLocal

router = APIRouter()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.post("/unlock")
async def unlock_vault(request: Request, pin: str = Form(...), db: Session = Depends(get_db)):
    user_id = request.cookies.get("user_id")
    user = db.query(User).filter(User.id == int(user_id)).first()
    if not user:
        raise HTTPException(status_code=404, detail="Utilisateur non trouvé")

    salt = user.username.encode()  # Salt simple ici
    key = crypto.derive_key_from_pin(pin, salt)

    try:
        decrypted_key = crypto.decrypt_aes(key, user.encrypted_aes_key)
        request.session = { "aes_key": decrypted_key }  # À sécuriser plus tard
        return RedirectResponse("/dashboard", status_code=302)
    except Exception:
        raise HTTPException(status_code=403, detail="PIN incorrect")
