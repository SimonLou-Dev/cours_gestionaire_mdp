import os
from typing import Annotated

from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session, joinedload

from models.credential import CredentialIn, Credential
from models.users import UserIn, User, UserOut
from utils.authentication import Authenticator
from utils.keygen import KeyGen
from database import Base, engine, get_db

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()


Base.metadata.create_all(bind=engine)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")



@app.post("/users/regiter")
async def register_user(new_user: UserIn, db: Session = Depends(get_db)):
    findByEmail = db.query(User).filter(User.email == new_user.email).first()
    if findByEmail:
        raise HTTPException(status_code=400, detail="User already exists")

    user = User()
    user.email = new_user.email
    user.pseudo = new_user.pseudo
    user.password = pwd_context.hash(new_user.password)
    private_key, public_key, salt = KeyGen().generate_user_key(new_user.password)
    user.public_key = public_key
    user.private_key = private_key
    user.salt = salt
    db.add(user)
    db.commit()
    db.refresh(user)
    return {
        "user": user.render(),
        "token": Authenticator().create_access_token(user, db)
    }

@app.post("/users/login")
async def login_user(login_user: UserIn, db: Session = Depends(get_db)):
    user = db.query(User).filter_by(email=login_user.email).first()
    print(user)
    if not user or not pwd_context.verify(login_user.password, user.password):
        raise HTTPException(status_code=404, detail="User not found")
    return {
        "user": user.render(),
        "token": Authenticator().create_access_token(user, db)
    }

@app.get("/credentials")
async def get_credentials(token: Annotated[str, Depends(oauth2_scheme)], db: Session = Depends(get_db)):
    user = Authenticator().get_user(token, db)
    return {
        "credentials": [cred.render() for cred in user.creds],
        "shared": []
    }

@app.post("/credentials")
async def add_credentials(new_cred: CredentialIn, token: Annotated[str, Depends(oauth2_scheme)], db: Session = Depends(get_db)):
    user = Authenticator().get_user(token, db)
    cred = Credential(
        email=new_cred.email,
        name=new_cred.name,
        password=new_cred.password,
        pseudo=new_cred.pseudo,
        url=new_cred.url,
        iv=new_cred.iv,
        user_id=user.id
    )
    db.add(cred)
    db.commit()
    db.refresh(cred)
    return cred.render()

@app.put("/credentials/{cred_id}")
async def update_credentials(cred_id: int,new_cred: CredentialIn, token: Annotated[str, Depends(oauth2_scheme)], db: Session = Depends(get_db)):
    user: User = Authenticator().get_user(token, db)
    cred: Credential = db.query(Credential).filter(Credential.id == cred_id).filter(Credential.user_id == user.id).first()
    if cred is None:
        raise HTTPException(status_code=404, detail="Credential not found")
    cred.email = new_cred.email
    cred.name = new_cred.name
    cred.password = new_cred.password
    cred.pseudo = new_cred.pseudo
    cred.url = new_cred.url
    db.add(cred)
    db.commit()
    db.refresh(cred)
    return cred.render()

@app.delete("/credentials/{cred_id}")
async def delete_credentials(cred_id: int, token: Annotated[str, Depends(oauth2_scheme)], db: Session = Depends(get_db)):
    user: User = Authenticator().get_user(token, db)
    cred: Credential = db.query(Credential).filter(Credential.id == cred_id).filter(Credential.user_id == user.id).first()
    if cred is None:
        raise HTTPException(status_code=404, detail="Credential not found")
    db.delete(cred)
    db.commit()
    return ""
