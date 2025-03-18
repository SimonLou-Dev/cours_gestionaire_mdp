
import jwt
from fastapi import HTTPException
from fastapi.security import OAuth2PasswordBearer
from datetime import datetime, timedelta

from jwt import InvalidTokenError
from sqlalchemy.orm import Session

from models.access_token import AccessToken
from models.users import User

credentials_exception = HTTPException(
    status_code=401,
    detail="Could not validate tokens",
    headers={"WWW-Authenticate": "Bearer"},
)



class Authenticator:
    def __init__(self):
        self.oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
        self.SECRET_KEY = "secret"
        self.ALGORITHM = "HS256"

    def create_access_token(self, user: User, db: Session):
        expire = datetime.utcnow() + timedelta(minutes=30)
        to_encode = {"exp": expire, "userId": user.id}
        encoded_jwt = jwt.encode(to_encode,self.SECRET_KEY, algorithm=self.ALGORITHM)
        token = AccessToken()
        token.access_token = encoded_jwt
        token.expires_at = expire
        token.user_id = user.id
        db.add(token)
        db.commit()
        db.refresh(token)
        return encoded_jwt

    def get_user(self, token: str,  db: Session) -> User:
        print("ici")
        try:
            payload = jwt.decode(token, self.SECRET_KEY, algorithms=[self.ALGORITHM])
            print("1")
            userId = payload.get("userId")
            expiry = payload.get("exp")
            print("2")
            if userId is None or expiry is None:
                raise credentials_exception
            print("Before")
            user: User = db.query(User).filter(User.id == userId).first()
            print("After")
            if user is None:
                raise credentials_exception
            return user
        except InvalidTokenError:
            raise credentials_exception

    def get_oauth2_scheme(self):
        return self.oauth2_scheme

