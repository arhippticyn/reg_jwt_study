from fastapi import FastAPI, Depends, HTTPException, status, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from datetime import datetime, timedelta
import jwt
from jwt import PyJWTError

SECRET_KEY = "SECRET_KEY"
ALGORITHM = 'HS256'
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='login')

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.now() + (expires_delta or timedelta(minutes=60))
    to_encode.update({'exp': expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    
        if not payload:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Невірний токен або відсутній user_id",headers={"WWW-Authenticate": "Bearer"})
    
        user_id = payload.get('user_id')
    
        return user_id
    
    except PyJWTError:
        raise HTTPException(detail='bad debil', status_code=status.HTTP_401_UNAUTHORIZED)
    
@app.post('/login')
def login(username: str = Form(...), password: str = Form(...)):
    if username == 'admin' and password == 'secret':
        access = create_access_token({
            'id': 67,
            'username': username
        })
        
        return {'access_token': access, 'token_type': 'bearer'}
    
    else:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='idi nahui yebok')
    
@app.get('/profile')
def profile(user: int = Depends(verify_user)):
    return user