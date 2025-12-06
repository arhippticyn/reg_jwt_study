import jwt
from jwt import PyJWTError
import time
from fastapi import FastAPI, HTTPException, Depends, status
from typing import Annotated
from models import *
from db import get_db, User
from sqlalchemy.orm import Session
from fastapi.responses import JSONResponse
from fastapi.requests import Request

def create_access(data: dict):
    payload = data.copy()
    payload['exp'] = int(time.time()) + 1800
    payload['type'] = 'access'
    
    return jwt.encode(payload, key='ezz', algorithm='HS256')  

def craete_refresh(data: dict):
      payload = data.copy()
      payload['exp'] = int(time.time()) + 180000
      payload['type'] = 'access'
      return jwt.encode(payload, key='ezz', algorithm='HS256')
  
def verify_token(token: str):
    try:
        payload = jwt.decode(token, key='ezz', algorithm='HS256')
        return payload
    except PyJWTError:
        return None
    
def verify_user(req: Request):
    token = req.cookies.get('access_token')
    
    if token:
       payload = verify_token(token)
       if payload:
        return payload
       else:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)
    
app = FastAPI()

@app.post('/register', response_model=UserResponse)
def register(data: CreateUser, db: Session = Depends(get_db)):
    user = data.model_dump()
    
    if user:
        new_user = User(**user)
        new_user.set_password(user['password'])
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        
        user.pop('password')
        
        access = create_access(user)
        refresh = craete_refresh(user)
        
        if access and refresh:
            res = JSONResponse({'message':'successfuly created'}, status_code=status.HTTP_201_CREATED)
            
            res.set_cookie(
                key="access_token",
                value=access,
                max_age=900,
                httponly=True,
                samesite="lax"
            )
            
            res.set_cookie(
                key="refresh_token",
                value=refresh,
                httponly=True,
                secure=False,
                samesite="lax",
                max_age=60 * 60 * 24 * 7
            )
            
            return res
    

@app.post('/login')
def login(data: LoginUser, db: Session = Depends(get_db)):
    user = data.model_dump()
    
    password = user.get('password')
    db_user = db.query(User).filter_by(username=user['username']).first()
    
    if password:
        if db_user.check_password(password):
            user.pop('password')
            
            access = create_access(user)
            refresh = craete_refresh(user)
            
            if access and refresh:
                res = JSONResponse({'message': 'successfuly logged in'})

                res.set_cookie(
                    key="access_token",
                    value=access,
                    max_age=900,
                    httponly=True,
                    samesite="lax"
                )

                res.set_cookie(
                    key="refresh_token",
                    value=refresh,
                    httponly=True,
                    secure=False,
                    samesite="lax",
                    max_age=60 * 60 * 24 * 7
                )

                return res
            else:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
        else:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)
    else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)
    
@app.get('/profile')
def get_profile(user = Depends(verify_user)):
    return user

@app.post('/refresh')
def refresh(req: Request):
    refresh_token = req.cookies.get('refresh_token')
    
    if refresh_token:
        payload = verify_token(refresh_token)
        
        if payload:
            username = payload.get('username')
            
            data = {
                'username': username
            }
            
            access = create_access(data)
            res = JSONResponse({'message': 'created access'})

            res.set_cookie(
                key="access_token",
                value=access,
                max_age=900,
                httponly=True,
                samesite="lax"
            )
            
            return res