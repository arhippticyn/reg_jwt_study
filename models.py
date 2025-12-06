from pydantic import BaseModel, EmailStr

class LoginUser(BaseModel):
    username: str
    password: str
    
class CreateUser(BaseModel):
    username: str
    password: str
    email: EmailStr
    
class UserResponse(BaseModel):
    id: int
    email: EmailStr
    username: str
    
    class Config():
        from_attributes = True