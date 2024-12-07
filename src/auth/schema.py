from enum import Enum
from typing import Optional
from pydantic import BaseModel, EmailStr


class RoleEnum(Enum):
    USER = "user"
    ADMIN = "admin"
    

class UserBase(BaseModel):
    username: str
    email: EmailStr
    avatar: Optional[str] = None
    

class UserCreate(UserBase):
    username: str
    email: EmailStr
    password: str
    avatar: Optional[str] = None


class UserResponse(UserBase):
    id: int

    class Config:
        from_atributes = True


class TokenData(BaseModel):
    username: str | None = None


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str