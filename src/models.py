from pydantic import BaseModel, EmailStr
from typing import List


class User(BaseModel):
    id: int
    email: EmailStr
    username: str


class UsersResponseModel(BaseModel):
    users: List[User]


class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str


class UserResponse(BaseModel):
    username: str
    email: EmailStr


class LoginModel(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str
