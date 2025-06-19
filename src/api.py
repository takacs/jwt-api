from fastapi import Depends, APIRouter, status, Body
from fastapi import HTTPException, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlite3 import Connection
import base64
import json

from src.db import get_db
from src.models import (
    User,
    UserResponse,
    UsersResponseModel,
    UserCreate,
    LoginModel,
    LoginResponse,
)
import bcrypt

from src.utils import (
    create_access_token,
    create_refresh_token,
    verify_password,
    verify_access_token,
    verify_refresh_token,
)

router = APIRouter()


@router.get("/users", response_model=UsersResponseModel, status_code=status.HTTP_200_OK)
def get_users(conn: Connection = Depends(get_db)):
    cursor = conn.cursor()
    cursor.execute("SELECT id, email, username FROM users")

    users = []
    for row in cursor.fetchall():
        user = dict(row)
        users.append(
            User(id=user["id"], username=user["username"], email=user["email"])
        )

    return UsersResponseModel(users=users)


@router.post(
    "/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED
)
def register(user: UserCreate, conn: Connection = Depends(get_db)):
    hashed_pw = bcrypt.hashpw(user.password.encode(), bcrypt.gensalt())

    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO users (username, email, hashed_password) VALUES (?, ?, ?)",
        (user.username, user.email, hashed_pw),
    )
    conn.commit()

    return UserResponse(username=user.username, email=user.email)


@router.post("/login", response_model=LoginResponse, status_code=status.HTTP_200_OK)
def login(user_login: LoginModel, conn: Connection = Depends(get_db)):
    cursor = conn.cursor()
    db_user = cursor.execute(
        "SELECT id, username, hashed_password FROM users WHERE username = ?",
        (user_login.username,),
    ).fetchone()

    if db_user is None:
        return HTTPException(
            status.HTTP_404_NOT_FOUND, f"User {user_login.username} doesn't exist."
        )

    if not verify_password(user_login.password, db_user["hashed_password"]):
        return HTTPException(status.HTTP_401_UNAUTHORIZED, "Password invalid.")

    payload = {"sub": user_login.username}
    access_token = create_access_token(payload)
    refresh_token, expires_at = create_refresh_token(payload)

    cursor.execute(
        "INSERT INTO refresh_tokens (user_id, token, expires_at, revoked) VALUES (?, ?, ?, 0)",
        (db_user["id"], refresh_token, expires_at),
    )
    conn.commit()

    return LoginResponse(
        access_token=access_token, refresh_token=refresh_token, token_type="bearer"
    )


security = HTTPBearer()


@router.get("/me")
def me(credentials: HTTPAuthorizationCredentials = Security(security)):
    access_token = credentials.credentials
    payload = verify_access_token(access_token)
    if not payload:
        return HTTPException(status.HTTP_401_UNAUTHORIZED, "Access token not valid.")
    return payload

@router.post("/refresh", response_model=LoginResponse, status_code=status.HTTP_200_OK)
def refresh(
    refresh_token: str = Body(..., embed=True),
    conn: Connection = Depends(get_db),
):
    payload = verify_refresh_token(refresh_token)
    if not payload:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Refresh token not valid.")

    cursor = conn.cursor()
    db_token = cursor.execute(
        "SELECT user_id, expires_at, revoked FROM refresh_tokens WHERE token = ?",
        (refresh_token,),
    ).fetchone()

    if db_token is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Refresh token not found.")
    if db_token[2]:  # revoked
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Refresh token revoked.")
    if int(db_token[1]) < int(__import__('time').time()):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Refresh token expired.")

    # Issue new access token
    username = payload.get("sub")
    if not username:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Malformed refresh token payload.")
    access_token = create_access_token({"sub": username})

    return LoginResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer"
    )

    