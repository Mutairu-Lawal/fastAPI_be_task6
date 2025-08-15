from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import Optional, List
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
import jwt
import json
import os

app = FastAPI(title="Secure Notes API")

# ===== Security Config =====
SECRET_KEY = os.getenv("SECRET_KEY", "CHANGE_ME_IN_PRODUCTION")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

USERS_FILE = "users.json"
NOTES_FILE = "notes.json"

# ===== Models =====


class UserRegister(BaseModel):
    username: str
    password: str


class Note(BaseModel):
    title: str
    content: str
    date: str  # e.g., "2025-08-14"


class TokenResponse(BaseModel):
    access_token: str
    token_type: str

# ===== File Helpers =====


def load_json(file_path: str):
    if not os.path.exists(file_path):
        return []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError:
        return []


def save_json(file_path: str, data):
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)

# ===== Auth Helpers =====


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def authenticate_user(username: str, password: str):
    users = load_json(USERS_FILE)
    for u in users:
        if u["username"] == username and verify_password(password, u["password"]):
            return u
    return None


def create_access_token(subject: str, expires_delta: Optional[timedelta] = None) -> str:
    expire = datetime.now(
        timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    payload = {"sub": subject, "exp": expire}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str) -> str:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=401, detail="Invalid token payload")
        return username
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

# ===== Dependency =====


def get_current_user(token: str = Depends(oauth2_scheme)):
    username = decode_access_token(token)
    users = load_json(USERS_FILE)
    user = next((u for u in users if u["username"] == username), None)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

# ===== Auth Endpoints =====


@app.post("/register/")
def register(user: UserRegister):
    users = load_json(USERS_FILE)
    if any(u["username"] == user.username for u in users):
        raise HTTPException(status_code=400, detail="Username already exists")
    users.append({"username": user.username,
                 "password": hash_password(user.password)})
    save_json(USERS_FILE, users)
    return {"message": "User registered successfully"}


@app.post("/login/", response_model=TokenResponse)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"}
        )
    token = create_access_token(subject=user["username"])
    return {"access_token": token, "token_type": "bearer"}

# ===== Notes Endpoints =====


@app.post("/notes/")
def add_note(note: Note, current_user=Depends(get_current_user)):
    notes = load_json(NOTES_FILE)
    notes.append({
        "username": current_user["username"],
        "title": note.title,
        "content": note.content,
        "date": note.date
    })
    save_json(NOTES_FILE, notes)
    return {"message": "Note added successfully"}


@app.get("/notes/")
def get_notes(current_user=Depends(get_current_user)):
    notes = load_json(NOTES_FILE)
    user_notes = [n for n in notes if n["username"]
                  == current_user["username"]]
    return user_notes
