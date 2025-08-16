from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from pydantic import BaseModel
from typing import List

import os
import json

app = FastAPI(title='Secure Student Portal API')

# ===== Password hashing config =====
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 token URL dependency
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


# ===== Student Model =====
class Student(BaseModel):
    username: str
    password: str  # plaintext for registration, hashed internally
    grades: List[int]


STUDENTS_FILE = "students.json"


# ===== Helper Functions =====
def load_students():
    try:
        if not os.path.exists(STUDENTS_FILE):
            return []
        with open(STUDENTS_FILE, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def save_students(students):
    try:
        with open(STUDENTS_FILE, "w") as f:
            json.dump(students, f, indent=4)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error saving data: {e}")


#  return hashed password
def hash_password(password: str):
    return pwd_context.hash(password)


# verify password
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


# authenticate user
def authenticate_user(username: str, password: str):
    students = load_students()
    for student in students:
        if student["username"] == username and verify_password(password, student["password"]):
            return student
    return None


# ===== API Endpoints =====
@app.post("/register/")
def register(student: Student):
    students = load_students()

    # Check if username exists
    if any(s["username"] == student.username for s in students):
        raise HTTPException(status_code=400, detail="Username already exists")

    # checking if user send empty data
    if not student.grades:
        raise HTTPException(status_code=400, detail="Grades is required")

    # Store hashed password
    hashed_pw = hash_password(student.password)
    students.append({
        "username": student.username,
        "password": hashed_pw,
        "grades": student.grades
    })

    save_students(students)
    return {"message": "Student registered successfully"}


@app.post("/login/")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")

    # For simplicity, token is just the username (use JWT in real apps)
    return {"access_token": user["username"], "token_type": "bearer"}


@app.get("/grades/")
def get_grades(token: str = Depends(oauth2_scheme)):
    students = load_students()
    user = next((s for s in students if s["username"] == token), None)
    if not user:
        raise HTTPException(
            status_code=401, detail="Invalid authentication token")
    return {"username": user["username"], "grades": user["grades"]}
