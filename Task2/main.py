from pydantic import BaseModel, Field
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from typing import List
import json
import os

from auth import (
    hash_password, authenticate_user, create_access_token,
    get_current_user, require_admin, load_users, save_users
)

app = FastAPI(title="Secure Shopping Cart API")

PRODUCTS_FILE = "products.json"
CART_FILE = "cart.json"

# ===== File Helpers =====


def load_products():
    if not os.path.exists(PRODUCTS_FILE):
        return []
    try:
        with open(PRODUCTS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError:
        return []


def save_products(products):
    with open(PRODUCTS_FILE, "w", encoding="utf-8") as f:
        json.dump(products, f, indent=4)


def load_cart():
    if not os.path.exists(CART_FILE):
        return []
    try:
        with open(CART_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError:
        return []


def save_cart(cart):
    with open(CART_FILE, "w", encoding="utf-8") as f:
        json.dump(cart, f, indent=4)


# ===== Models =====


class UserRegister(BaseModel):
    username: str
    password: str
    role: str  # 'admin' or 'customer'


class Product(BaseModel):
    name: str
    price: float = Field(gt=0)


class CartItem(BaseModel):
    product_name: str
    quantity: int = Field(gt=1)


# ===== Auth Endpoints =====
@app.post("/register/")
def register(user: UserRegister):
    users = load_users()
    if any(u["username"] == user.username for u in users):
        raise HTTPException(status_code=400, detail="Username already exists")
    if user.role not in ["admin", "customer"]:
        raise HTTPException(status_code=400, detail="Invalid role")
    users.append({
        "username": user.username,
        "password": hash_password(user.password),
        "role": user.role
    })
    save_users(users)
    return {"message": "User registered successfully"}


@app.post("/login/")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=401, detail="Invalid username or password")
    token = create_access_token(subject=user["username"], role=user["role"])
    return {"access_token": token, "token_type": "bearer"}


# ===== Product Endpoints =====
@app.post("/admin/add_product/")
def add_product(product: Product, admin=Depends(require_admin)):
    products = load_products()
    if any(p["name"] == product.name for p in products):
        raise HTTPException(status_code=400, detail="Product already exists")
    products.append(product.dict())
    save_products(products)
    return {"message": "Product added successfully"}


@app.get("/products/")
def get_products():
    return load_products()


# ===== Cart Endpoints =====
@app.post("/cart/add/")
def add_to_cart(item: CartItem, current_user=Depends(get_current_user)):
    products = load_products()
    if not any(p["name"] == item.product_name for p in products):
        raise HTTPException(status_code=404, detail="Product not found")

    cart = load_cart()
    cart.append({
        "username": current_user["username"],
        "product_name": item.product_name,
        "quantity": item.quantity
    })
    save_cart(cart)
    return {"message": "Item added to cart"}
