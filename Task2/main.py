from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from models import CartItem, Product, UserRegister
from utils import load_db, save_to_db

from auth import (
    hash_password, authenticate_user, create_access_token,
    get_current_user, require_admin, USERS_FILE
)

app = FastAPI(title="Secure Shopping Cart API")

PRODUCTS_FILE = "products.json"
CART_FILE = "cart.json"


# ===== Auth Endpoints =====
@app.post("/register/", status_code=201)
def register(user: UserRegister):
    users = load_db(USERS_FILE)
    if any(u["username"] == user.username for u in users):
        raise HTTPException(status_code=400, detail="Username already exists")
    if user.role not in ["admin", "customer"]:
        raise HTTPException(status_code=400, detail="Invalid role")
    users.append({
        "username": user.username,
        "password": hash_password(user.password),
        "role": user.role
    })
    save_to_db(USERS_FILE, users)
    return {"message": "User registered successfully"}


@app.get("/products/")
def get_products():
    return load_db(PRODUCTS_FILE)


@app.post("/login/")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=401, detail="Invalid username or password")
    token = create_access_token(subject=user["username"], role=user["role"])
    return {"access_token": token, "token_type": "bearer"}


# ===== Product Endpoints =====
@app.post("/admin/add-product/")
def add_product(product: Product, admin=Depends(require_admin)):
    products = load_db(PRODUCTS_FILE)
    if any(p["name"] == product.name for p in products):
        raise HTTPException(status_code=400, detail="Product already exists")
    products.append(product.model_dump())
    save_to_db(PRODUCTS_FILE, products)
    return {"message": "Product added successfully"}


# ===== Cart Endpoints =====
@app.post("/cart/add/")
def add_to_cart(item: CartItem, current_user=Depends(get_current_user)):
    products = load_db(PRODUCTS_FILE)
    if not any(p["name"] == item.product_name for p in products):
        raise HTTPException(status_code=404, detail="Product not found")

    cart = load_db(CART_FILE)
    cart.append({
        "username": current_user["username"],
        "product_name": item.product_name,
        "quantity": item.quantity
    })
    save_to_db(CART_FILE, cart)
    return {"message": "Item added to cart"}
