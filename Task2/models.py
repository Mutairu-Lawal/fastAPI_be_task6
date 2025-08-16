from pydantic import BaseModel, Field
from typing import Optional


# ===== Models =====

class UserRegister(BaseModel):
    username: str = Field(min_length=1)
    password: str = Field(min_length=1)
    role: Optional[str] = 'customer'  # 'admin' or 'customer'


class Product(BaseModel):
    name: str = Field(min_length=1)
    price: float = Field(gt=0)


class CartItem(BaseModel):
    product_name: str = Field(min_length=1)
    quantity: int = Field(gt=1)
