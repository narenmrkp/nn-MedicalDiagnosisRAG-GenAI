# from pydantic import BaseModel

# class SignupRequest(BaseModel):
#     username:str
#     password:str
#     role:str 
# def verify_user(username: str, password: str):
#     ...
#     return user_or_none

from server.config.db import users_collection
import bcrypt

def verify_user(username: str, password: str):
    user = users_collection.find_one({"username": username})
    if not user:
        return None

    if not bcrypt.checkpw(password.encode(), user["password"].encode()):
        return None

    return {
        "username": user["username"],
        "role": user["role"]
    }

