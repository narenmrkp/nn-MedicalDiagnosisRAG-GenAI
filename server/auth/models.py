from pydantic import BaseModel

class SignupRequest(BaseModel):
    username:str
    password:str
    role:str 
def verify_user(username: str, password: str):
    ...
    return user_or_none
