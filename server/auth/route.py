from fastapi import APIRouter, HTTPException, Depends
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from .models import SignupRequest
from .hash_utils import hash_password, verify_password
from ..config.db import users_collection


router=APIRouter(prefix="/auth",tags=["auth"])
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials

security = HTTPBasic(auto_error=False)

def authenticate(credentials: HTTPBasicCredentials = Depends(security)):
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "Authentication required"},
            headers={"WWW-Authenticate": "Basic"},
        )

    user = verify_user(credentials.username, credentials.password)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "Invalid username or password"},
            headers={"WWW-Authenticate": "Basic"},
        )

    return user

################################## wrong code ##########
# security=HTTPBasic()

# def authenticate(credentials:HTTPBasicCredentials=Depends(security)):
#     user=users_collection.find_one({"username":credentials.username})
#     if not user or not verify_password(credentials.password,user["password"]):
#         raise HTTPException(status_code=401,detail="Invalid credentials")
#     return {"username":user["username"],"role":user["role"]}
#######################################################

@router.post("/signup")
def signup(req:SignupRequest):
    if users_collection.find_one({"username":req.username}):
        raise HTTPException(status_code=400,detail="user already exists")
    users_collection.insert_one({
        "username":req.username,
        "password":hash_password( req.password),
        "role":req.role
    })
    return {"message":"User created successfully"}


@router.get("/login")
def login(user=Depends(authenticate)):
    return {"username":user["username"],"role":user["role"]}
