from datetime import datetime, timedelta
from typing import Optional
import json
from pathlib import Path
from passlib.context import CryptContext
from jose import JWTError, jwt

# Simple config — in production use env vars and secure keys
SECRET_KEY = "change-this-secret-to-a-secure-random-value"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 1 day

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

USERS_FILE = Path(__file__).parent / "users.json"

# Ensure users file exists
if not USERS_FILE.exists():
    USERS_FILE.write_text("{}")


def get_users_data():
    try:
        return json.loads(USERS_FILE.read_text())
    except Exception:
        return {}


def save_users_data(data: dict):
    USERS_FILE.write_text(json.dumps(data, indent=2))


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def get_user(email: str) -> Optional[dict]:
    users = get_users_data()
    return users.get(email)


def create_user(email: str, password: str, role: str = "member") -> dict:
    users = get_users_data()
    if email in users:
        raise ValueError("User already exists")
    hashed = get_password_hash(password)
    users[email] = {"email": email, "hashed_password": hashed, "role": role}
    save_users_data(users)
    return users[email]


def authenticate_user(email: str, password: str) -> Optional[dict]:
    user = get_user(email)
    if not user:
        return None
    if not verify_password(password, user["hashed_password"]):
        return None
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None
