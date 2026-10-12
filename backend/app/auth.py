"""Sign-in: password hashing, sign-in tokens, and who may see which project.

Passwords are stored as salted PBKDF2-SHA256 hashes (Python's standard library, no extra packages).
A sign-in token is "user id . expiry time . signature"; the signature is an HMAC made with a server secret,
so a token cannot be changed or made up without that secret.
"""
import base64
import hashlib
import hmac
import os
import secrets
import time

from fastapi import Depends, Header, HTTPException
from sqlalchemy.orm import Session

from . import models
from .database import get_db

TOKEN_DAYS = 7
ITERATIONS = 200_000


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), ITERATIONS).hex()
    return f"pbkdf2_sha256${ITERATIONS}${salt}${digest}"


def check_password(password: str, stored: str) -> bool:
    try:
        _, iterations, salt, digest = stored.split("$")
    except ValueError:
        return False
    test = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), int(iterations)).hex()
    return hmac.compare_digest(test, digest)


_RANDOM_SECRET = secrets.token_bytes(32)


def _secret() -> bytes:
    """SESSION_SECRET if set, else one made from PORTAL_API_KEY (so nothing new to set up).
    Without either, a random one: everyone is signed out when the backend restarts."""
    if os.getenv("SESSION_SECRET"):
        return os.environ["SESSION_SECRET"].encode()
    if os.getenv("PORTAL_API_KEY"):
        return hashlib.sha256(b"secflow-session:" + os.environ["PORTAL_API_KEY"].encode()).digest()
    return _RANDOM_SECRET


def _sign(body: str) -> str:
    mac = hmac.new(_secret(), body.encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac).decode().rstrip("=")


def make_token(user_id: int) -> str:
    body = f"{user_id}.{int(time.time()) + TOKEN_DAYS * 86400}"
    return f"{body}.{_sign(body)}"


def read_token(token: str) -> int | None:
    try:
        user_id, expires, signature = token.split(".")
    except ValueError:
        return None
    if not hmac.compare_digest(signature, _sign(f"{user_id}.{expires}")) or int(expires) < time.time():
        return None
    return int(user_id)


def current_user(authorization: str | None = Header(default=None), db: Session = Depends(get_db)) -> models.User:
    """FastAPI dependency: the signed-in person, from the "Authorization: Bearer <token>" header."""
    token = (authorization or "").removeprefix("Bearer ").strip()
    user_id = read_token(token) if token else None
    user = db.get(models.User, user_id) if user_id else None
    if not user:
        raise HTTPException(status_code=401, detail="Please sign in")
    return user


def allowed_repos(user: models.User) -> list[str] | None:
    """None means every project (managers)."""
    return None if user.role == "manager" else user.project_list


def check_repo(user: models.User, repo: str | None) -> None:
    allowed = allowed_repos(user)
    if repo and allowed is not None and repo not in allowed:
        raise HTTPException(status_code=403, detail="You are not a member of this project")
