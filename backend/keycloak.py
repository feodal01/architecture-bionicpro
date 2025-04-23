import os, time, requests
from functools import lru_cache
from fastapi import Header, HTTPException, status
from jose import jwt, JWTError

REALM = os.getenv("KEYCLOAK_REALM", "reports-realm")
KC_URL = os.getenv("KEYCLOAK_URL", "http://keycloak:8080")

# ---------- грузим JWKS одноразово ----------
@lru_cache(maxsize=1)
def _load_jwks():
    url = f"{KC_URL}/realms/{REALM}/protocol/openid-connect/certs"
    return requests.get(url, timeout=5).json()

# ---------- извлекаем имя юзера -------------
def get_current_user(authorization: str = Header(...)):
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    token = authorization.split()[1]

    try:
        payload = jwt.decode(
            token,
            _load_jwks(),
            algorithms=["RS256"],
            audience="account",
            issuer=f"{KC_URL}/realms/{REALM}",
        )
    except JWTError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))

    # берём preferred_username или sub
    return payload.get("preferred_username") or payload["sub"]
