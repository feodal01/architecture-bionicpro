import os, time, requests
from functools import lru_cache
from fastapi import Header, HTTPException, status
from jose import jwt, JWTError
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

REALM = os.getenv("KEYCLOAK_REALM", "reports-realm")
KC_URL = os.getenv("KEYCLOAK_URL", "http://keycloak:8080")
REQUIRED_ROLE = "prothetic_user" 

# Для проверки токена используем localhost, так как Keycloak выдает токены с этим issuer
ISSUER = "http://localhost:8080"

logger.debug(f"Keycloak configuration: URL={KC_URL}, REALM={REALM}, ISSUER={ISSUER}")

@lru_cache(maxsize=1)
def _load_jwks():
    url = f"{KC_URL}/realms/{REALM}/protocol/openid-connect/certs"
    logger.debug(f"Loading JWKS from {url}")
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        jwks = response.json()
        logger.debug("Successfully loaded JWKS")
        return jwks
    except Exception as e:
        logger.error(f"Failed to load JWKS: {str(e)}")
        raise


def get_current_user(authorization: str = Header(...)):
    logger.debug(f"Received authorization header: {authorization[:20]}...")
    
    if not authorization.startswith("Bearer "):
        logger.error("Authorization header does not start with 'Bearer '")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authorization header")
    
    token = authorization.split()[1]
    logger.debug(f"Extracted token: {token[:20]}...")

    try:
        jwks = _load_jwks()
        logger.debug("Attempting to decode token...")
        
        # Сначала проверяем подпись токена
        try:
            # Получаем заголовок токена для определения алгоритма
            header = jwt.get_unverified_header(token)
            algorithm = header.get('alg')
            if not algorithm:
                raise JWTError("No algorithm specified in token header")
            
            # Проверяем подпись и декодируем токен
            payload = jwt.decode(
                token,
                jwks,
                algorithms=[algorithm],
                audience="account",
                issuer=f"{ISSUER}/realms/{REALM}",
                options={"verify_signature": True}
            )
        except JWTError as e:
            logger.error(f"Token signature validation failed: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token signature"
            )
        
        logger.debug(f"Successfully decoded token for user: {payload.get('preferred_username')}")

        # Проверяем роли
        roles: list[str] = payload.get("realm_access", {}).get("roles", [])
        logger.debug(f"User roles: {roles}")

        if REQUIRED_ROLE not in roles:
            logger.error(f"User does not have required role: {REQUIRED_ROLE}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User does not have required role",
            )
        
        return payload.get("preferred_username") or payload["sub"]
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
