import base64
import hashlib
import os
import secrets
import time
from typing import Any

import httpx
import jwt
from dotenv import load_dotenv
from fastapi import Cookie, Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse

load_dotenv()
print("Client ID:", os.getenv("fastapi-rbac-client"))
print("Secret loaded:", bool(os.getenv("1oSFbvwyHBSf5g3FcbnfQYc6rKVGZmSK")))

KEYCLOAK_BASE_URL = os.getenv("KEYCLOAK_BASE_URL", "http://localhost:8180")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM", "rbac-demo")
KEYCLOAK_CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID", "fastapi-rbac-client")
KEYCLOAK_CLIENT_SECRET = os.getenv("KEYCLOAK_CLIENT_SECRET", "")
BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000")
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")
SESSION_COOKIE_NAME = os.getenv("SESSION_COOKIE_NAME", "rbac_session")
SESSION_SECURE = os.getenv("SESSION_SECURE", "false").lower() == "true"

AUTHORIZATION_ENDPOINT = (
    f"{KEYCLOAK_BASE_URL}/realms/{KEYCLOAK_REALM}"
    "/protocol/openid-connect/auth"
)

TOKEN_ENDPOINT = (
    f"{KEYCLOAK_BASE_URL}/realms/{KEYCLOAK_REALM}"
    "/protocol/openid-connect/token"
)

LOGOUT_ENDPOINT = (
    f"{KEYCLOAK_BASE_URL}/realms/{KEYCLOAK_REALM}"
    "/protocol/openid-connect/logout"
)

JWKS_ENDPOINT = (
    f"{KEYCLOAK_BASE_URL}/realms/{KEYCLOAK_REALM}"
    "/protocol/openid-connect/certs"
)

ISSUER = f"{KEYCLOAK_BASE_URL}/realms/{KEYCLOAK_REALM}"
CALLBACK_URL = f"{BACKEND_URL}/auth/callback"

APPLICATION_ROLES = {
    "admin",
    "manager",
    "developer",
    "tester",
    "viewer",
}

app = FastAPI(title="RBAC FastAPI Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:3001",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)

# Development-only in-memory stores.
# Use Redis or a database in production.
login_states: dict[str, dict[str, Any]] = {}
sessions: dict[str, dict[str, Any]] = {}


def create_pkce_values() -> tuple[str, str]:
    """Create a PKCE verifier and SHA-256 challenge."""
    verifier = secrets.token_urlsafe(64)

    digest = hashlib.sha256(verifier.encode("utf-8")).digest()

    challenge = (
        base64.urlsafe_b64encode(digest)
        .decode("utf-8")
        .rstrip("=")
    )

    return verifier, challenge


def decode_token_without_verification(token: str) -> dict[str, Any]:
    """
    Used only to read user details after the backend obtained the token
    directly from Keycloak over the token endpoint.

    Protected API validation is performed separately using Keycloak JWKS.
    """
    return jwt.decode(
        token,
        options={
            "verify_signature": False,
            "verify_aud": False,
        },
    )


async def verify_access_token(token: str) -> dict[str, Any]:
    """Verify signature, issuer and expiry using Keycloak public keys."""
    try:
        async with httpx.AsyncClient() as client:
            jwks_response = await client.get(JWKS_ENDPOINT)
            jwks_response.raise_for_status()
            jwks = jwks_response.json()

        header = jwt.get_unverified_header(token)
        key_id = header.get("kid")

        matching_key = next(
            (key for key in jwks["keys"] if key.get("kid") == key_id),
            None,
        )

        if matching_key is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="No matching Keycloak signing key found.",
            )

        public_key = jwt.algorithms.RSAAlgorithm.from_jwk(matching_key)

        return jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            issuer=ISSUER,
            options={
                # Keycloak access token audience configuration can vary.
                # Add audience validation after configuring an audience mapper.
                "verify_aud": False,
            },
        )

    except HTTPException:
        raise
    except jwt.ExpiredSignatureError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session access token has expired.",
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid access token.",
        ) from exc


async def refresh_session(session_id: str) -> dict[str, Any]:
    session = sessions.get(session_id)

    if not session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No active session.",
        )

    refresh_token = session.get("refresh_token")

    if not refresh_token:
        sessions.pop(session_id, None)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token is unavailable.",
        )

    async with httpx.AsyncClient() as client:
        response = await client.post(
            TOKEN_ENDPOINT,
            data={
                "grant_type": "refresh_token",
                "client_id": KEYCLOAK_CLIENT_ID,
                "client_secret": KEYCLOAK_CLIENT_SECRET,
                "refresh_token": refresh_token,
            },
        )

    if response.status_code != 200:
        sessions.pop(session_id, None)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired. Please log in again.",
        )

    token_data = response.json()

    session["access_token"] = token_data["access_token"]
    session["refresh_token"] = token_data.get(
        "refresh_token",
        refresh_token,
    )
    session["id_token"] = token_data.get(
        "id_token",
        session.get("id_token"),
    )
    session["access_token_expires_at"] = (
        time.time() + token_data.get("expires_in", 300)
    )

    return session


async def get_current_user(
    session_id: str | None = Cookie(
        default=None,
        alias=SESSION_COOKIE_NAME,
    ),
) -> dict[str, Any]:
    if not session_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
        )

    session = sessions.get(session_id)

    if not session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session.",
        )

    # Refresh shortly before expiration.
    if session["access_token_expires_at"] <= time.time() + 30:
        session = await refresh_session(session_id)

    claims = await verify_access_token(session["access_token"])

    realm_roles = claims.get("realm_access", {}).get("roles", [])

    application_roles = [
        role for role in realm_roles if role in APPLICATION_ROLES
    ]

    return {
        "session_id": session_id,
        "sub": claims.get("sub"),
        "username": claims.get("preferred_username"),
        "name": claims.get("name"),
        "email": claims.get("email"),
        "roles": application_roles,
        "all_roles": realm_roles,
    }


def require_roles(*allowed_roles: str):
    async def role_dependency(
        user: dict[str, Any] = Depends(get_current_user),
    ) -> dict[str, Any]:
        user_roles = set(user.get("roles", []))

        if not user_roles.intersection(allowed_roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to access this resource.",
            )

        return user

    return role_dependency


@app.get("/")
async def root():
    return {
        "message": "RBAC FastAPI backend is running",
        "keycloak_realm": KEYCLOAK_REALM,
    }


@app.get("/auth/login")
async def login():
    state = secrets.token_urlsafe(32)
    verifier, challenge = create_pkce_values()

    login_states[state] = {
        "code_verifier": verifier,
        "created_at": time.time(),
    }

    authorization_url = (
        f"{AUTHORIZATION_ENDPOINT}"
        f"?client_id={KEYCLOAK_CLIENT_ID}"
        f"&response_type=code"
        f"&scope=openid%20profile%20email"
        f"&redirect_uri={CALLBACK_URL}"
        f"&state={state}"
        f"&code_challenge={challenge}"
        f"&code_challenge_method=S256"
    )

    return RedirectResponse(authorization_url)


@app.get("/auth/callback")
async def auth_callback(
    code: str,
    state: str,
):
    state_data = login_states.pop(state, None)

    if not state_data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired login state.",
        )

    if time.time() - state_data["created_at"] > 300:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Login request expired.",
        )

    async with httpx.AsyncClient() as client:
        response = await client.post(
            TOKEN_ENDPOINT,
            data={
                "grant_type": "authorization_code",
                "client_id": KEYCLOAK_CLIENT_ID,
                "client_secret": KEYCLOAK_CLIENT_SECRET,
                "code": code,
                "redirect_uri": CALLBACK_URL,
                "code_verifier": state_data["code_verifier"],
            },
        )

    if response.status_code != 200:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "message": "Authorization-code exchange failed.",
                "keycloak_response": response.text,
            },
        )

    token_data = response.json()
    access_token = token_data["access_token"]

    # Verify before creating the application session.
    await verify_access_token(access_token)

    session_id = secrets.token_urlsafe(48)

    sessions[session_id] = {
        "access_token": access_token,
        "refresh_token": token_data.get("refresh_token"),
        "id_token": token_data.get("id_token"),
        "access_token_expires_at": (
            time.time() + token_data.get("expires_in", 300)
        ),
    }

    redirect = RedirectResponse(
        url=f"{FRONTEND_URL}?login=success",
        status_code=status.HTTP_302_FOUND,
    )

    redirect.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=session_id,
        httponly=True,
        secure=SESSION_SECURE,
        samesite="lax",
        max_age=1800,
        path="/",
    )

    return redirect


@app.get("/auth/me")
async def me(
    user: dict[str, Any] = Depends(get_current_user),
):
    return {
        "authenticated": True,
        "username": user["username"],
        "name": user["name"],
        "email": user["email"],
        "roles": user["roles"],
    }


@app.post("/auth/logout")
async def logout(
    request: Request,
    session_id: str | None = Cookie(
        default=None,
        alias=SESSION_COOKIE_NAME,
    ),
):
    session = sessions.pop(session_id, None) if session_id else None

    if session and session.get("refresh_token"):
        async with httpx.AsyncClient() as client:
            await client.post(
                LOGOUT_ENDPOINT,
                data={
                    "client_id": KEYCLOAK_CLIENT_ID,
                    "client_secret": KEYCLOAK_CLIENT_SECRET,
                    "refresh_token": session["refresh_token"],
                },
            )

    response = RedirectResponse(
        url=FRONTEND_URL,
        status_code=status.HTTP_302_FOUND,
    )

    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        path="/",
    )

    return response


@app.get("/api/dashboard")
async def dashboard(
    user: dict[str, Any] = Depends(get_current_user),
):
    return {
        "message": "Protected dashboard data",
        "user": user,
    }


@app.get("/api/users")
async def users(
    user: dict[str, Any] = Depends(require_roles("admin")),
):
    return {
        "requested_by": user["username"],
        "users": [
            {"username": "admin_user", "role": "admin"},
            {"username": "manager_user", "role": "manager"},
            {"username": "developer_user", "role": "developer"},
            {"username": "tester_user", "role": "tester"},
            {"username": "viewer_user", "role": "viewer"},
        ],
    }


@app.get("/api/reports")
async def reports(
    user: dict[str, Any] = Depends(
        require_roles("admin", "manager", "viewer")
    ),
):
    return {
        "message": "Report data",
        "requested_by": user["username"],
    }


@app.get("/api/developer")
async def developer_area(
    user: dict[str, Any] = Depends(
        require_roles("admin", "developer")
    ),
):
    return {
        "message": "Developer-only data",
        "requested_by": user["username"],
    }