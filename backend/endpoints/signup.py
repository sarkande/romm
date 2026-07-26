import hmac

from config import ROMCADE_SIGNUP_SECRET
from fastapi import Body, HTTPException, Request, status
from handler.auth import auth_handler
from handler.auth.constants import WRITE_SCOPES
from handler.database import db_client_token_handler, db_user_handler
from logger.logger import log
from models.client_token import ClientToken
from models.user import Role, User
from utils.client_tokens import build_create_schema
from utils.router import APIRouter
from utils.validation import (
    ValidationError,
    validate_email,
    validate_password,
    validate_username,
)

from endpoints.responses.client_token import ClientTokenCreateSchema

router = APIRouter(prefix="/users", tags=["signup"])


@router.post("/signup", status_code=status.HTTP_201_CREATED)
def signup(
    request: Request,
    username: str = Body(..., embed=True),
    password: str = Body(..., embed=True),
    email: str | None = Body(None, embed=True),
) -> ClientTokenCreateSchema:
    """Create an account and hand back a client token, in one call.

    Upstream registration needs an invite token that is single-use and
    arrives as a link, so a client with no browser cannot enroll anyone.
    Doing both steps here also keeps the password typed once and never
    stored, which matters on hardware that gets passed around.

    Off unless ROMCADE_SIGNUP_SECRET is set, and the caller must present
    it. The secret only keeps passers-by out: a client that carries it can
    be decompiled, so it is a lock, not armour.
    """
    if not ROMCADE_SIGNUP_SECRET:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Signup is disabled on this instance.",
        )

    # compare_digest: response time must not reveal how much of the secret
    # is right.
    presented = request.headers.get("x-signup-secret", "")
    if not hmac.compare_digest(presented, ROMCADE_SIGNUP_SECRET):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid signup secret.",
        )

    try:
        validate_username(username)
        validate_password(password)
        if email:
            validate_email(email)
    except ValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=exc.message
        ) from exc

    if db_user_handler.get_user_by_username(username.lower()):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Username {username} already exists",
        )

    if email and db_user_handler.get_user_by_email(email.lower()):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"User with email {email} already exists",
        )

    # Always the plain user role: an endpoint behind a shared secret must
    # never be able to mint an administrator.
    user = db_user_handler.add_user(
        User(
            username=username.lower(),
            hashed_password=auth_handler.get_password_hash(password),
            email=(email or "").lower() or None,
            role=Role.USER,
        )
    )

    # Capped at WRITE_SCOPES: a device token is for playing, not for
    # administering the instance.
    granted = [s.value for s in user.oauth_scopes if s in WRITE_SCOPES]

    raw_token = auth_handler.generate_client_token()
    token = db_client_token_handler.add_token(
        ClientToken(
            user_id=user.id,
            name="romcade",
            hashed_token=auth_handler.hash_client_token(raw_token),
            scopes=" ".join(granted),
            expires_at=None,
        )
    )

    log.info(f"Account {user.username} created through signup")
    return build_create_schema(token, raw_token)
