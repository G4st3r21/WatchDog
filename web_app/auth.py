import time

import jwt
from sqladmin.authentication import AuthenticationBackend
from starlette.requests import Request

from admin_config import JWT_SECRET, ADMIN_PASSWORD, ADMIN_LOGIN


def sign_jwt(jwt_secret: str = JWT_SECRET) -> dict[str, str]:
    payload = {
        "expires": time.time() + 86400
    }
    token = jwt.encode(payload, jwt_secret, algorithm="HS256")
    return token


def decode_jwt(token: str, jwt_secret: str = JWT_SECRET) -> dict | None:
    try:
        decoded_token = jwt.decode(token, jwt_secret, algorithms=["HS256"])
    except:
        return None
    return decoded_token if decoded_token["expires"] >= time.time() else None


class CheckUser(AuthenticationBackend):
    async def login(self, request: Request) -> bool:
        form = await request.form()
        username, password = form["username"], form["password"]
        if username == ADMIN_LOGIN and password == ADMIN_PASSWORD:
            request.session.update({"token": sign_jwt()})
            return True
        return False

    async def logout(self, request: Request) -> bool:
        # Usually you'd want to just clear the session
        request.session.clear()
        return True

    async def authenticate(self, request: Request) -> bool:
        token = request.session.get("token")

        if not token or not decode_jwt(token):
            return False

        return True
