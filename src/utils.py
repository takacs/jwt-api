import bcrypt
import base64
import time
import hmac
import hashlib
import json
from typing import Optional
import uuid

SECRET_KEY = "jotty-jot-jot"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_SECONDS = 60
REFRESH_TOKEN_EXPIRE_SECONDS = 60 * 60 * 24 * 7


def verify_password(plain_password: str, hashed_password: bytes) -> bool:
    return bcrypt.checkpw(plain_password.encode(), hashed_password)


def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def create_access_token(payload: dict, expires_in: Optional[int] = None) -> str:
    payload = payload.copy()
    header = {"alg": ALGORITHM, "typ": "JWT"}
    expires_at = int(time.time()) + (expires_in or ACCESS_TOKEN_EXPIRE_SECONDS)
    payload.update({"exp": expires_at, "type": "access"})

    header_b64 = base64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = base64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    message = f"{header_b64}.{payload_b64}".encode()

    signature = hmac.new(
        key=SECRET_KEY.encode(), msg=message, digestmod=hashlib.sha256
    ).digest()
    signature_b64 = base64url_encode(signature)

    return f"{header_b64}.{payload_b64}.{signature_b64}"


def verify_access_token(access_token: str) -> Optional[dict]:
    try:
        parts = access_token.split(".")
        if len(parts) != 3:
            return None

        header_b64, payload_b64, signature_b64 = parts
        message = f"{header_b64}.{payload_b64}".encode()

        expected_signature = hmac.new(
            key=SECRET_KEY.encode(), msg=message, digestmod=hashlib.sha256
        ).digest()
        expected_signature_b64 = base64url_encode(expected_signature)

        if not hmac.compare_digest(signature_b64, expected_signature_b64):
            return None

        padded_payload_b64 = payload_b64 + "=" * (-len(payload_b64) % 4)
        payload_json = base64.urlsafe_b64decode(padded_payload_b64.encode()).decode()
        payload = json.loads(payload_json)

        if "exp" not in payload or int(payload["exp"]) < int(time.time()):
            return None

        if payload.get("type") != "access":
            return None

        return payload
    except Exception:
        return None


def verify_refresh_token(refresh_token: str) -> Optional[dict]:
    try:
        parts = refresh_token.split(".")
        if len(parts) != 3:
            return None

        header_b64, payload_b64, signature_b64 = parts
        message = f"{header_b64}.{payload_b64}".encode()

        expected_signature = hmac.new(
            key=SECRET_KEY.encode(), msg=message, digestmod=hashlib.sha256
        ).digest()
        expected_signature_b64 = base64url_encode(expected_signature)

        if not hmac.compare_digest(signature_b64, expected_signature_b64):
            return None

        padded_payload_b64 = payload_b64 + "=" * (-len(payload_b64) % 4)
        payload_json = base64.urlsafe_b64decode(padded_payload_b64.encode()).decode()
        payload = json.loads(payload_json)

        if "exp" not in payload or int(payload["exp"]) < int(time.time()):
            return None

        if payload.get("type") != "refresh":
            return None

        return payload
    except Exception:
        return None


def create_refresh_token(
    payload: dict, expires_in: Optional[int] = None
) -> tuple[str, int]:
    header = {"alg": ALGORITHM, "typ": "JWT"}
    expires_at = int(time.time()) + (expires_in or REFRESH_TOKEN_EXPIRE_SECONDS)

    refresh_payload = payload.copy()
    refresh_payload.update(
        {
            "exp": expires_at,
            "type": "refresh",
            "jti": str(uuid.uuid4()),
        }
    )

    header_b64 = base64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = base64url_encode(
        json.dumps(refresh_payload, separators=(",", ":")).encode()
    )
    message = f"{header_b64}.{payload_b64}".encode()

    signature = hmac.new(
        key=SECRET_KEY.encode(), msg=message, digestmod=hashlib.sha256
    ).digest()
    signature_b64 = base64url_encode(signature)

    return (f"{header_b64}.{payload_b64}.{signature_b64}", expires_at)
