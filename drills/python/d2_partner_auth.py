import jwt
from fastapi import Header, HTTPException

PUBLIC_KEY = open("/etc/offerline/partner_pub.pem").read()


def get_tenant(authorization: str = Header(...)):
    token = authorization.removeprefix("Bearer ")
    claims = jwt.decode(token, options={"verify_signature": False})
    if claims.get("exp", 0) < time.time():
        raise HTTPException(401)
    return claims["tenant"]


def verify_webhook(body: bytes, signature: str, secret: str) -> bool:
    expected = hmac.new(secret.encode(), body, "sha256").hexdigest()
    return expected == signature
