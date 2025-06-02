import jwt
import time

secret = "myjwtsecretislongerthanwhatyouwouldexpectonanormaldayoutinthesunshine"
payload = {
    "sub": "1234567890",
    "name": "John Doe",
    "iat": int(time.time()),
    "nbf": int(time.time()),
    "exp": int(time.time()) + 600,
    "jti": "047bc3c6-b8e1-4e6e-9d62-50b5a058a9d2",
    "scope": "foo bar"
}

token = jwt.encode(payload, secret, algorithm="HS256")
print(token)
