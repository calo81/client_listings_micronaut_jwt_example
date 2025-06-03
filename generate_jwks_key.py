from jwcrypto import jwk

with open("public_key.pem", "rb") as f:
    key_data = f.read()

key = jwk.JWK.from_pem(key_data)
print(key.export(private_key=False))