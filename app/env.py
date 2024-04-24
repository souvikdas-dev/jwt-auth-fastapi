import os

secret_key: str = os.getenv("SECRET_KEY") or ""
algorithm: str = os.getenv("ALGORITHM") or ""
access_token_expire_minutes = 30
