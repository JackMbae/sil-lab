"""Generate a short-lived lab JWT for the 'dr-wanjiku' consumer (no extra packages needed).
Run: python scripts/make_jwt.py
"""
import base64, hashlib, hmac, json, time

SECRET = b"CHANGE_ME_lab_only_secret_min_32_chars_long"   # must match gateway/kong.yml


def b64(d: bytes) -> str:
    return base64.urlsafe_b64encode(d).rstrip(b"=").decode()


header = {"alg": "HS256", "typ": "JWT"}
payload = {"iss": "lab-issuer", "sub": "dr-wanjiku", "exp": int(time.time()) + 900}  # 15-minute token
signing_input = f"{b64(json.dumps(header).encode())}.{b64(json.dumps(payload).encode())}"
sig = hmac.new(SECRET, signing_input.encode(), hashlib.sha256).digest()
print(f"{signing_input}.{b64(sig)}")
