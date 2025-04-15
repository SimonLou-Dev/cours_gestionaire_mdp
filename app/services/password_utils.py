import re
from collections import Counter
from app.services import crypto

def password_strength(password: str) -> str:
    length = len(password)
    if length < 6:
        return "faible"
    elif length >= 8 and re.search(r"[A-Z]", password) and re.search(r"[0-9]", password) and re.search(r"[!@#$%^&*]", password):
        return "fort"
    else:
        return "moyen"

def analyze_passwords(entries):
    decrypted = []
    duplicates = []
    seen = Counter()
    for e in entries:
        # Assume AES key is managed separately
        pass_plain = "decrypted_example"  # Stub value
        decrypted.append({"title": e.title, "strength": password_strength(pass_plain)})
        seen[pass_plain] += 1
    for key, count in seen.items():
        if count > 1:
            duplicates.append(key)
    return {"entries": decrypted, "duplicates": duplicates}
