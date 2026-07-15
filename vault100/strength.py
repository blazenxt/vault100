"""Password strength estimation for Vault100.

A local, dependency-free estimator (inspired by zxcvbn heuristics —
nothing is sent anywhere). Returns a 0–4 score plus human advice.
"""

from __future__ import annotations

import re

_LABELS = ["Very weak", "Weak", "Fair", "Strong", "Excellent"]

_COMMON = {
    "password", "123456", "12345678", "123456789", "12345", "qwerty",
    "abc123", "password1", "111111", "letmein", "iloveyou", "admin",
    "welcome", "monkey", "dragon", "football", "sunshine", "master",
    "shadow", "superman", "michael", "p@ssw0rd", "passw0rd", "trustno1",
}
_KBD_ROWS = ("qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890")
_SEQ = "abcdefghijklmnopqrstuvwxyz"

# Rough guesses/second against Argon2id (64 MiB, t=3) on a rented GPU rig.
_ATTACK_RATE = 20_000


def _entropy_bits(pw: str) -> float:
    pool = 0
    pool += 26 if re.search(r"[a-z]", pw) else 0
    pool += 26 if re.search(r"[A-Z]", pw) else 0
    pool += 10 if re.search(r"[0-9]", pw) else 0
    pool += 33 if re.search(r"[^a-zA-Z0-9]", pw) else 0
    if pool == 0:
        return 0.0
    import math
    bits = len(pw) * math.log2(pool)

    # Penalties for structure that shrinks real-world search space.
    low = pw.lower()
    if re.search(r"(.)\1{2,}", low):                    # aaa, 1111
        bits *= 0.6
    run = max((len(m.group(0)) for m in re.finditer(
        r"(.)\1+", low)), default=0)
    bits -= min(run, 6)
    for seq in (_SEQ, _SEQ[::-1], *_KBD_ROWS):
        for n in range(4, min(len(pw), 10) + 1):
            for i in range(len(seq) - n + 1):
                if seq[i:i + n] in low:
                    bits -= 3 * n / 4
                    break
    if re.search(r"\b(19|20)\d{2}\b", pw):              # years
        bits -= 6
    for word in _COMMON:
        if word in low:
            bits -= 12
            break
    if len(pw) < 8:
        bits *= 0.5
    return max(bits, 1.0)


def _crack_time(bits: float) -> str:
    seconds = 2 ** (bits - 1) / _ATTACK_RATE  # average case
    if seconds < 60:
        return "~seconds"
    if seconds < 3600:
        return f"~{seconds / 60:.0f} minutes"
    if seconds < 86400:
        return f"~{seconds / 3600:.0f} hours"
    days = seconds / 86400
    if days < 730:
        return f"~{days:.0f} days"
    years = days / 365
    if years < 1000:
        return f"~{years:.0f} years"
    for mag, label in ((1e15, "quadrillions"), (1e12, "trillions"),
                       (1e9, "billions"), (1e6, "millions"),
                       (1e3, "thousands")):
        if years >= mag:
            return f"~{years / mag:.1f} {label} of years"
    return "longer than the age of the universe"


def estimate(password: str) -> dict:
    """Return {'score': 0..4, 'label', 'crack_time', 'tips': [...]}."""
    if not password:
        return {"score": 0, "label": _LABELS[0], "crack_time": "instantly",
                "tips": ["Enter a password."]}
    if password.lower() in _COMMON:
        return {"score": 0, "label": _LABELS[0], "crack_time": "instantly",
                "tips": ["This is one of the most common passwords on Earth."]}

    bits = _entropy_bits(password)
    score = 0 if bits < 28 else 1 if bits < 40 else 2 if bits < 60 \
        else 3 if bits < 80 else 4

    tips = []
    if len(password) < 12:
        tips.append("Use at least 12 characters — length beats complexity.")
    if not re.search(r"[A-Z]", password) or not re.search(r"[0-9]", password):
        tips.append("Mix upper/lowercase and digits.")
    if not re.search(r"[^a-zA-Z0-9]", password):
        tips.append("Add symbols (e.g. !@#) or use a multi-word passphrase.")
    if score < 3:
        tips.append("A 4–5 random-word passphrase is both strong and "
                    "memorable.")

    return {"score": score, "label": _LABELS[score],
            "crack_time": _crack_time(bits), "entropy_bits": round(bits, 1),
            "tips": tips}
