"""
Password policy enforcement for Member 3.
"""
import re

def check_password_policy(password: str, min_length: int = 8, require_upper: bool = True, require_lower: bool = True, require_digit: bool = True, require_special: bool = True) -> bool:
    if len(password) < min_length:
        return False
    if require_upper and not re.search(r"[A-Z]", password):
        return False
    if require_lower and not re.search(r"[a-z]", password):
        return False
    if require_digit and not re.search(r"\d", password):
        return False
    if require_special and not re.search(r"[^A-Za-z0-9]", password):
        return False
    return True

def password_policy_feedback(password: str) -> list:
    feedback = []
    if len(password) < 8:
        feedback.append("Password must be at least 8 characters long.")
    if not re.search(r"[A-Z]", password):
        feedback.append("Password must contain at least one uppercase letter.")
    if not re.search(r"[a-z]", password):
        feedback.append("Password must contain at least one lowercase letter.")
    if not re.search(r"\d", password):
        feedback.append("Password must contain at least one digit.")
    if not re.search(r"[^A-Za-z0-9]", password):
        feedback.append("Password must contain at least one special character.")
    return feedback
