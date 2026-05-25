"""
Secure hashing utilities for Member 3 (bcrypt, argon2, salting, key stretching).
"""
import bcrypt
from argon2 import PasswordHasher
import os

# Bcrypt hashing with salt
def hash_bcrypt(password: str, rounds: int = 12) -> str:
    salt = bcrypt.gensalt(rounds)
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

# Argon2 hashing
def hash_argon2(password: str) -> str:
    ph = PasswordHasher()
    return ph.hash(password)

# Verify bcrypt hash
def verify_bcrypt(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

# Verify argon2 hash
def verify_argon2(password: str, hashed: str) -> bool:
    ph = PasswordHasher()
    try:
        ph.verify(hashed, password)
        return True
    except Exception:
        return False

# Generate a random salt (for demonstration, not needed with bcrypt/argon2)
def generate_salt(length: int = 16) -> str:
    return os.urandom(length).hex()
