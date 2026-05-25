"""
Hash passwords using MD5 and SHA1.

Note: MD5 and SHA1 are broken for security — we use them here only
to demonstrate why weak passwords fail quickly in lab exercises.
"""

import hashlib


def hash_md5(plain_text: str) -> str:
    """
    Return the MD5 hash of a string as a lowercase hex digest.

    Example: hash_md5("hello") -> "5d41402abc4b2a76b9719d911017c592"
    """
    encoded = plain_text.encode("utf-8")
    return hashlib.md5(encoded).hexdigest()


def hash_sha1(plain_text: str) -> str:
    """
    Return the SHA1 hash of a string as a lowercase hex digest.

    Example: hash_sha1("hello") -> "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
    """
    encoded = plain_text.encode("utf-8")
    return hashlib.sha1(encoded).hexdigest()


def hash_password(plain_text: str, algorithm: str) -> str:
    """
    Hash a password with the chosen algorithm.

    Args:
        plain_text: The password to hash.
        algorithm: Either "md5" or "sha1" (case-insensitive).

    Returns:
        Hex digest string.

    Raises:
        ValueError: If algorithm is not supported.
    """
    algo = algorithm.lower().strip()
    if algo == "md5":
        return hash_md5(plain_text)
    if algo == "sha1":
        return hash_sha1(plain_text)
    raise ValueError(f"Unsupported algorithm: {algorithm}. Use 'md5' or 'sha1'.")
