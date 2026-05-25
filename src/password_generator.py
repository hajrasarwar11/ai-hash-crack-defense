"""
Generate a dataset of weak passwords for security lab exercises.

Weak passwords are short, common, or predictable — easy targets for
dictionary and brute-force attacks.
"""

from pathlib import Path


# Common weak passwords used in real-world breaches (educational sample only)
COMMON_WEAK_PASSWORDS = [
    "123456",
    "password",
    "12345678",
    "qwerty",
    "abc123",
    "111111",
    "12345",
    "dragon",
    "master",
    "hello",
    "admin",
    "letmein",
    "welcome",
    "monkey",
    "login",
    "pass",
    "test",
    "guest",
    "root",
    "toor",
]


def generate_weak_passwords(extra_count: int = 10) -> list[str]:
    """
    Build a list of weak passwords.

    Args:
        extra_count: How many numeric-only passwords to add (e.g. 1000, 1001).

    Returns:
        List of password strings.
    """
    passwords = list(COMMON_WEAK_PASSWORDS)

    # Add simple numeric patterns (still very weak)
    for i in range(extra_count):
        passwords.append(str(1000 + i))

    # Remove duplicates while keeping order
    seen = set()
    unique = []
    for pwd in passwords:
        if pwd not in seen:
            seen.add(pwd)
            unique.append(pwd)

    return unique


def save_passwords(passwords: list[str], filepath: Path) -> None:
    """Write one password per line to a text file."""
    filepath.parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as file:
        for password in passwords:
            file.write(password + "\n")


def load_passwords(filepath: Path) -> list[str]:
    """Read passwords from a text file (one per line)."""
    if not filepath.exists():
        return []
    with open(filepath, "r", encoding="utf-8") as file:
        return [line.strip() for line in file if line.strip()]


def build_dictionary(passwords: list[str], filepath: Path) -> None:
    """
    Save an extended dictionary for dictionary attacks.
    Includes the weak passwords plus extra wordlist entries.
    """
    extra_words = ["sunshine", "princess", "football", "shadow", "superman"]
    dictionary = list(dict.fromkeys(passwords + extra_words))
    save_passwords(dictionary, filepath)
