"""
Save and load password hashes from text files.

File format (one entry per line):
    hash_value:original_password

The original password is stored only for lab grading — in real attacks
the attacker does not know the plaintext.
"""

from pathlib import Path


def save_hashes(entries: list[tuple[str, str]], filepath: Path) -> None:
    """
    Write hash entries to a text file.

    Args:
        entries: List of (hash_hex, plain_password) tuples.
        filepath: Output file path.
    """
    filepath.parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as file:
        for hash_value, plain_password in entries:
            file.write(f"{hash_value}:{plain_password}\n")


def load_hashes(filepath: Path) -> list[tuple[str, str]]:
    """
    Read hash entries from a text file.

    Returns:
        List of (hash_hex, plain_password) tuples.
    """
    if not filepath.exists():
        return []

    entries = []
    with open(filepath, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()
            if not line or ":" not in line:
                continue
            hash_part, password_part = line.split(":", 1)
            entries.append((hash_part.strip(), password_part.strip()))
    return entries


def load_hash_targets_only(filepath: Path) -> list[str]:
    """
    Load only hash values (what an attacker would see).

    Returns:
        List of hash hex strings.
    """
    entries = load_hashes(filepath)
    return [h for h, _ in entries]
