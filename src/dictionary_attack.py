"""
Dictionary attack: try every word in a wordlist against target hashes.

A dictionary attack is fast when passwords are common words from leaks.
"""

import time
from pathlib import Path

from src.hasher import hash_password


def dictionary_attack(
    target_hashes: list[str],
    dictionary_path: Path,
    algorithm: str,
) -> dict:
    """
    Attempt to crack hashes using a dictionary file.

    Args:
        target_hashes: List of hash hex strings to crack.
        dictionary_path: Text file with one candidate password per line.
        algorithm: "md5" or "sha1".

    Returns:
        Dictionary with keys:
            - cracked: {hash: password} for recovered passwords
            - attempts: number of hash computations tried
            - elapsed_seconds: time spent
            - success_rate: percent of targets cracked
    """
    # Build a set for O(1) lookup when we find a match
    targets = set(target_hashes)
    cracked = {}

    # Load wordlist from disk
    with open(dictionary_path, "r", encoding="utf-8") as file:
        wordlist = [line.strip() for line in file if line.strip()]

    start_time = time.perf_counter()
    attempts = 0

    for candidate in wordlist:
        # Stop early if we cracked everything
        if len(cracked) >= len(targets):
            break

        digest = hash_password(candidate, algorithm)
        attempts += 1

        if digest in targets and digest not in cracked:
            cracked[digest] = candidate

    elapsed = time.perf_counter() - start_time
    total = len(target_hashes)
    success_rate = (len(cracked) / total * 100) if total else 0.0

    return {
        "attack_type": "dictionary",
        "algorithm": algorithm,
        "cracked": cracked,
        "attempts": attempts,
        "elapsed_seconds": elapsed,
        "total_targets": total,
        "success_rate": success_rate,
    }
