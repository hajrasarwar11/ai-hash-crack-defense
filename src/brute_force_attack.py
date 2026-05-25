"""
Brute-force attack: try every combination from a character set up to max length.

Brute force is exhaustive but slow. We use a small charset and max length
so the demo finishes in reasonable time on a classroom laptop.
"""

import itertools
import time

from src.hasher import hash_password


def brute_force_attack(
    target_hashes: list[str],
    algorithm: str,
    charset: str = "abcdefghijklmnopqrstuvwxyz0123456789",
    min_length: int = 1,
    max_length: int = 4,
    max_attempts: int = 500_000,
) -> dict:
    """
    Try all character combinations until hashes are cracked or limits hit.

    Args:
        target_hashes: Hash hex strings to recover.
        algorithm: "md5" or "sha1".
        charset: Characters to combine (default: lowercase + digits).
        min_length: Shortest password length to try.
        max_length: Longest password length to try.
        max_attempts: Safety cap so the demo does not run forever.

    Returns:
        Same result shape as dictionary_attack().
    """
    targets = set(target_hashes)
    cracked = {}

    start_time = time.perf_counter()
    attempts = 0

    for length in range(min_length, max_length + 1):
        # itertools.product generates every combination of charset^length
        for combo in itertools.product(charset, repeat=length):
            if attempts >= max_attempts:
                break
            if len(cracked) >= len(targets):
                break

            candidate = "".join(combo)
            digest = hash_password(candidate, algorithm)
            attempts += 1

            if digest in targets and digest not in cracked:
                cracked[digest] = candidate

        if attempts >= max_attempts or len(cracked) >= len(targets):
            break

    elapsed = time.perf_counter() - start_time
    total = len(target_hashes)
    success_rate = (len(cracked) / total * 100) if total else 0.0

    return {
        "attack_type": "brute_force",
        "algorithm": algorithm,
        "cracked": cracked,
        "attempts": attempts,
        "elapsed_seconds": elapsed,
        "total_targets": total,
        "success_rate": success_rate,
        "max_length": max_length,
        "charset_size": len(charset),
    }
