"""
Validation metrics for secure hashing and AI improvements.
"""
import time
import numpy as np
from src.secure_hasher import hash_bcrypt, hash_argon2
from src.hasher import hash_md5, hash_sha1
from src.ai_weak_detector import predict_weak_password
from src.password_policy import check_password_policy

def measure_hash_time(hash_fn, password: str, iterations: int = 100) -> float:
    start = time.perf_counter()
    for _ in range(iterations):
        hash_fn(password)
    end = time.perf_counter()
    return (end - start) / iterations

def validate_improvements(passwords: list[str]) -> dict:
    results = {}
    # Hashing times
    results['md5_time'] = measure_hash_time(hash_md5, passwords[0])
    results['sha1_time'] = measure_hash_time(hash_sha1, passwords[0])
    results['bcrypt_time'] = measure_hash_time(hash_bcrypt, passwords[0])
    results['argon2_time'] = measure_hash_time(hash_argon2, passwords[0])
    # AI weak password detection
    weak_probs = [predict_weak_password(p) for p in passwords]
    results['avg_weak_prob'] = float(np.mean(weak_probs))
    # Password policy enforcement
    policy_pass = [check_password_policy(p) for p in passwords]
    results['policy_compliance_rate'] = float(np.mean(policy_pass))
    return results
