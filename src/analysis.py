"""
Member 2: Cryptanalysis and AI analysis helpers.

- entropy analysis (Shannon entropy)
- statistical pattern analysis
- build/train ML password-strength classifier
- simulate attack prediction using the model
- compare hash computation times (md5 vs sha1)

This module is intentionally self-contained and depends only on numpy/pandas/scikit-learn.
"""
from __future__ import annotations

import math
import random
import string
import time
import pickle
from collections import Counter
from pathlib import Path
from typing import Iterable

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    ent = 0.0
    for c in counts.values():
        p = c / length
        ent -= p * math.log2(p)
    return ent


def password_features(passwords: Iterable[str]) -> pd.DataFrame:
    rows = []
    for p in passwords:
        length = len(p)
        digits = sum(c.isdigit() for c in p)
        lower = sum(c.islower() for c in p)
        upper = sum(c.isupper() for c in p)
        special = length - (digits + lower + upper)
        unique_chars = len(set(p))
        entropy = shannon_entropy(p)
        rows.append(
            {
                "password": p,
                "length": length,
                "digits": digits,
                "lower": lower,
                "upper": upper,
                "special": special,
                "unique_chars": unique_chars,
                "entropy": entropy,
            }
        )
    return pd.DataFrame(rows)


def analyze_patterns(passwords: Iterable[str], top_n: int = 10) -> dict:
    df = password_features(passwords)
    length_counts = df["length"].value_counts().sort_index().to_dict()

    # common prefixes/suffixes (first/last 3 chars)
    prefixes = Counter(p[:3] for p in df["password"] if len(p) >= 1)
    suffixes = Counter(p[-3:] for p in df["password"] if len(p) >= 1)

    # common 3-grams
    ngrams = Counter()
    for p in df["password"]:
        for i in range(max(0, len(p) - 3 + 1)):
            ngrams[p[i : i + 3]] += 1

    return {
        "length_counts": length_counts,
        "top_prefixes": prefixes.most_common(top_n),
        "top_suffixes": suffixes.most_common(top_n),
        "top_3grams": ngrams.most_common(top_n),
        "feature_frame": df,
    }


def generate_strong_passwords(count: int = 500, min_len: int = 10, max_len: int = 16) -> list[str]:
    out = []
    alphabet = string.ascii_letters + string.digits + string.punctuation
    for _ in range(count):
        length = random.randint(min_len, max_len)
        # ensure mixed classes
        pwd = [
            random.choice(string.ascii_lowercase),
            random.choice(string.ascii_uppercase),
            random.choice(string.digits),
            random.choice(string.punctuation),
        ]
        pwd += [random.choice(alphabet) for _ in range(length - len(pwd))]
        random.shuffle(pwd)
        out.append("".join(pwd))
    return out


def build_training_set(weak_passwords: Iterable[str], strong_passwords: Iterable[str]):
    weak = list(weak_passwords)
    strong = list(strong_passwords)
    dfw = password_features(weak)
    dfs = password_features(strong)
    dfw["label"] = 1  # 1 = weak
    dfs["label"] = 0  # 0 = strong
    df = pd.concat([dfw, dfs], ignore_index=True)
    X = df[["length", "digits", "lower", "upper", "special", "unique_chars", "entropy"]]
    y = df["label"].values
    return X, y, df


def train_password_strength_model(X: pd.DataFrame, y: np.ndarray) -> Pipeline:
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    pipe = Pipeline([("scale", StandardScaler()), ("rf", clf)])
    pipe.fit(X, y)
    return pipe


def simulate_attack_prediction(model: Pipeline, candidate_passwords: Iterable[str], top_n: int = 20) -> list[tuple[str, float]]:
    df = password_features(candidate_passwords)
    X = df[["length", "digits", "lower", "upper", "special", "unique_chars", "entropy"]]
    # model predicts probability of label 1 (weak)
    probs = model.predict_proba(X)[:, 1]
    df["weak_prob"] = probs
    ranked = df.sort_values("weak_prob", ascending=False)
    return list(zip(ranked["password"].tolist()[:top_n], ranked["weak_prob"].tolist()[:top_n]))


def compare_hash_times(sample_passwords: Iterable[str], iterations: int = 1000) -> dict:
    from src.hasher import hash_md5, hash_sha1

    samples = list(sample_passwords)
    if not samples:
        samples = ["password123", "admin", "QwErTy!@#"]

    # run timing
    def time_fn(fn):
        start = time.perf_counter()
        for i in range(iterations):
            pw = samples[i % len(samples)]
            fn(pw)
        end = time.perf_counter()
        return (end - start) / iterations

    md5_avg = time_fn(hash_md5)
    sha1_avg = time_fn(hash_sha1)
    return {"md5_avg_seconds": md5_avg, "sha1_avg_seconds": sha1_avg}


def run_member2(paths: dict | None = None) -> dict:
    """High-level runner for Member 2 tasks.

    paths: optional dict with keys: project_root (Path)
    Returns: results dict containing analysis outputs and file paths saved.
    """
    if paths is None:
        project_root = Path(__file__).resolve().parents[1]
    else:
        project_root = Path(paths.get("project_root", Path(__file__).resolve().parents[1]))

    data_dir = project_root / "data"
    output_dir = project_root / "output" / "results"
    output_dir.mkdir(parents=True, exist_ok=True)

    pwd_file = data_dir / "passwords.txt"
    passwords = []
    if pwd_file.exists():
        with open(pwd_file, "r", encoding="utf-8") as fh:
            passwords = [l.strip() for l in fh if l.strip()]

    # 1) entropy and pattern analysis
    pattern = analyze_patterns(passwords)
    feature_frame = pattern["feature_frame"]
    feature_csv = output_dir / "member2_features.csv"
    feature_frame.to_csv(feature_csv, index=False)

    # 2) generate strong passwords and train model
    strong = generate_strong_passwords(count=max(500, len(passwords)))
    X, y, full_df = build_training_set(passwords, strong)
    model = train_password_strength_model(X, y)
    model_file = output_dir / "member2_model.pkl"
    with open(model_file, "wb") as fh:
        pickle.dump(model, fh)

    # 3) simulate attack prediction
    top_targets = simulate_attack_prediction(model, passwords, top_n=20)
    attack_txt = output_dir / "member2_attack_prediction.txt"
    with open(attack_txt, "w", encoding="utf-8") as fh:
        fh.write("Top predicted weak passwords (probability)\n")
        fh.write("=\n")
        for pwd, prob in top_targets:
            fh.write(f"{prob:.4f}: {pwd}\n")

    # 4) compare hash computation times
    hash_times = compare_hash_times(passwords[:10], iterations=2000)
    hash_txt = output_dir / "member2_hash_timings.txt"
    with open(hash_txt, "w", encoding="utf-8") as fh:
        fh.write("Hash timing (average seconds per hash)\n")
        fh.write(f"MD5: {hash_times['md5_avg_seconds']:.8f}\n")
        fh.write(f"SHA1: {hash_times['sha1_avg_seconds']:.8f}\n")

    # 5) save a human-readable summary
    summary = output_dir / "member2_summary.txt"
    with open(summary, "w", encoding="utf-8") as fh:
        fh.write("Member 2 Analysis Summary\n")
        fh.write("=\n")
        fh.write(f"Passwords analyzed: {len(passwords)}\n")
        fh.write(f"Feature CSV: {feature_csv}\n")
        fh.write(f"Trained model: {model_file}\n")
        fh.write(f"Attack predictions: {attack_txt}\n")
        fh.write(f"Hash timings: {hash_txt}\n")

    return {
        "feature_csv": str(feature_csv),
        "model_file": str(model_file),
        "attack_prediction": str(attack_txt),
        "hash_timings": hash_times,
        "summary_file": str(summary),
    }


if __name__ == "__main__":
    import json

    out = run_member2()
    print("Member 2 tasks complete. Summary:")
    print(json.dumps(out, indent=2))
