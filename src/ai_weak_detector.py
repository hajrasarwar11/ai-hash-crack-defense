"""
AI-based weak password detector using PassGuard's trained model.
"""
import pickle
import os
import numpy as np
import pandas as pd
from pathlib import Path

# Path to AI/models (new location)
AI_MODELS_DIR = Path(__file__).resolve().parents[1] / 'AI' / 'models'
MODEL_PATH = AI_MODELS_DIR / 'model.pkl'
SCALER_PATH = AI_MODELS_DIR / 'scaler.pkl'


# Feature extraction (21 features, matches PassGuard backend)
import re
from collections import Counter
import math

def extract_features(password: str) -> pd.DataFrame:
    p      = str(password)
    length = len(p)
    num_upper   = sum(1 for c in p if c.isupper())
    num_lower   = sum(1 for c in p if c.islower())
    num_digits  = sum(1 for c in p if c.isdigit())
    num_special = sum(1 for c in p if not c.isalnum())
    unique_chars = len(set(p))
    freq    = Counter(p)
    entropy = (
        -sum((v / length) * math.log2(v / length) for v in freq.values())
        if length > 0 else 0.0
    )
    features = {
        "length":              length,
        "num_upper":           num_upper,
        "num_lower":           num_lower,
        "num_digits":          num_digits,
        "num_special":         num_special,
        "has_upper":           int(num_upper > 0),
        "has_lower":           int(num_lower > 0),
        "has_digit":           int(num_digits > 0),
        "has_special":         int(num_special > 0),
        "unique_chars":        unique_chars,
        "char_variety_ratio":  unique_chars / max(length, 1),
        "entropy":             round(entropy, 4),
        "starts_with_cap":     int(p[0].isupper() if p else 0),
        "ends_with_digit":     int(p[-1].isdigit() if p else 0),
        "sequential_nums":     int(bool(re.search(r"(012|123|234|345|456|567|678|789)", p))),
        "repeated_chars":      int(bool(re.search(r"(.)\1\1", p))),
        "common_weak_pattern": int(bool(re.search(
            r"(password|qwerty|abc|111|000|admin|login|welcome"
            r"|pakistan|lahore|imran|iloveyou|apnapass|mera123|allah786"
            r"|karachi|islamabad|peshawar|multan)", p.lower()))),
        "only_letters":        int(p.isalpha()),
        "only_digits":         int(p.isdigit()),
        "digit_ratio":         num_digits / max(length, 1),
        "special_ratio":       num_special / max(length, 1),
    }
    return pd.DataFrame([features])

def load_model():
    with open(MODEL_PATH, 'rb') as f:
        model = pickle.load(f)
    with open(SCALER_PATH, 'rb') as f:
        scaler = pickle.load(f)
    return model, scaler

def predict_weak_password(password: str) -> float:
    model, scaler = load_model()
    features = extract_features(password)
    features_scaled = scaler.transform(features)
    prob_weak = model.predict_proba(features_scaled)[0][1]
    return prob_weak
