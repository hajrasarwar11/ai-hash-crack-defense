"""
backend.py — PassGuard ML Logic
All ML functions, feature engineering, predictions, and utilities.
"""

import re
import math
import pickle
import random
import string
import hashlib
import urllib.request
import numpy as np
import pandas as pd
from collections import Counter
from pathlib import Path

# ─────────────────────────────────────────────────────────────
# PATHS
# ─────────────────────────────────────────────────────────────
BASE_DIR    = Path(__file__).parent
MODEL_PATH  = BASE_DIR / "models" / "model.pkl"
SCALER_PATH = BASE_DIR / "models" / "scaler.pkl"

# ─────────────────────────────────────────────────────────────
# LOAD MODEL
# ─────────────────────────────────────────────────────────────
def load_model():
    try:
        with open(MODEL_PATH, "rb") as f:
            return pickle.load(f)
    except FileNotFoundError:
        return None

def load_scaler():
    try:
        with open(SCALER_PATH, "rb") as f:
            return pickle.load(f)
    except FileNotFoundError:
        return None

MODEL  = load_model()
SCALER = load_scaler()

# ─────────────────────────────────────────────────────────────
# FEATURE EXTRACTION
# ─────────────────────────────────────────────────────────────
def extract_features(password: str) -> dict:
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
    return {
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

# ─────────────────────────────────────────────────────────────
# PREDICT STRENGTH
# ─────────────────────────────────────────────────────────────
def predict_strength(password: str):
    feats = extract_features(password)
    if MODEL is None:
        score = 0
        if feats["length"] >= 8:             score += 1
        if feats["length"] >= 12:            score += 1
        if feats["has_upper"]:               score += 1
        if feats["has_digit"]:               score += 1
        if feats["has_special"]:             score += 1
        if feats["common_weak_pattern"]:     score -= 2
        score = max(0, score)
        if score <= 2:   return 0, [0.85, 0.10, 0.05]
        elif score <= 3: return 1, [0.10, 0.75, 0.15]
        else:            return 2, [0.05, 0.15, 0.80]
    feat_df = pd.DataFrame([feats])
    pred    = int(MODEL.predict(feat_df)[0])
    proba   = MODEL.predict_proba(feat_df)[0].tolist()
    return pred, proba

# ─────────────────────────────────────────────────────────────
# ENTROPY
# ─────────────────────────────────────────────────────────────
def calculate_entropy(password: str) -> float:
    charset = 0
    if re.search(r"[a-z]", password):        charset += 26
    if re.search(r"[A-Z]", password):        charset += 26
    if re.search(r"[0-9]", password):        charset += 10
    if re.search(r"[^a-zA-Z0-9]", password): charset += 32
    if charset == 0 or not password:          return 0.0
    return round(len(password) * math.log2(charset), 2)

# ─────────────────────────────────────────────────────────────
# CRACK TIME
# ─────────────────────────────────────────────────────────────
def estimate_crack_time(password: str):
    charset = 0
    if re.search(r"[a-z]", password):        charset += 26
    if re.search(r"[A-Z]", password):        charset += 26
    if re.search(r"[0-9]", password):        charset += 10
    if re.search(r"[^a-zA-Z0-9]", password): charset += 32
    if not password or charset == 0:
        return "Instantly", "Brute Force", 0
    combinations = charset ** len(password)
    gpu_speed    = 1_000_000_000
    seconds      = combinations / gpu_speed
    if seconds < 1:           t = "Instantly"
    elif seconds < 60:        t = f"{int(seconds)} seconds"
    elif seconds < 3600:      t = f"{int(seconds/60)} minutes"
    elif seconds < 86400:     t = f"{int(seconds/3600)} hours"
    elif seconds < 2_592_000: t = f"{int(seconds/86400)} days"
    elif seconds < 31_536_000:t = f"{int(seconds/2_592_000)} months"
    elif seconds < 3.15e9:    t = f"{int(seconds/31_536_000)} years"
    else:                     t = f"{int(seconds/3.15e9):,}+ centuries"
    feats = extract_features(password)
    if feats["common_weak_pattern"]: attack = "Dictionary Attack"
    elif feats["only_digits"]:       attack = "Numeric Brute Force"
    elif feats["sequential_nums"]:   attack = "Pattern Attack"
    elif feats["repeated_chars"]:    attack = "Repetition Attack"
    else:                            attack = "Full Brute Force"
    return t, attack, seconds

# ─────────────────────────────────────────────────────────────
# ATTACK SIMULATION
# ─────────────────────────────────────────────────────────────
def identify_attacks(password: str) -> list:
    feats   = extract_features(password)
    attacks = []
    if feats["common_weak_pattern"]:
        attacks.append(("Dictionary Attack",
                         "Contains words found in attacker wordlists (e.g. rockyou.txt)."))
    if feats["sequential_nums"]:
        attacks.append(("Pattern Attack",
                         "Contains sequential numbers like 123, 456 — first tried by all crackers."))
    if feats["repeated_chars"]:
        attacks.append(("Repetition Attack",
                         "Has 3+ repeated characters (e.g. aaa, 111) — trivial to detect."))
    if feats["only_digits"]:
        attacks.append(("Numeric Brute Force",
                         "All digits — fastest attack type. Cracks in seconds."))
    if feats["length"] < 8:
        attacks.append(("Short Password Attack",
                         "Length < 8 — exhaustive brute force is trivial even on old hardware."))
    if not attacks:
        attacks.append(("Full Brute Force Only",
                         "No obvious pattern. Attacker must try all character combinations."))
    return attacks

# ─────────────────────────────────────────────────────────────
# BREACH CHECK (HaveIBeenPwned — k-anonymity)
# ─────────────────────────────────────────────────────────────
def check_breach(password: str):
    try:
        sha1   = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        url    = f"https://api.pwnedpasswords.com/range/{prefix}"
        req    = urllib.request.Request(url, headers={"User-Agent": "PassGuard-App"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = resp.read().decode("utf-8")
        for line in data.splitlines():
            h, count = line.split(":")
            if h == suffix:
                return True, int(count)
        return False, 0
    except Exception:
        return None, 0

# ─────────────────────────────────────────────────────────────
# PASSWORD GENERATOR
# ─────────────────────────────────────────────────────────────
def generate_password(length: int = 16) -> str:
    chars = (string.ascii_uppercase + string.ascii_lowercase
             + string.digits + "!@#$%^&*()_+-=[]{}|")
    while True:
        pwd = "".join(random.choices(chars, k=length))
        if (any(c.isupper()     for c in pwd) and
            any(c.islower()     for c in pwd) and
            any(c.isdigit()     for c in pwd) and
            any(not c.isalnum() for c in pwd)):
            return pwd

# ─────────────────────────────────────────────────────────────
# QR CODE
# ─────────────────────────────────────────────────────────────
def generate_qr_code(text: str):
    try:
        import qrcode, io
        qr  = qrcode.QRCode(box_size=6, border=2)
        qr.add_data(text)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return buf.getvalue()
    except ImportError:
        return None

# ─────────────────────────────────────────────────────────────
# IMPROVEMENT TIPS
# ─────────────────────────────────────────────────────────────
def get_tips(password: str) -> list:
    feats   = extract_features(password)
    entropy = calculate_entropy(password)
    tips    = []
    if feats["length"] < 8:
        tips.append(("bad",  "Too short — use at least 12 characters."))
    elif feats["length"] < 12:
        tips.append(("warn", f"Length {feats['length']} is okay — 16+ is recommended."))
    else:
        tips.append(("good", f"Good length: {feats['length']} characters."))
    if not feats["has_upper"]:   tips.append(("bad",  "Add uppercase letters (A-Z)."))
    else:                        tips.append(("good", "Contains uppercase letters."))
    if not feats["has_lower"]:   tips.append(("bad",  "Add lowercase letters (a-z)."))
    else:                        tips.append(("good", "Contains lowercase letters."))
    if not feats["has_digit"]:   tips.append(("bad",  "Add digits (0-9)."))
    else:                        tips.append(("good", "Contains digits."))
    if not feats["has_special"]: tips.append(("bad",  "Add special characters: @, #, !, $."))
    else:                        tips.append(("good", "Contains special characters."))
    if feats["common_weak_pattern"]:
        tips.append(("bad",  "Remove common words like 'password', 'admin', 'pakistan'."))
    if feats["repeated_chars"]:
        tips.append(("warn", "Avoid 3+ repeated characters in a row (aaa, 111)."))
    if feats["sequential_nums"]:
        tips.append(("warn", "Avoid sequential numbers like 123, 456."))
    if entropy < 40:   tips.append(("bad",  f"Entropy too low ({entropy} bits). Increase character variety."))
    elif entropy < 60: tips.append(("warn", f"Entropy moderate ({entropy} bits). Try a longer password."))
    else:              tips.append(("good", f"High entropy: {entropy} bits — excellent randomness."))
    return tips

# ─────────────────────────────────────────────────────────────
# DEGRADATION PREDICTOR
# ─────────────────────────────────────────────────────────────
def predict_degradation(password: str) -> list:
    _, _, seconds = estimate_crack_time(password)
    if seconds == 0: seconds = 0.001
    rows = []
    for year_offset in range(0, 21, 2):
        speed_mult  = 2 ** (year_offset / 2)
        future_secs = seconds / speed_mult
        if future_secs < 1:           label = "Instantly"
        elif future_secs < 60:        label = f"{int(future_secs)}s"
        elif future_secs < 3600:      label = f"{int(future_secs/60)}m"
        elif future_secs < 86400:     label = f"{int(future_secs/3600)}h"
        elif future_secs < 2592000:   label = f"{int(future_secs/86400)}d"
        elif future_secs < 31536000:  label = f"{int(future_secs/2592000)}mo"
        else:                         label = f"{int(future_secs/31536000)}yr"
        safe = future_secs > 86400 * 365
        rows.append({
            "Year":       2026 + year_offset,
            "GPU Speed":  f"{(1e9 * speed_mult)/1e9:.0f}B/s",
            "Crack Time": label,
            "Status":     "Safe" if safe else "CRACKABLE",
        })
    return rows

# ─────────────────────────────────────────────────────────────
# BATCH AUDIT
# ─────────────────────────────────────────────────────────────
def audit_batch(passwords: list) -> list:
    rows = []
    for pwd in passwords:
        pred, proba      = predict_strength(pwd)
        crack, attack, _ = estimate_crack_time(pwd)
        entropy          = calculate_entropy(pwd)
        feats            = extract_features(pwd)
        rows.append({
            "Password (masked)": "*" * len(pwd),
            "Length":            feats["length"],
            "Strength":          ["Weak", "Medium", "Strong"][pred],
            "Entropy (bits)":    entropy,
            "Crack Time":        crack,
            "Likely Attack":     attack,
            "Has Upper":         "Yes" if feats["has_upper"]   else "No",
            "Has Digit":         "Yes" if feats["has_digit"]   else "No",
            "Has Special":       "Yes" if feats["has_special"] else "No",
        })
    return rows

# ─────────────────────────────────────────────────────────────
# MULTILINGUAL WEAK PATTERNS
# ─────────────────────────────────────────────────────────────
WEAK_PATTERNS = {
    "English":    ["password", "qwerty", "admin", "login", "welcome",
                   "letmein", "iloveyou", "monkey", "dragon", "master"],
    "Pakistani":  ["pakistan", "lahore", "karachi", "islamabad", "imran",
                   "allah786", "apnapass", "mera123", "multan", "peshawar",
                   "quetta", "rawalpindi", "bismillah", "yaallah", "pyar"],
    "Arabic":     ["habib", "habibi", "alhamdulillah", "subhanallah", "mashallah"],
    "Hindi/Roman":["pyaar", "mohabbat", "dosti", "yaar123", "bhai123",
                   "india123", "hindi", "namaste"],
    "Common PIN": ["1234", "0000", "1111", "4321", "9999", "1234567890",
                   "000000", "123123"],
}

def check_multilingual_patterns(password: str) -> list:
    p     = password.lower()
    found = []
    for lang, patterns in WEAK_PATTERNS.items():
        for pat in patterns:
            if pat in p:
                found.append((lang, pat))
    return found

# ─────────────────────────────────────────────────────────────
# CSV BATCH AUDIT (upload file)
# ─────────────────────────────────────────────────────────────
def audit_csv(df_uploaded: pd.DataFrame) -> pd.DataFrame:
    """
    Accepts a DataFrame with a 'password' column.
    Returns audit results DataFrame.
    """
    if "password" not in df_uploaded.columns:
        raise ValueError("CSV must have a 'password' column.")
    passwords = df_uploaded["password"].dropna().astype(str).tolist()
    rows      = audit_batch(passwords)
    return pd.DataFrame(rows)

# ─────────────────────────────────────────────────────────────
# PASSWORD VAULT — Encrypted local storage (Fernet symmetric)
# ─────────────────────────────────────────────────────────────
def derive_key(master_password: str) -> bytes:
    """Derive a Fernet key from master password using SHA-256."""
    import base64
    digest = hashlib.sha256(master_password.encode()).digest()
    return base64.urlsafe_b64encode(digest)

def vault_encrypt(password: str, master_key: str) -> str:
    try:
        from cryptography.fernet import Fernet
        f   = Fernet(derive_key(master_key))
        enc = f.encrypt(password.encode()).decode()
        return enc
    except ImportError:
        return None

def vault_decrypt(encrypted: str, master_key: str) -> str:
    try:
        from cryptography.fernet import Fernet
        f   = Fernet(derive_key(master_key))
        dec = f.decrypt(encrypted.encode()).decode()
        return dec
    except Exception:
        return None

# ─────────────────────────────────────────────────────────────
# AI PASSWORD COACH — rule-based step-by-step guidance
# (No API key needed — logic-driven chatbot)
# ─────────────────────────────────────────────────────────────
def coach_response(user_message: str, password: str = "") -> str:
    msg = user_message.lower().strip()

    if any(w in msg for w in ["hi", "hello", "hey", "start", "help"]):
        return (
            "Hello! I'm your AI Password Coach 🔐\n\n"
            "I can help you:\n"
            "• Understand why your password is weak\n"
            "• Guide you step by step to a stronger password\n"
            "• Answer questions about password security\n\n"
            "Type your question, or type **'analyze'** and I'll look at your current password."
        )

    if "analyze" in msg or "check" in msg or "why" in msg:
        if not password:
            return "Please enter a password in the Analyze tab first, then come back here."
        pred, _  = predict_strength(password)
        feats    = extract_features(password)
        entropy  = calculate_entropy(password)
        tips     = get_tips(password)
        label    = ["Weak", "Medium", "Strong"][pred]
        bad_tips = [t for s, t in tips if s == "bad"]
        response = f"Your password is classified as **{label}**.\n\n"
        if bad_tips:
            response += "Here is why it's not strong enough:\n"
            for t in bad_tips:
                response += f"• {t}\n"
        response += f"\nEntropy score: {entropy} bits "
        response += ("(very low — easy to guess)" if entropy < 40
                     else "(moderate)" if entropy < 60
                     else "(excellent!)")
        response += "\n\nType **'fix it'** and I'll guide you step by step."
        return response

    if "fix" in msg or "improve" in msg or "how" in msg or "better" in msg:
        if not password:
            return "Enter a password in the Analyze tab first."
        feats = extract_features(password)
        steps = []
        step  = 1
        if feats["length"] < 12:
            steps.append(f"Step {step}: Make it longer — aim for at least 16 characters.")
            step += 1
        if not feats["has_upper"]:
            steps.append(f"Step {step}: Add uppercase letters — e.g. replace 'a' with 'A'.")
            step += 1
        if not feats["has_digit"]:
            steps.append(f"Step {step}: Add numbers — e.g. insert '7' or '42' somewhere.")
            step += 1
        if not feats["has_special"]:
            steps.append(f"Step {step}: Add special characters — e.g. '@', '#', '!', '$'.")
            step += 1
        if feats["common_weak_pattern"]:
            steps.append(f"Step {step}: Remove common words like 'password', 'admin', or city names.")
            step += 1
        if feats["repeated_chars"]:
            steps.append(f"Step {step}: Remove repeated characters like 'aaa' or '111'.")
            step += 1
        if not steps:
            return "Your password already looks strong! Keep it safe and never reuse it."
        return "Here is your step-by-step improvement plan:\n\n" + "\n".join(steps)

    if "entropy" in msg:
        return (
            "**Entropy** measures how unpredictable your password is, in bits.\n\n"
            "• Under 40 bits = Weak (easy to crack)\n"
            "• 40–60 bits = Moderate\n"
            "• Above 60 bits = Strong\n\n"
            "Entropy increases when you use more character types and longer passwords."
        )

    if "breach" in msg or "leaked" in msg or "pwned" in msg:
        return (
            "A **data breach** happens when hackers steal password databases from websites.\n\n"
            "If your password was in a breach, attackers already have it in their lists "
            "and will try it on every site you use.\n\n"
            "Use the **Breach Check** tab to see if your password was leaked. "
            "Your password is never sent to any server — only a partial hash is checked."
        )

    if "crack" in msg or "time" in msg:
        return (
            "**Crack time** is how long it would take a modern GPU making "
            "1 billion guesses per second to find your password by brute force.\n\n"
            "• Short/simple passwords = cracked instantly\n"
            "• 16+ chars with mixed types = centuries\n\n"
            "The longer and more random your password, the longer the crack time."
        )

    if "vault" in msg or "save" in msg or "store" in msg:
        return (
            "The **Password Vault** lets you save generated passwords encrypted with a master key.\n\n"
            "• Your passwords are encrypted using AES-256 (Fernet)\n"
            "• Only someone with the master key can decrypt them\n"
            "• Nothing is sent to any server — everything stays in your browser session\n\n"
            "Go to the **Vault** tab to save and retrieve your passwords."
        )

    if "qr" in msg:
        return (
            "The **QR Code** feature lets you scan a generated password directly onto your phone "
            "without typing it.\n\n"
            "Generate a strong password, click 'QR', then scan with your phone camera."
        )

    if "lstm" in msg or "deep learning" in msg or "neural" in msg:
        return (
            "The **LSTM model** reads your password character by character, "
            "learning patterns the way a human attacker would think.\n\n"
            "It can detect subtle weaknesses that a Random Forest might miss, "
            "like keyboard walks (qwerty, asdf) or disguised common words (p@ssw0rd).\n\n"
            "Switch to LSTM in the Analyze tab using the model selector."
        )

    return (
        "I can help with:\n"
        "• **'analyze'** — why is my password weak?\n"
        "• **'fix it'** — step by step improvement\n"
        "• **'entropy'** — what is entropy?\n"
        "• **'crack time'** — how crack time is calculated\n"
        "• **'breach'** — what is a data breach?\n"
        "• **'vault'** — how password vault works\n"
        "• **'qr'** — how QR code transfer works"
    )

# ─────────────────────────────────────────────────────────────
# VOICE PASSWORD — transcription helper
# ─────────────────────────────────────────────────────────────
def transcribe_audio(audio_bytes: bytes) -> str:
    """
    Transcribes audio using SpeechRecognition library.
    Returns transcribed text or error string.
    """
    try:
        import speech_recognition as sr
        import io, wave, struct

        recognizer = sr.Recognizer()
        audio_file = io.BytesIO(audio_bytes)

        with sr.AudioFile(audio_file) as source:
            audio_data = recognizer.record(source)

        text = recognizer.recognize_google(audio_data)
        return text
    except ImportError:
        return "ERROR: Install SpeechRecognition: pip install SpeechRecognition"
    except Exception as e:
        return f"ERROR: {str(e)}"
