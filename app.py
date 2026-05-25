"""
Cryptanalysis of Weak Password Hashing Systems and AI-Based Defence Mechanism
Main Streamlit Frontend — uses all src/ modules directly
"""

import sys
import io
import time
import math
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import streamlit as st
from pathlib import Path
from collections import Counter

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.hasher import hash_md5, hash_sha1, hash_password
from src.password_generator import generate_weak_passwords, build_dictionary, save_passwords
from src.secure_hasher import hash_bcrypt, hash_argon2, verify_bcrypt, verify_argon2, generate_salt
from src.password_policy import check_password_policy, password_policy_feedback
from src.ai_weak_detector import predict_weak_password, extract_features
from src.validation_metrics import validate_improvements, measure_hash_time
from src.analysis import shannon_entropy, password_features, analyze_patterns
from src.dictionary_attack import dictionary_attack
from src.brute_force_attack import brute_force_attack
from src.metrics import format_attack_report

DATA_DIR = PROJECT_ROOT / "data"
DATA_DIR.mkdir(exist_ok=True)

# ─────────────────────────────────────────
# PAGE CONFIG
# ─────────────────────────────────────────
st.set_page_config(
    page_title="Cryptanalysis Lab",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ─────────────────────────────────────────
# CSS
# ─────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;900&family=JetBrains+Mono:wght@400;700&display=swap');

html, body, [class*="css"] { font-family: 'Inter', sans-serif !important; }

.stApp, .main, [data-testid="stAppViewContainer"],
[data-testid="stAppViewBlockContainer"] {
    background-color: #0b0f1a !important;
}

section[data-testid="stSidebar"] {
    background: #060910 !important;
    border-right: 1px solid #1e2a3a !important;
}
section[data-testid="stSidebar"] * { color: #c9d4e0 !important; }

html, body, p, span, div, label, li, .stMarkdown, .stText {
    color: #c9d4e0 !important;
}

.stButton > button {
    background: #0f1e35 !important;
    color: #4fc3f7 !important;
    border: 1px solid #1e4a7a !important;
    border-radius: 4px !important;
    font-weight: 700 !important;
    letter-spacing: 1px !important;
    text-transform: uppercase !important;
    font-size: 0.78rem !important;
    width: 100%;
    transition: all 0.15s !important;
}
.stButton > button:hover {
    background: #4fc3f7 !important;
    color: #0b0f1a !important;
    border-color: #4fc3f7 !important;
}

.stTextInput > div > div > input,
.stTextArea > div > div > textarea {
    background: #0f1e35 !important;
    color: #e0eaff !important;
    border: 1px solid #1e4a7a !important;
    border-radius: 4px !important;
    font-family: 'JetBrains Mono', monospace !important;
}
.stSelectbox > div > div {
    background: #0f1e35 !important;
    color: #e0eaff !important;
    border: 1px solid #1e4a7a !important;
}
.stSelectbox svg { fill: #4fc3f7 !important; }

[data-testid="stMetric"] {
    background: #0f1e35 !important;
    border: 1px solid #1e4a7a !important;
    padding: 1rem;
    border-radius: 6px;
}
[data-testid="stMetric"] * { color: #e0eaff !important; }
[data-testid="stMetricLabel"] {
    font-size: 0.62rem !important;
    letter-spacing: 2px !important;
    text-transform: uppercase !important;
    color: #6e9cc4 !important;
}
[data-testid="stMetricValue"] {
    font-size: 1.3rem !important;
    font-weight: 900 !important;
    font-family: 'JetBrains Mono', monospace !important;
    color: #4fc3f7 !important;
}

.stTabs [data-baseweb="tab-list"] {
    border-bottom: 1px solid #1e4a7a !important;
    background: transparent !important;
    gap: 0;
}
.stTabs [data-baseweb="tab"] {
    font-weight: 700 !important;
    letter-spacing: 2px !important;
    font-size: 0.68rem !important;
    text-transform: uppercase !important;
    padding: 0.6rem 0.9rem !important;
    color: #6e9cc4 !important;
    background: transparent !important;
}
.stTabs [aria-selected="true"] {
    border-bottom: 2px solid #4fc3f7 !important;
    color: #4fc3f7 !important;
}

.stProgress > div > div > div { background: #4fc3f7 !important; }
.stProgress > div > div { background: #1e2a3a !important; }

code, .stCode {
    background: #0f1e35 !important;
    color: #7fff7f !important;
    font-family: 'JetBrains Mono', monospace !important;
    border: 1px solid #1e4a7a !important;
}
[data-testid="stDataFrame"] { background: #0f1e35 !important; }
[data-testid="stExpander"] {
    background: #0f1e35 !important;
    border: 1px solid #1e2a3a !important;
}
[data-testid="stExpander"] * { color: #c9d4e0 !important; }
hr { border-color: #1e2a3a !important; }
[data-testid="stAlert"] { border-radius: 4px !important; }
</style>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────
def page_header(title, subtitle=""):
    st.markdown(f"""
    <div style="background:linear-gradient(135deg,#071428,#0f2040);
         padding:2rem 2rem 1.4rem;margin-bottom:1.2rem;
         border-bottom:2px solid #1e4a7a;border-radius:0 0 8px 8px;">
        <div style="color:#4fc3f7;font-size:1.7rem;font-weight:900;letter-spacing:3px;">{title}</div>
        {"<div style='color:#6e9cc4;font-size:0.8rem;letter-spacing:2px;margin-top:0.3rem;text-transform:uppercase;'>" + subtitle + "</div>" if subtitle else ""}
    </div>
    """, unsafe_allow_html=True)


def section(text):
    st.markdown(f"""
    <div style="font-size:0.7rem;font-weight:700;letter-spacing:4px;text-transform:uppercase;
         color:#4fc3f7;border-bottom:1px solid #1e4a7a;padding-bottom:0.3rem;margin:1rem 0 0.7rem;">
         {text}</div>""", unsafe_allow_html=True)


def make_chart(fig):
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=130, bbox_inches="tight",
                facecolor="#0b0f1a", edgecolor="none")
    plt.close(fig)
    buf.seek(0)
    return buf


def style_axes(ax, title=""):
    ax.set_facecolor("#0f1e35")
    ax.tick_params(colors="#6e9cc4", labelsize=8)
    for spine in ax.spines.values():
        spine.set_edgecolor("#1e4a7a")
    if title:
        ax.set_title(title, color="#4fc3f7", fontsize=10, fontweight="bold", pad=8)
    ax.xaxis.label.set_color("#6e9cc4")
    ax.yaxis.label.set_color("#6e9cc4")


# ─────────────────────────────────────────
# SIDEBAR
# ─────────────────────────────────────────
with st.sidebar:
    st.markdown("""
    <div style='text-align:center;padding:1rem 0;'>
        <div style='font-size:1.5rem;font-weight:900;color:#4fc3f7;letter-spacing:3px;'>🔐 CRYPTLAB</div>
        <div style='font-size:0.62rem;color:#3a6a9a;letter-spacing:2px;margin-top:4px;'>VULNERABILITY ASSESSMENT</div>
    </div>""", unsafe_allow_html=True)
    st.markdown("---")

    page = st.radio("Navigation", [
        "🏠  Overview",
        "⚙️  Member 1 — Hash Lab",
        "⚔️  Member 1 — Attack Lab",
        "🔬  Member 2 — Cryptanalysis",
        "🛡️  Member 3 — Defence System",
        "📊  Validation Metrics",
    ], label_visibility="collapsed")

    st.markdown("---")
    st.markdown("<div style='font-size:0.65rem;color:#3a6a9a;letter-spacing:2px;'>PROJECT</div>", unsafe_allow_html=True)
    st.markdown("<div style='font-size:0.7rem;color:#6e9cc4;line-height:1.6;'>Cryptanalysis of Weak Password Hashing Systems and AI-Based Defence Mechanism</div>", unsafe_allow_html=True)
    st.markdown("---")
    st.caption("Tools: Python · hashlib · bcrypt · argon2 · scikit-learn · Matplotlib")


# ══════════════════════════════════════════
# PAGE: OVERVIEW
# ══════════════════════════════════════════
if "Overview" in page:
    page_header("🔐 CRYPTANALYSIS LAB", "Weak Password Hashing Systems & AI-Based Defence")

    st.markdown("""
    <div style='background:#0f1e35;border:1px solid #1e4a7a;border-radius:8px;padding:1.5rem;margin-bottom:1rem;'>
        <p style='color:#c9d4e0;line-height:1.8;'>
        This project focuses on <b style='color:#4fc3f7;'>identifying vulnerabilities</b> in weak password hashing systems,
        performing <b style='color:#4fc3f7;'>cryptanalysis</b> through dictionary and brute-force attacks, and designing
        a secure <b style='color:#4fc3f7;'>AI-based defence mechanism</b> using modern hashing algorithms and machine learning.
        </p>
    </div>
    """, unsafe_allow_html=True)

    col1, col2, col3 = st.columns(3)

    with col1:
        st.markdown("""
        <div style='background:#071428;border:1px solid #1e4a7a;border-radius:8px;padding:1.2rem;'>
            <div style='color:#f97316;font-size:0.7rem;font-weight:700;letter-spacing:3px;'>MEMBER 1</div>
            <div style='color:#e0eaff;font-size:0.95rem;font-weight:700;margin:0.4rem 0;'>Vulnerability Assessment<br>& Hash Cracking</div>
            <hr style='border-color:#1e2a3a;'/>
            <ul style='color:#6e9cc4;font-size:0.8rem;line-height:2;margin:0;padding-left:1.2rem;'>
                <li>Implement MD5 / SHA-1 hashing</li>
                <li>Generate password dataset</li>
                <li>Dictionary attack</li>
                <li>Brute-force attack</li>
                <li>Measure cracking time & success rate</li>
                <li>Identify vulnerabilities (no salt)</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown("""
        <div style='background:#071428;border:1px solid #1e4a7a;border-radius:8px;padding:1.2rem;'>
            <div style='color:#a78bfa;font-size:0.7rem;font-weight:700;letter-spacing:3px;'>MEMBER 2</div>
            <div style='color:#e0eaff;font-size:0.95rem;font-weight:700;margin:0.4rem 0;'>Cryptanalysis<br>& AI Analysis</div>
            <hr style='border-color:#1e2a3a;'/>
            <ul style='color:#6e9cc4;font-size:0.8rem;line-height:2;margin:0;padding-left:1.2rem;'>
                <li>Entropy analysis (Shannon)</li>
                <li>Statistical pattern analysis</li>
                <li>Build ML classifier</li>
                <li>Simulate attack prediction</li>
                <li>Compare hash computation times</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)

    with col3:
        st.markdown("""
        <div style='background:#071428;border:1px solid #1e4a7a;border-radius:8px;padding:1.2rem;'>
            <div style='color:#34d399;font-size:0.7rem;font-weight:700;letter-spacing:3px;'>MEMBER 3</div>
            <div style='color:#e0eaff;font-size:0.95rem;font-weight:700;margin:0.4rem 0;'>Defence System<br>& Validation</div>
            <hr style='border-color:#1e2a3a;'/>
            <ul style='color:#6e9cc4;font-size:0.8rem;line-height:2;margin:0;padding-left:1.2rem;'>
                <li>Secure hashing (bcrypt / argon2)</li>
                <li>Salting & key stretching</li>
                <li>Password policy enforcement</li>
                <li>AI-based weak password detector</li>
                <li>Validate improvements with metrics</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    section("Tools & Technologies")

    tools = [
        ("Python", "Core language"),
        ("hashlib", "MD5 / SHA-1 hashing"),
        ("bcrypt", "Secure salted hashing"),
        ("argon2-cffi", "Memory-hard hashing"),
        ("scikit-learn", "ML password classifier"),
        ("NumPy / Pandas", "Data analysis"),
        ("Matplotlib", "Attack visualisation"),
    ]
    cols = st.columns(4)
    for i, (tool, desc) in enumerate(tools):
        with cols[i % 4]:
            st.markdown(f"""
            <div style='background:#0f1e35;border:1px solid #1e2a3a;border-radius:6px;
                 padding:0.7rem;margin-bottom:0.5rem;text-align:center;'>
                <div style='color:#4fc3f7;font-weight:700;font-size:0.85rem;'>{tool}</div>
                <div style='color:#6e9cc4;font-size:0.7rem;'>{desc}</div>
            </div>""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    section("Validation Metrics Tracked")
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Attack Success Rate", "Measured", "dictionary + brute-force")
    m2.metric("Crack Time", "Measured", "perf_counter")
    m3.metric("Entropy Improvement", "Calculated", "Shannon bits")
    m4.metric("Hash Speed Ratio", "Compared", "MD5 vs bcrypt")


# ══════════════════════════════════════════
# PAGE: MEMBER 1 — HASH LAB
# ══════════════════════════════════════════
elif "Hash Lab" in page:
    page_header("⚙️ MEMBER 1 — HASH LAB", "Weak Hashing: MD5 & SHA-1 Vulnerability Demonstration")

    tab1, tab2, tab3 = st.tabs(["HASH A PASSWORD", "GENERATE DATASET", "VULNERABILITY DEMO"])

    with tab1:
        section("Live MD5 / SHA-1 Hashing")
        st.info("MD5 and SHA-1 are **cryptographically broken** — used here only to demonstrate why weak passwords are easy to crack.")

        inp_col, algo_col = st.columns([3, 1])
        with inp_col:
            pwd_input = st.text_input("", placeholder="Enter any password...", label_visibility="collapsed")
        with algo_col:
            algo = st.selectbox("", ["md5", "sha1", "both"], label_visibility="collapsed")

        if pwd_input:
            st.markdown("<br>", unsafe_allow_html=True)
            section("Hash Output")
            if algo in ("md5", "both"):
                h = hash_md5(pwd_input)
                c1, c2 = st.columns([1, 3])
                c1.markdown("<div style='color:#f97316;font-weight:700;padding-top:0.5rem;'>MD5</div>", unsafe_allow_html=True)
                c2.code(h, language=None)
            if algo in ("sha1", "both"):
                h = hash_sha1(pwd_input)
                c1, c2 = st.columns([1, 3])
                c1.markdown("<div style='color:#a78bfa;font-weight:700;padding-top:0.5rem;'>SHA-1</div>", unsafe_allow_html=True)
                c2.code(h, language=None)

            st.markdown("---")
            section("Why This Is Dangerous")
            vc1, vc2, vc3 = st.columns(3)
            vc1.error("✗  No salt added — same password always gives same hash")
            vc2.error("✗  Extremely fast — attackers can try billions per second")
            vc3.error("✗  Rainbow table lookups crack most common passwords instantly")

    with tab2:
        section("Password Dataset Generation")
        st.write("Generate the weak password dataset used in attack simulations.")

        extra = st.slider("Extra numeric passwords to add:", 5, 50, 10)

        if st.button("⚡ Generate Dataset"):
            passwords = generate_weak_passwords(extra_count=extra)
            pwd_path = DATA_DIR / "passwords.txt"
            save_passwords(passwords, pwd_path)
            dict_path = DATA_DIR / "dictionary.txt"
            build_dictionary(passwords, dict_path)

            md5_entries = [(hash_md5(p), p) for p in passwords]
            sha1_entries = [(hash_sha1(p), p) for p in passwords]

            md5_path = DATA_DIR / "hashes_md5.txt"
            sha1_path = DATA_DIR / "hashes_sha1.txt"
            with open(md5_path, "w") as f:
                for h, p in md5_entries: f.write(f"{h}: {p}\n")
            with open(sha1_path, "w") as f:
                for h, p in sha1_entries: f.write(f"{h}: {p}\n")

            st.success(f"✓  Generated {len(passwords)} passwords, MD5 hashes, SHA-1 hashes, and dictionary.")

            g1, g2, g3 = st.columns(3)
            g1.metric("Total Passwords", len(passwords))
            g2.metric("Dictionary Entries", len(passwords) + 5)
            g3.metric("Hash Files Created", 2)

            section("Sample — Password → MD5 Hash")
            sample_df = pd.DataFrame(
                [(p, hash_md5(p), hash_sha1(p)) for p in passwords[:15]],
                columns=["Password", "MD5 Hash", "SHA-1 Hash"]
            )
            st.dataframe(sample_df, use_container_width=True)

    with tab3:
        section("Vulnerability: No Salt Demonstration")
        st.write("When two users have the same password, their hashes are identical — a critical security flaw.")

        test_pwds = ["password", "123456", "admin", "qwerty"]
        rows = []
        for p in test_pwds:
            rows.append({
                "Password": p,
                "MD5 (User A)": hash_md5(p),
                "MD5 (User B)": hash_md5(p),
                "Identical?": "🚨 YES — VULNERABLE"
            })
        st.dataframe(pd.DataFrame(rows), use_container_width=True)

        st.markdown("<br>", unsafe_allow_html=True)
        section("Hash Speed — Why MD5/SHA1 Are Dangerous")
        st.write("More hashes per second = attacker can try more passwords per second.")

        if st.button("🔬 Measure Hash Speed"):
            samples = ["password", "abc123", "qwerty", "letmein", "dragon"]
            iters = 10000

            t0 = time.perf_counter()
            for _ in range(iters):
                hash_md5(samples[_ % len(samples)])
            md5_t = (time.perf_counter() - t0) / iters

            t0 = time.perf_counter()
            for _ in range(iters):
                hash_sha1(samples[_ % len(samples)])
            sha1_t = (time.perf_counter() - t0) / iters

            s1, s2, s3, s4 = st.columns(4)
            s1.metric("MD5 avg time", f"{md5_t*1e6:.2f} µs")
            s2.metric("SHA-1 avg time", f"{sha1_t*1e6:.2f} µs")
            s3.metric("MD5 hashes/sec", f"{int(1/md5_t):,}")
            s4.metric("SHA-1 hashes/sec", f"{int(1/sha1_t):,}")
            st.error("🚨  Millions of hashes per second — attacker can crack weak passwords in milliseconds!")


# ══════════════════════════════════════════
# PAGE: MEMBER 1 — ATTACK LAB
# ══════════════════════════════════════════
elif "Attack Lab" in page:
    page_header("⚔️ MEMBER 1 — ATTACK LAB", "Dictionary & Brute-Force Attack Simulation")

    pwd_path  = DATA_DIR / "passwords.txt"
    dict_path = DATA_DIR / "dictionary.txt"

    if not pwd_path.exists():
        st.warning("⚠  Dataset not found. Go to **Member 1 — Hash Lab → Generate Dataset** first.")
    else:
        passwords = [l.strip() for l in pwd_path.read_text().splitlines() if l.strip()]

        tab1, tab2, tab3 = st.tabs(["DICTIONARY ATTACK", "BRUTE-FORCE ATTACK", "RESULTS & CHARTS"])

        with tab1:
            section("Dictionary Attack")
            st.write("Tries every word from a pre-built wordlist against the target hashes. **Very effective against common passwords.**")

            da_algo = st.selectbox("Hash Algorithm", ["md5", "sha1"], key="da_algo")
            da_count = st.slider("Number of target passwords to attack:", 5, min(len(passwords), 30), 10)

            if st.button("🚀 Run Dictionary Attack"):
                targets_plain = passwords[:da_count]
                target_hashes = [hash_password(p, da_algo) for p in targets_plain]

                with st.spinner("Running dictionary attack..."):
                    result = dictionary_attack(target_hashes, dict_path, da_algo)

                st.session_state["dict_result"] = result
                st.session_state["dict_algo"]   = da_algo
                st.session_state["dict_plain"]  = targets_plain

                r1, r2, r3, r4 = st.columns(4)
                r1.metric("Targets",      result["total_targets"])
                r2.metric("Cracked",      len(result["cracked"]))
                r3.metric("Success Rate", f"{result['success_rate']:.1f}%")
                r4.metric("Time",         f"{result['elapsed_seconds']:.4f}s")
                r5, r6 = st.columns(2)
                r5.metric("Attempts",     f"{result['attempts']:,}")
                r6.metric("Algorithm",    da_algo.upper())

                if result["cracked"]:
                    section("Recovered Passwords")
                    cracked_df = pd.DataFrame(
                        [(h[:20]+"...", p) for h, p in result["cracked"].items()],
                        columns=["Hash (truncated)", "Cracked Password"]
                    )
                    st.dataframe(cracked_df, use_container_width=True)
                    st.success(f"✓  Dictionary attack cracked {len(result['cracked'])} out of {result['total_targets']} hashes!")
                else:
                    st.info("No passwords cracked — try generating a fresh dataset first.")

            elif "dict_result" in st.session_state:
                result = st.session_state["dict_result"]
                r1, r2, r3, r4 = st.columns(4)
                r1.metric("Targets",      result["total_targets"])
                r2.metric("Cracked",      len(result["cracked"]))
                r3.metric("Success Rate", f"{result['success_rate']:.1f}%")
                r4.metric("Time",         f"{result['elapsed_seconds']:.4f}s")

        with tab2:
            section("Brute-Force Attack")
            st.write("Tries **every possible character combination** up to a max length. Exhaustive but slow — effective on very short passwords.")

            bf_algo   = st.selectbox("Hash Algorithm", ["md5", "sha1"], key="bf_algo")
            bf_maxlen = st.slider("Max password length to try:", 2, 5, 3)
            bf_count  = st.slider("Number of short target passwords:", 1, 5, 3)
            bf_charset = st.selectbox("Character set", [
                "abcdefghijklmnopqrstuvwxyz0123456789",
                "abcdefghijklmnopqrstuvwxyz",
                "0123456789",
            ])

            if st.button("💥 Run Brute-Force Attack"):
                short_pwds = [p for p in passwords if len(p) <= bf_maxlen][:bf_count]
                if not short_pwds:
                    st.warning(f"No passwords of length ≤ {bf_maxlen} in dataset. Generating sample targets.")
                    short_pwds = ["abc", "123", "hi"][:bf_count]

                target_hashes = [hash_password(p, bf_algo) for p in short_pwds]

                with st.spinner(f"Running brute-force (max_len={bf_maxlen}, charset size={len(bf_charset)})..."):
                    result = brute_force_attack(
                        target_hashes, bf_algo,
                        charset=bf_charset,
                        min_length=1,
                        max_length=bf_maxlen,
                        max_attempts=2_000_000,
                    )

                st.session_state["brute_result"] = result

                b1, b2, b3, b4 = st.columns(4)
                b1.metric("Targets",      result["total_targets"])
                b2.metric("Cracked",      len(result["cracked"]))
                b3.metric("Success Rate", f"{result['success_rate']:.1f}%")
                b4.metric("Time",         f"{result['elapsed_seconds']:.4f}s")
                b5, b6 = st.columns(2)
                b5.metric("Attempts Made",    f"{result['attempts']:,}")
                b6.metric("Search Space",     f"{len(bf_charset)**bf_maxlen:,} (max len)")

                if result["cracked"]:
                    section("Recovered Passwords")
                    cracked_df = pd.DataFrame(
                        [(h[:20]+"...", p) for h, p in result["cracked"].items()],
                        columns=["Hash (truncated)", "Cracked Password"]
                    )
                    st.dataframe(cracked_df, use_container_width=True)

        with tab3:
            section("Attack Comparison Charts")
            if "dict_result" not in st.session_state and "brute_result" not in st.session_state:
                st.info("Run attacks in the other tabs first to see comparison charts here.")
            else:
                results = []
                if "dict_result" in st.session_state:
                    results.append(st.session_state["dict_result"])
                if "brute_result" in st.session_state:
                    results.append(st.session_state["brute_result"])

                labels = []
                for r in results:
                    atk = r["attack_type"].replace("_", " ").title()
                    labels.append(f"{atk}\n({r['algorithm'].upper()})")

                fig, axes = plt.subplots(1, 3, figsize=(13, 4))
                fig.patch.set_facecolor("#0b0f1a")

                success = [r["success_rate"] for r in results]
                axes[0].bar(labels, success, color=["#f97316", "#a78bfa"][:len(results)], edgecolor="#1e4a7a")
                axes[0].set_ylabel("Success Rate (%)", color="#6e9cc4")
                axes[0].set_ylim(0, 110)
                for bar, v in zip(axes[0].patches, success):
                    axes[0].text(bar.get_x()+bar.get_width()/2, bar.get_height()+1, f"{v:.1f}%", ha="center", color="#e0eaff", fontsize=9)
                style_axes(axes[0], "Success Rate (%)")

                times = [r["elapsed_seconds"] for r in results]
                axes[1].bar(labels, times, color=["#4fc3f7", "#34d399"][:len(results)], edgecolor="#1e4a7a")
                axes[1].set_ylabel("Time (seconds)", color="#6e9cc4")
                for bar, v in zip(axes[1].patches, times):
                    axes[1].text(bar.get_x()+bar.get_width()/2, bar.get_height(), f"{v:.3f}s", ha="center", va="bottom", color="#e0eaff", fontsize=9)
                style_axes(axes[1], "Cracking Time (s)")

                attempts = [r["attempts"] for r in results]
                axes[2].bar(labels, attempts, color=["#f472b6", "#facc15"][:len(results)], edgecolor="#1e4a7a")
                axes[2].set_ylabel("Attempts", color="#6e9cc4")
                axes[2].set_yscale("log")
                style_axes(axes[2], "Hash Attempts (log)")

                plt.tight_layout()
                st.image(make_chart(fig), use_container_width=True)


# ══════════════════════════════════════════
# PAGE: MEMBER 2 — CRYPTANALYSIS
# ══════════════════════════════════════════
elif "Cryptanalysis" in page:
    page_header("🔬 MEMBER 2 — CRYPTANALYSIS", "Entropy Analysis · Statistical Patterns · ML Model · Hash Timing")

    pwd_path = DATA_DIR / "passwords.txt"
    if not pwd_path.exists():
        passwords = generate_weak_passwords(extra_count=10)
    else:
        passwords = [l.strip() for l in pwd_path.read_text().splitlines() if l.strip()]

    tab1, tab2, tab3, tab4 = st.tabs(["ENTROPY ANALYSIS", "PATTERN STATISTICS", "ML CLASSIFIER", "HASH TIMING"])

    with tab1:
        section("Shannon Entropy Analysis")
        st.write("Entropy (bits) measures unpredictability. Higher entropy = harder to crack.")

        ent_input = st.text_input("Enter a password to calculate entropy:", placeholder="e.g. P@ssw0rd!2024")
        if ent_input:
            ent = shannon_entropy(ent_input)
            feats = password_features([ent_input]).iloc[0]

            ec1, ec2, ec3, ec4 = st.columns(4)
            ec1.metric("Shannon Entropy", f"{ent:.3f} bits/char")
            ec2.metric("Length", int(feats["length"]))
            ec3.metric("Unique Chars", int(feats["unique_chars"]))
            ec4.metric("Charset Entropy", f"{int(feats['length'] * ent):.1f} total bits")

            if ent < 2.0:
                st.error("✗  Very LOW entropy — easily predictable, very weak password.")
            elif ent < 3.0:
                st.warning("⚠  Moderate entropy — some patterns detected.")
            else:
                st.success("✓  High entropy — good randomness and unpredictability.")

        st.markdown("---")
        section("Entropy Distribution — Dataset")

        df_feats = password_features(passwords)
        df_feats["entropy"] = [shannon_entropy(p) for p in passwords]

        fig, axes = plt.subplots(1, 2, figsize=(12, 4))
        fig.patch.set_facecolor("#0b0f1a")

        axes[0].hist(df_feats["entropy"], bins=12, color="#4fc3f7", edgecolor="#0b0f1a", alpha=0.85)
        axes[0].set_xlabel("Shannon Entropy (bits/char)")
        axes[0].set_ylabel("Password Count")
        style_axes(axes[0], "Entropy Distribution")

        axes[1].scatter(df_feats["length"], df_feats["entropy"], color="#f97316", alpha=0.7, s=40, edgecolors="#1e4a7a")
        axes[1].set_xlabel("Password Length")
        axes[1].set_ylabel("Entropy (bits/char)")
        style_axes(axes[1], "Length vs Entropy")

        plt.tight_layout()
        st.image(make_chart(fig), use_container_width=True)

    with tab2:
        section("Statistical Pattern Analysis")

        df_feats2 = password_features(passwords)
        df_feats2["entropy"] = [shannon_entropy(p) for p in passwords]

        p1, p2, p3, p4 = st.columns(4)
        p1.metric("Avg Length",       f"{df_feats2['length'].mean():.1f}")
        p2.metric("Avg Entropy",      f"{df_feats2['entropy'].mean():.2f} bits")
        p3.metric("Avg Unique Chars", f"{df_feats2['unique_chars'].mean():.1f}")
        p4.metric("Total Passwords",  len(passwords))

        patterns = analyze_patterns(passwords, top_n=8)

        fig, axes = plt.subplots(1, 3, figsize=(14, 4))
        fig.patch.set_facecolor("#0b0f1a")

        len_counts = patterns["length_counts"]
        axes[0].bar(list(len_counts.keys()), list(len_counts.values()), color="#a78bfa", edgecolor="#0b0f1a")
        axes[0].set_xlabel("Password Length")
        axes[0].set_ylabel("Count")
        style_axes(axes[0], "Length Distribution")

        top_pref = patterns["top_prefixes"][:8]
        axes[1].barh([p[0] for p in top_pref], [p[1] for p in top_pref], color="#f97316", edgecolor="#0b0f1a")
        axes[1].set_xlabel("Frequency")
        style_axes(axes[1], "Top Prefixes (first 3 chars)")

        feat_means = df_feats2[["digits","lower","upper","special"]].mean()
        axes[2].bar(["Digits","Lower","Upper","Special"], feat_means.values,
                    color=["#4fc3f7","#34d399","#f97316","#a78bfa"], edgecolor="#0b0f1a")
        axes[2].set_ylabel("Avg Count per Password")
        style_axes(axes[2], "Char Type Breakdown")

        plt.tight_layout()
        st.image(make_chart(fig), use_container_width=True)

        section("Password Feature Table (Sample)")
        st.dataframe(df_feats2.head(15), use_container_width=True)

    with tab3:
        section("ML Password Strength Classifier")
        st.write("Random Forest model trained on weak vs strong passwords. Predicts whether a password is weak.")

        single_pwd = st.text_input("Test a password against the AI model:", placeholder="Enter password...")

        if single_pwd:
            prob = predict_weak_password(single_pwd)
            feats = extract_features(single_pwd)

            mc1, mc2, mc3 = st.columns(3)
            mc1.metric("Weak Probability",   f"{prob:.1%}")
            mc2.metric("Strong Probability", f"{1-prob:.1%}")
            mc3.metric("Prediction",         "WEAK" if prob > 0.5 else "STRONG")

            st.markdown(f"**Confidence Bar:**")
            st.progress(float(prob))

            if prob > 0.7:
                st.error(f"🚨  Model is {prob:.1%} confident this password is WEAK — easy attack target.")
            elif prob > 0.4:
                st.warning(f"⚠  Model is uncertain — moderate password strength.")
            else:
                st.success(f"✓  Model classifies this as STRONG ({(1-prob):.1%} confidence).")

        st.markdown("---")
        section("Attack Prediction — Rank Dataset by Weakness")
        st.write("Model ranks passwords by how likely an attacker is to crack them first.")

        if st.button("🤖 Run Attack Prediction on Dataset"):
            probs = []
            for p in passwords:
                try:
                    probs.append((p, predict_weak_password(p)))
                except Exception:
                    probs.append((p, 0.5))
            ranked = sorted(probs, key=lambda x: x[1], reverse=True)
            df_ranked = pd.DataFrame(ranked[:20], columns=["Password", "Weak Probability"])
            df_ranked["Weak Probability"] = df_ranked["Weak Probability"].apply(lambda x: f"{x:.1%}")
            df_ranked["Attack Priority"] = [f"#{i+1}" for i in range(len(df_ranked))]
            st.dataframe(df_ranked, use_container_width=True)
            st.info("Passwords at the top of this list are the first targets an attacker would try.")

    with tab4:
        section("Hash Computation Time Comparison")
        st.write("MD5 and SHA-1 are **extremely fast** — this is a vulnerability, not a feature. Attackers exploit this speed.")

        if st.button("⏱️ Run Hash Timing Benchmark"):
            samples = passwords[:10] if len(passwords) >= 5 else ["password", "abc", "123456", "admin", "qwerty"]
            iters = 5000

            with st.spinner("Benchmarking..."):
                md5_t  = measure_hash_time(hash_md5,  samples[0], iterations=iters)
                sha1_t = measure_hash_time(hash_sha1, samples[0], iterations=iters)

            t1, t2, t3, t4 = st.columns(4)
            t1.metric("MD5 avg",          f"{md5_t*1e6:.2f} µs")
            t2.metric("SHA-1 avg",        f"{sha1_t*1e6:.2f} µs")
            t3.metric("MD5 hashes/sec",   f"{int(1/md5_t):,}")
            t4.metric("SHA-1 hashes/sec", f"{int(1/sha1_t):,}")

            fig, ax = plt.subplots(figsize=(7, 3.5))
            fig.patch.set_facecolor("#0b0f1a")
            bars = ax.bar(["MD5", "SHA-1"], [md5_t*1e6, sha1_t*1e6],
                          color=["#f97316","#a78bfa"], edgecolor="#1e4a7a", width=0.4)
            for bar, v in zip(bars, [md5_t*1e6, sha1_t*1e6]):
                ax.text(bar.get_x()+bar.get_width()/2, bar.get_height()+0.01,
                        f"{v:.3f} µs", ha="center", color="#e0eaff", fontsize=10)
            ax.set_ylabel("Avg Time per Hash (µs)")
            style_axes(ax, "MD5 vs SHA-1 — Average Hash Time")
            plt.tight_layout()
            st.image(make_chart(fig), use_container_width=True)
            st.error("🚨  At millions of hashes/sec, weak passwords fall in seconds. Use bcrypt/argon2 instead!")


# ══════════════════════════════════════════
# PAGE: MEMBER 3 — DEFENCE SYSTEM
# ══════════════════════════════════════════
elif "Defence" in page:
    page_header("🛡️ MEMBER 3 — DEFENCE SYSTEM", "Secure Hashing · Salting · Password Policy · AI Detection")

    tab1, tab2, tab3, tab4 = st.tabs(["SECURE HASHING", "SALTING DEMO", "PASSWORD POLICY", "AI WEAK DETECTOR"])

    with tab1:
        section("bcrypt & Argon2 — Secure Hashing")
        st.write("Modern algorithms are **intentionally slow** with built-in salting — designed to resist brute-force attacks.")

        sec_pwd = st.text_input("Enter a password to securely hash:", placeholder="Any password...", key="sec_hash_input")

        if sec_pwd:
            sh1, sh2 = st.columns(2)

            with sh1:
                st.markdown("<div style='color:#34d399;font-weight:700;letter-spacing:2px;font-size:0.8rem;'>BCRYPT</div>", unsafe_allow_html=True)
                if st.button("🔒 Hash with bcrypt"):
                    with st.spinner("Hashing..."):
                        t0 = time.perf_counter()
                        bh = hash_bcrypt(sec_pwd)
                        bt = time.perf_counter() - t0
                    st.code(bh, language=None)
                    st.metric("Time taken", f"{bt*1000:.1f} ms")
                    st.success("✓  bcrypt includes automatic salt — every hash is unique!")
                    v = verify_bcrypt(sec_pwd, bh)
                    st.metric("Verification", "✓ PASS" if v else "✗ FAIL")

            with sh2:
                st.markdown("<div style='color:#4fc3f7;font-weight:700;letter-spacing:2px;font-size:0.8rem;'>ARGON2</div>", unsafe_allow_html=True)
                if st.button("🔒 Hash with Argon2"):
                    with st.spinner("Hashing..."):
                        t0 = time.perf_counter()
                        ah = hash_argon2(sec_pwd)
                        at = time.perf_counter() - t0
                    st.code(ah, language=None)
                    st.metric("Time taken", f"{at*1000:.1f} ms")
                    st.success("✓  Argon2 is memory-hard — resistant to GPU attacks!")
                    v = verify_argon2(sec_pwd, ah)
                    st.metric("Verification", "✓ PASS" if v else "✗ FAIL")

        st.markdown("---")
        section("Why Slow Hashing Matters")
        sc1, sc2, sc3 = st.columns(3)
        sc1.success("✓  bcrypt: ~100ms per hash → ~10 attempts/sec for attacker")
        sc2.success("✓  Argon2: memory-hard → GPU farms ineffective")
        sc3.success("✓  Cost factor configurable → grows with hardware improvements")

    with tab2:
        section("Salting Demonstration")
        st.write("A **salt** is random data added before hashing. Same password + different salt = completely different hash.")

        salt_pwd = st.text_input("Password to salt and hash:", placeholder="e.g. password123", key="salt_input")

        if salt_pwd and st.button("🎲 Generate Salted Hashes"):
            salts  = [generate_salt() for _ in range(4)]
            rows = []
            for s in salts:
                salted = salt_pwd + s
                rows.append({
                    "Salt (hex)":        s,
                    "Salted Input":      salted[:20] + "...",
                    "MD5(password+salt)": hash_md5(salted),
                })
            st.dataframe(pd.DataFrame(rows), use_container_width=True)
            st.success("✓  Same password produces 4 completely different hashes — rainbow table attacks defeated!")

        st.markdown("---")
        section("bcrypt Built-in Salting")
        st.write("bcrypt automatically generates and embeds a unique salt in every hash output.")

        salt_demo_pwd = st.text_input("Password:", placeholder="test password", key="bcrypt_salt_demo")
        if salt_demo_pwd and st.button("Show bcrypt Salt Demo"):
            h1 = hash_bcrypt(salt_demo_pwd)
            h2 = hash_bcrypt(salt_demo_pwd)
            sd1, sd2 = st.columns(2)
            sd1.markdown("**Hash 1:**")
            sd1.code(h1, language=None)
            sd2.markdown("**Hash 2 (same password):**")
            sd2.code(h2, language=None)
            st.success(f"✓  Match 1=2? {h1 == h2} — Different every time, but both verify correctly!")

    with tab3:
        section("Password Policy Enforcement")
        st.write("Strong password policies prevent weak passwords from entering the system in the first place.")

        pol_pwd = st.text_input("Test a password against policy:", placeholder="e.g. mypassword", key="pol_input")

        if pol_pwd:
            compliant = check_password_policy(pol_pwd)
            feedback  = password_policy_feedback(pol_pwd)

            if compliant:
                st.success("✓  Password meets all policy requirements!")
            else:
                st.error("✗  Password fails policy check!")

            section("Policy Checklist")
            rules = [
                ("Minimum 8 characters",                len(pol_pwd) >= 8),
                ("Contains uppercase letter (A-Z)",     any(c.isupper() for c in pol_pwd)),
                ("Contains lowercase letter (a-z)",     any(c.islower() for c in pol_pwd)),
                ("Contains digit (0-9)",                any(c.isdigit() for c in pol_pwd)),
                ("Contains special character (!@#...)", any(not c.isalnum() for c in pol_pwd)),
            ]
            for rule, passed in rules:
                if passed:
                    st.success(f"✓  {rule}")
                else:
                    st.error(f"✗  {rule}")

        st.markdown("---")
        section("Batch Policy Audit")
        batch = st.text_area("Paste passwords (one per line):", height=120,
                              placeholder="password123\nAdmin@2024!\nabc")
        if batch.strip() and st.button("Run Policy Audit"):
            pwds = [p.strip() for p in batch.strip().splitlines() if p.strip()]
            rows = []
            for p in pwds:
                fb = password_policy_feedback(p)
                rows.append({
                    "Password (masked)": "*" * len(p),
                    "Compliant": "✓" if not fb else "✗",
                    "Issues": "; ".join(fb) if fb else "None",
                })
            df = pd.DataFrame(rows)
            st.dataframe(df, use_container_width=True)
            pass_pct = (df["Compliant"] == "✓").sum() / len(df) * 100
            st.metric("Policy Compliance Rate", f"{pass_pct:.1f}%")

    with tab4:
        section("AI-Based Weak Password Detector")
        st.write("Machine learning model (21 features) predicts if a password is weak, trained on thousands of real-world examples.")

        ai_pwd = st.text_input("Enter password for AI analysis:", placeholder="Any password...", key="ai_input")

        if ai_pwd:
            prob = predict_weak_password(ai_pwd)
            feats = extract_features(ai_pwd).iloc[0]

            ac1, ac2, ac3 = st.columns(3)
            ac1.metric("AI: Weak Probability",   f"{prob:.1%}")
            ac2.metric("AI: Strong Probability", f"{1-prob:.1%}")
            ac3.metric("Classification",         "⚠ WEAK" if prob > 0.5 else "✓ STRONG")

            st.progress(float(prob))

            section("Feature Breakdown (21 Features)")
            feat_dict = feats.to_dict()
            fd1, fd2, fd3 = st.columns(3)
            items = list(feat_dict.items())
            for i, (k, v) in enumerate(items):
                col = [fd1, fd2, fd3][i % 3]
                col.metric(k.replace("_", " ").title(), round(float(v), 3))


# ══════════════════════════════════════════
# PAGE: VALIDATION METRICS
# ══════════════════════════════════════════
elif "Validation" in page:
    page_header("📊 VALIDATION METRICS", "Measuring Security Improvements — Weak vs Secure Systems")

    pwd_path = DATA_DIR / "passwords.txt"
    if not pwd_path.exists():
        passwords = generate_weak_passwords(extra_count=10)
    else:
        passwords = [l.strip() for l in pwd_path.read_text().splitlines() if l.strip()]

    st.write("Run the full validation to compare weak hashing (MD5/SHA-1) vs secure hashing (bcrypt/Argon2) and AI detection.")

    if st.button("🔬 Run Full Validation"):
        with st.spinner("Running validation metrics — bcrypt/argon2 are intentionally slow..."):
            metrics = validate_improvements(passwords[:10])

        section("Hash Speed Comparison — Weak vs Secure")
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("MD5 avg time",     f"{metrics['md5_time']*1000:.4f} ms", delta="FAST = DANGEROUS", delta_color="inverse")
        m2.metric("SHA-1 avg time",   f"{metrics['sha1_time']*1000:.4f} ms", delta="FAST = DANGEROUS", delta_color="inverse")
        m3.metric("bcrypt avg time",  f"{metrics['bcrypt_time']*1000:.1f} ms", delta="SLOW = SECURE", delta_color="normal")
        m4.metric("Argon2 avg time",  f"{metrics['argon2_time']*1000:.1f} ms", delta="SLOW = SECURE", delta_color="normal")

        bcrypt_ratio  = metrics['bcrypt_time']  / metrics['md5_time']
        argon2_ratio  = metrics['argon2_time']  / metrics['md5_time']

        section("Security Improvement Factors")
        r1, r2, r3 = st.columns(3)
        r1.metric("bcrypt vs MD5 (speed ratio)",  f"{bcrypt_ratio:,.0f}x slower", delta="harder to brute-force", delta_color="normal")
        r2.metric("Argon2 vs MD5 (speed ratio)",  f"{argon2_ratio:,.0f}x slower", delta="harder to brute-force", delta_color="normal")
        r3.metric("AI Weak Detection Avg",         f"{metrics['avg_weak_prob']:.1%}", delta="correctly identifies weak")

        st.markdown("---")
        section("Visual Comparison")

        fig, axes = plt.subplots(1, 3, figsize=(15, 5))
        fig.patch.set_facecolor("#0b0f1a")

        algos = ["MD5", "SHA-1", "bcrypt", "Argon2"]
        times = [
            metrics["md5_time"]    * 1000,
            metrics["sha1_time"]   * 1000,
            metrics["bcrypt_time"] * 1000,
            metrics["argon2_time"] * 1000,
        ]
        colors = ["#ef4444","#f97316","#34d399","#4fc3f7"]

        axes[0].bar(algos, times, color=colors, edgecolor="#1e4a7a")
        axes[0].set_ylabel("Time per hash (ms)")
        axes[0].set_yscale("log")
        for bar, v in zip(axes[0].patches, times):
            axes[0].text(bar.get_x()+bar.get_width()/2, bar.get_height()*1.05,
                         f"{v:.3f}", ha="center", color="#e0eaff", fontsize=8)
        style_axes(axes[0], "Hash Speed Comparison (log scale)")

        hashes_per_sec = [int(1/(t/1000)) for t in times]
        axes[1].bar(algos, hashes_per_sec, color=colors, edgecolor="#1e4a7a")
        axes[1].set_ylabel("Hashes per second")
        axes[1].set_yscale("log")
        style_axes(axes[1], "Hashes/sec — Attacker Speed")

        attack_time_sec = [hs / 1e9 for hs in hashes_per_sec]  # assume 1B password keyspace
        axes[2].bar(algos, [1/h if h > 0 else 0 for h in hashes_per_sec],
                    color=colors, edgecolor="#1e4a7a")
        axes[2].set_ylabel("Seconds per attempt")
        axes[2].set_yscale("log")
        style_axes(axes[2], "Attacker: Time per Attempt (log)")

        plt.tight_layout()
        st.image(make_chart(fig), use_container_width=True)

        section("Summary — Security Gains")
        st.markdown(f"""
        <div style='background:#0f1e35;border:1px solid #1e4a7a;border-radius:8px;padding:1.5rem;'>
        <table style='width:100%;border-collapse:collapse;font-size:0.85rem;'>
        <tr style='border-bottom:1px solid #1e4a7a;'>
            <th style='color:#4fc3f7;padding:0.5rem;text-align:left;'>Metric</th>
            <th style='color:#ef4444;padding:0.5rem;'>MD5 (Weak)</th>
            <th style='color:#ef4444;padding:0.5rem;'>SHA-1 (Weak)</th>
            <th style='color:#34d399;padding:0.5rem;'>bcrypt (Secure)</th>
            <th style='color:#4fc3f7;padding:0.5rem;'>Argon2 (Secure)</th>
        </tr>
        <tr style='border-bottom:1px solid #0f1e35;'>
            <td style='color:#c9d4e0;padding:0.5rem;'>Avg Hash Time</td>
            <td style='color:#ef4444;padding:0.5rem;text-align:center;'>{metrics["md5_time"]*1000:.4f} ms</td>
            <td style='color:#ef4444;padding:0.5rem;text-align:center;'>{metrics["sha1_time"]*1000:.4f} ms</td>
            <td style='color:#34d399;padding:0.5rem;text-align:center;'>{metrics["bcrypt_time"]*1000:.1f} ms</td>
            <td style='color:#4fc3f7;padding:0.5rem;text-align:center;'>{metrics["argon2_time"]*1000:.1f} ms</td>
        </tr>
        <tr style='border-bottom:1px solid #0f1e35;'>
            <td style='color:#c9d4e0;padding:0.5rem;'>Built-in Salt</td>
            <td style='color:#ef4444;padding:0.5rem;text-align:center;'>✗ No</td>
            <td style='color:#ef4444;padding:0.5rem;text-align:center;'>✗ No</td>
            <td style='color:#34d399;padding:0.5rem;text-align:center;'>✓ Yes</td>
            <td style='color:#4fc3f7;padding:0.5rem;text-align:center;'>✓ Yes</td>
        </tr>
        <tr style='border-bottom:1px solid #0f1e35;'>
            <td style='color:#c9d4e0;padding:0.5rem;'>GPU Resistant</td>
            <td style='color:#ef4444;padding:0.5rem;text-align:center;'>✗ No</td>
            <td style='color:#ef4444;padding:0.5rem;text-align:center;'>✗ No</td>
            <td style='color:#34d399;padding:0.5rem;text-align:center;'>⚠ Partial</td>
            <td style='color:#4fc3f7;padding:0.5rem;text-align:center;'>✓ Yes (memory-hard)</td>
        </tr>
        <tr>
            <td style='color:#c9d4e0;padding:0.5rem;'>Recommended Use</td>
            <td style='color:#ef4444;padding:0.5rem;text-align:center;'>Never</td>
            <td style='color:#ef4444;padding:0.5rem;text-align:center;'>Never</td>
            <td style='color:#34d399;padding:0.5rem;text-align:center;'>✓ Passwords</td>
            <td style='color:#4fc3f7;padding:0.5rem;text-align:center;'>✓ Best Choice</td>
        </tr>
        </table>
        </div>
        """, unsafe_allow_html=True)

        section("Conclusion")
        st.markdown("""
        <div style='background:#071428;border-left:4px solid #34d399;padding:1.2rem;border-radius:0 6px 6px 0;'>
            <p style='color:#c9d4e0;line-height:1.8;margin:0;'>
            This project demonstrates that <b style='color:#ef4444;'>MD5 and SHA-1</b> are fundamentally broken for password storage —
            they are too fast, have no salting, and are trivially crackable via dictionary and brute-force attacks.
            The proposed defence system using <b style='color:#34d399;'>bcrypt/Argon2</b> with built-in salting,
            combined with an <b style='color:#4fc3f7;'>AI-based weak password detector</b> and
            <b style='color:#a78bfa;'>strict password policies</b>, significantly improves security
            and drastically reduces the attack success rate.
            </p>
        </div>
        """, unsafe_allow_html=True)


# ─────────────────────────────────────────
# FOOTER
# ─────────────────────────────────────────
st.markdown("---")
st.markdown("""
<div style='text-align:center;padding:0.8rem;'>
    <span style='color:#3a6a9a;font-size:0.7rem;letter-spacing:2px;'>
    CRYPTANALYSIS OF WEAK PASSWORD HASHING SYSTEMS AND AI-BASED DEFENCE MECHANISM
    </span>
</div>
""", unsafe_allow_html=True)
