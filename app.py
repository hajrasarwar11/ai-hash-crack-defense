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
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;900&family=JetBrains+Mono:wght@400;500;700&display=swap');

/* ── ANIMATIONS ───────────────────────────────── */
@keyframes fadeInUp {
    from { opacity: 0; transform: translateY(18px); }
    to   { opacity: 1; transform: translateY(0); }
}
@keyframes fadeIn {
    from { opacity: 0; }
    to   { opacity: 1; }
}
@keyframes slideInLeft {
    from { opacity: 0; transform: translateX(-12px); }
    to   { opacity: 1; transform: translateX(0); }
}
@keyframes goldPulse {
    0%, 100% { box-shadow: 0 0 0 0 #c9a42800; }
    50%       { box-shadow: 0 0 0 4px #c9a42818; }
}

.main .block-container {
    animation: fadeInUp 0.4s cubic-bezier(0.22, 1, 0.36, 1) both !important;
}
section[data-testid="stSidebar"] {
    animation: fadeIn 0.5s ease both !important;
}
[data-testid="stMetric"] {
    animation: fadeInUp 0.4s cubic-bezier(0.22, 1, 0.36, 1) both !important;
}
.stTabs [aria-selected="true"] {
    animation: goldPulse 2s ease infinite !important;
}
.stButton > button:active {
    transform: scale(0.97) !important;
    transition: transform 0.08s ease !important;
}

/* ── GLOBAL RESET ─────────────────────────────── */
*, *::before, *::after { box-sizing: border-box; }
html, body, [class*="css"] {
    font-family: 'Inter', sans-serif !important;
    -webkit-font-smoothing: antialiased !important;
    text-rendering: optimizeLegibility !important;
}

/* ── KILL STREAMLIT HEADER / DECORATION ───────── */
header[data-testid="stHeader"] {
    background-color: #161616 !important;
    border-bottom: 1px solid #222222 !important;
    height: 2.8rem !important;
}
[data-testid="stDecoration"] {
    background: none !important;
    background-image: none !important;
    height: 0 !important;
    display: none !important;
}
[data-testid="stToolbar"] {
    background-color: #161616 !important;
}
#MainMenu, footer { visibility: hidden !important; }

/* ── MAIN BACKGROUND ──────────────────────────── */
.stApp,
[data-testid="stAppViewContainer"],
[data-testid="stAppViewBlockContainer"],
.main,
.block-container {
    background-color: #1a1a1a !important;
}
[data-testid="stAppViewBlockContainer"] {
    padding-top: 1rem !important;
    max-width: 100% !important;
}

/* ── SIDEBAR ──────────────────────────────────── */
section[data-testid="stSidebar"] {
    background-color: #161616 !important;
    border-right: 1px solid #2a2a2a !important;
    box-shadow: 2px 0 0 0 #c9a428 !important;
}
section[data-testid="stSidebar"] > div {
    background-color: #161616 !important;
}
section[data-testid="stSidebar"] * {
    color: #b0b0b0 !important;
}

/* Sidebar radio — nav items */
[data-testid="stSidebar"] .stRadio > div {
    gap: 0 !important;
}
[data-testid="stSidebar"] .stRadio label {
    display: flex !important;
    align-items: center !important;
    padding: 0.65rem 1rem !important;
    margin: 1px 0 !important;
    border-radius: 6px !important;
    cursor: pointer !important;
    transition: background 0.15s, color 0.15s !important;
    font-size: 0.88rem !important;
    font-weight: 500 !important;
    color: #9ca3af !important;
    border-left: 3px solid transparent !important;
}
[data-testid="stSidebar"] .stRadio label:hover {
    background: #222222 !important;
    color: #e8e8e8 !important;
    border-left-color: #666666 !important;
}
[data-testid="stSidebar"] .stRadio label[data-checked="true"],
[data-testid="stSidebar"] .stRadio [aria-checked="true"] ~ label,
[data-testid="stSidebar"] .stRadio input:checked + div {
    background: #222222 !important;
    color: #c9a428 !important;
    border-left-color: #c9a428 !important;
    font-weight: 600 !important;
}
/* Hide ALL radio circles in sidebar */
[data-testid="stSidebar"] [data-baseweb="radio"] { display: none !important; }
[data-testid="stSidebar"] [role="radio"] { display: none !important; }
[data-testid="stSidebar"] .stRadio [data-testid="stWidgetLabel"] { display: none !important; }
[data-testid="stSidebar"] .stRadio span[data-baseweb="radio"] { display: none !important; }
[data-testid="stSidebar"] .stRadio div[role="radiogroup"] > label > div:first-child { display: none !important; }
[data-testid="stSidebar"] input[type="radio"] { display: none !important; }

/* ── TYPOGRAPHY ───────────────────────────────── */
html, body, p, span, div, label, li, .stMarkdown, .stText {
    color: #d0d0d0 !important;
}
h1, h2, h3, h4 { color: #f0f0f0 !important; }

/* ── BUTTONS ──────────────────────────────────── */
.stButton > button {
    background: transparent !important;
    color: #c9a428 !important;
    border: 1px solid #c9a428 !important;
    border-radius: 6px !important;
    font-weight: 600 !important;
    letter-spacing: 1.5px !important;
    text-transform: uppercase !important;
    font-size: 0.74rem !important;
    width: 100%;
    padding: 0.55rem 1rem !important;
    transition: all 0.2s ease !important;
}
.stButton > button:hover {
    background: #c9a428 !important;
    color: #161616 !important;
    box-shadow: 0 4px 20px #c9a42833 !important;
}

/* ── INPUTS ───────────────────────────────────── */
.stTextInput > div > div > input,
.stTextArea > div > div > textarea {
    background: #202020 !important;
    color: #f0f0f0 !important;
    border: 1px solid #2e2e2e !important;
    border-radius: 6px !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.88rem !important;
}
.stTextInput > div > div > input:focus,
.stTextArea > div > div > textarea:focus {
    border-color: #c9a428 !important;
    box-shadow: 0 0 0 2px #c9a42822 !important;
}
.stSelectbox > div > div {
    background: #202020 !important;
    color: #f0f0f0 !important;
    border: 1px solid #2e2e2e !important;
    border-radius: 6px !important;
}
.stSelectbox svg { fill: #c9a428 !important; }

/* ── METRICS ──────────────────────────────────── */
[data-testid="stMetric"] {
    background: #202020 !important;
    border: 1px solid #2a2a2a !important;
    border-top: 2px solid #c9a428 !important;
    padding: 1.1rem 1.2rem !important;
    border-radius: 8px !important;
}
[data-testid="stMetric"] * { color: #f0f0f0 !important; }
[data-testid="stMetricLabel"] {
    font-size: 0.62rem !important;
    letter-spacing: 2px !important;
    text-transform: uppercase !important;
    color: #888888 !important;
    font-weight: 600 !important;
}
[data-testid="stMetricValue"] {
    font-size: 1.5rem !important;
    font-weight: 800 !important;
    font-family: 'JetBrains Mono', monospace !important;
    color: #c9a428 !important;
}
[data-testid="stMetricDelta"] { font-size: 0.72rem !important; }

/* ── TABS ─────────────────────────────────────── */
.stTabs [data-baseweb="tab-list"] {
    border-bottom: 1px solid #2a2a2a !important;
    background: transparent !important;
    gap: 0 !important;
}
.stTabs [data-baseweb="tab"] {
    font-weight: 600 !important;
    letter-spacing: 2px !important;
    font-size: 0.68rem !important;
    text-transform: uppercase !important;
    padding: 0.7rem 1.2rem !important;
    color: #666666 !important;
    background: transparent !important;
    transition: color 0.15s !important;
    border-radius: 0 !important;
}
.stTabs [data-baseweb="tab"]:hover { color: #bbbbbb !important; }
.stTabs [aria-selected="true"] {
    border-bottom: 2px solid #c9a428 !important;
    color: #c9a428 !important;
}

/* ── PROGRESS ─────────────────────────────────── */
.stProgress > div > div > div {
    background: linear-gradient(90deg, #a8841e, #c9a428) !important;
    border-radius: 4px !important;
}
.stProgress > div > div { background: #2a2a2a !important; border-radius: 4px !important; }

/* ── CODE ─────────────────────────────────────── */
code, .stCode, pre {
    background: #202020 !important;
    color: #c9a428 !important;
    font-family: 'JetBrains Mono', monospace !important;
    border: 1px solid #2a2a2a !important;
    border-radius: 6px !important;
}

/* ── CARDS / EXPANDERS / DATAFRAMES ──────────── */
[data-testid="stDataFrame"] {
    background: #202020 !important;
    border: 1px solid #2a2a2a !important;
    border-radius: 8px !important;
}
[data-testid="stExpander"] {
    background: #202020 !important;
    border: 1px solid #2a2a2a !important;
    border-radius: 8px !important;
}
[data-testid="stExpander"] * { color: #d0d0d0 !important; }
[data-testid="stExpander"] summary:hover { color: #c9a428 !important; }

/* ── MISC ─────────────────────────────────────── */
hr { border-color: #2a2a2a !important; margin: 1rem 0 !important; }
[data-testid="stAlert"] { border-radius: 8px !important; }
.stCheckbox > label { color: #d0d0d0 !important; }
.stSlider > div > div > div { background: #c9a428 !important; }
[data-testid="stSlider"] > div > div > div > div { background: #2a2a2a !important; }

/* ── SCROLLBAR ────────────────────────────────── */
::-webkit-scrollbar { width: 5px; height: 5px; }
::-webkit-scrollbar-track { background: #161616; }
::-webkit-scrollbar-thumb { background: #333333; border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: #c9a428; }
</style>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────
def page_header(title, subtitle=""):
    # Strip emoji + clean title for display — ref style: small tag + big clean heading
    tag = subtitle if subtitle else ""
    st.markdown(f"""
    <div style="padding:2.2rem 0 1.6rem;margin-bottom:1.2rem;
         border-bottom:1px solid #232323;
         animation:fadeInUp 0.35s cubic-bezier(0.22,1,0.36,1) both;">
        {f'<div style="font-size:0.68rem;font-weight:600;color:#c9a428;letter-spacing:2.5px;text-transform:uppercase;margin-bottom:0.7rem;">{tag}</div>' if tag else ""}
        <div style="color:#f5f5f5;font-size:2.1rem;font-weight:300;line-height:1.2;letter-spacing:-0.3px;">{title}</div>
    </div>
    """, unsafe_allow_html=True)


def section(text):
    st.markdown(f"""
    <div style="font-size:0.66rem;font-weight:600;letter-spacing:3px;text-transform:uppercase;
         color:#888888;padding-bottom:0.45rem;margin:1.6rem 0 1rem;
         border-bottom:1px solid #232323;
         animation:slideInLeft 0.3s ease both;">
         {text}</div>""", unsafe_allow_html=True)


def make_chart(fig):
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=130, bbox_inches="tight",
                facecolor="#1a1a1a", edgecolor="none")
    plt.close(fig)
    buf.seek(0)
    return buf


def style_axes(ax, title=""):
    ax.set_facecolor("#202020")
    ax.tick_params(colors="#777777", labelsize=8)
    for spine in ax.spines.values():
        spine.set_edgecolor("#2a2a2a")
    if title:
        ax.set_title(title, color="#d0d0d0", fontsize=10, fontweight="bold", pad=10)
    ax.xaxis.label.set_color("#888888")
    ax.yaxis.label.set_color("#888888")
    ax.figure.patch.set_facecolor("#1a1a1a")


# ─────────────────────────────────────────
# SIDEBAR
# ─────────────────────────────────────────
with st.sidebar:
    st.markdown("""
    <div style='padding:1.5rem 0.5rem 1rem;'>
        <div style='font-size:1.3rem;font-weight:900;color:#c9a428;letter-spacing:4px;'>🔐 CRYPTLAB</div>
        <div style='font-size:0.58rem;color:#555555;letter-spacing:3px;margin-top:6px;text-transform:uppercase;'>Vulnerability Assessment</div>
    </div>""", unsafe_allow_html=True)
    st.markdown("<hr style='border-color:#2a2a2a;margin:0 0 1rem;'>", unsafe_allow_html=True)

    page = st.radio("Navigation", [
        "🏠  Overview",
        "⚙️  Hash Lab",
        "⚔️  Attack Simulation",
        "🔬  Cryptanalysis",
        "🛡️  Defence System",
        "📊  Validation Metrics",
        "🔍  Security Intelligence",
        "👥  About",
    ], label_visibility="collapsed")

    st.markdown("<hr style='border-color:#2a2a2a;margin:1rem 0;'>", unsafe_allow_html=True)
    st.markdown("<div style='font-size:0.6rem;color:#444444;letter-spacing:3px;text-transform:uppercase;margin-bottom:0.4rem;'>Project</div>", unsafe_allow_html=True)
    st.markdown("<div style='font-size:0.72rem;color:#666666;line-height:1.7;'>Cryptanalysis of Weak Password Hashing Systems and AI-Based Defence Mechanism</div>", unsafe_allow_html=True)
    st.markdown("<hr style='border-color:#2a2a2a;margin:1rem 0;'>", unsafe_allow_html=True)
    st.markdown("<div style='font-size:0.65rem;color:#444444;'>Python · hashlib · bcrypt · argon2 · scikit-learn</div>", unsafe_allow_html=True)


# ══════════════════════════════════════════
# PAGE: OVERVIEW
# ══════════════════════════════════════════
if "Overview" in page:
    st.markdown("""
    <div style='padding:2.5rem 0 2rem;border-bottom:1px solid #232323;
         animation:fadeInUp 0.4s cubic-bezier(0.22,1,0.36,1) both;'>
        <div style='font-size:0.68rem;font-weight:600;color:#c9a428;letter-spacing:2.5px;
             text-transform:uppercase;margin-bottom:0.9rem;'>
             Cryptanalysis Lab  ·  University Research Project
        </div>
        <div style='color:#f5f5f5;font-size:2.4rem;font-weight:300;line-height:1.15;letter-spacing:-0.5px;
             margin-bottom:1rem;'>
            Weak Password Hashing<br>
            <span style='color:#c9a428;font-weight:400;'>& AI-Based Defence</span>
        </div>
        <p style='color:#888888;line-height:1.85;max-width:700px;font-size:0.93rem;font-weight:400;margin:0;'>
            Investigating cryptographic vulnerabilities in legacy hashing algorithms (MD5, SHA-1), 
            simulating dictionary and brute-force attacks, and building a robust 
            <span style='color:#d0d0d0;'>machine-learning defence system</span> with memory-hard hashing.
        </p>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    kpi1, kpi2, kpi3, kpi4, kpi5 = st.columns(5)
    kpi1.metric("Hashing Algorithms", "4", "MD5 · SHA1 · bcrypt · Argon2")
    kpi2.metric("Attack Vectors", "2", "Dictionary + Brute-Force")
    kpi3.metric("ML Features", "21", "Random Forest Classifier")
    kpi4.metric("Defence Layers", "3", "Hash · Salt · Policy · AI")
    kpi5.metric("Report Pages", "10", "Full PDF Export")

    st.markdown("<br>", unsafe_allow_html=True)

    section("RESEARCH MODULES")
    col1, col2, col3 = st.columns(3)

    with col1:
        st.markdown("""
        <div style='background:linear-gradient(160deg,#161616,#202020);border:1px solid #2e2e2e;
             border-top:3px solid #f97316;border-radius:8px;padding:1.4rem;height:100%;'>
            <div style='display:flex;align-items:center;gap:0.5rem;margin-bottom:0.7rem;'>
                <div style='font-size:1.4rem;'>⚙️</div>
                <div style='color:#f97316;font-size:0.65rem;font-weight:700;letter-spacing:3px;'>MODULE I</div>
            </div>
            <div style='color:#f0f0f0;font-size:1rem;font-weight:800;margin-bottom:0.3rem;'>Vulnerability Assessment</div>
            <div style='color:#888888;font-size:0.75rem;margin-bottom:1rem;'>Hash Lab · Attack Simulation</div>
            <hr style='border-color:#2a2a2a;margin:0.7rem 0;'/>
            <ul style='color:#b0b0b0;font-size:0.8rem;line-height:2.1;margin:0;padding-left:1.1rem;'>
                <li>MD5 &amp; SHA-1 implementation &amp; analysis</li>
                <li>Weak password dataset generation</li>
                <li>Dictionary attack with success metrics</li>
                <li>Brute-force attack simulation</li>
                <li>Cracking time benchmarking</li>
                <li>No-salt vulnerability demonstration</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown("""
        <div style='background:linear-gradient(160deg,#161616,#202020);border:1px solid #2e2e2e;
             border-top:3px solid #a78bfa;border-radius:8px;padding:1.4rem;height:100%;'>
            <div style='display:flex;align-items:center;gap:0.5rem;margin-bottom:0.7rem;'>
                <div style='font-size:1.4rem;'>🔬</div>
                <div style='color:#a78bfa;font-size:0.65rem;font-weight:700;letter-spacing:3px;'>MODULE II</div>
            </div>
            <div style='color:#f0f0f0;font-size:1rem;font-weight:800;margin-bottom:0.3rem;'>Cryptanalysis &amp; AI</div>
            <div style='color:#888888;font-size:0.75rem;margin-bottom:1rem;'>Entropy · Patterns · ML Classifier</div>
            <hr style='border-color:#2a2a2a;margin:0.7rem 0;'/>
            <ul style='color:#b0b0b0;font-size:0.8rem;line-height:2.1;margin:0;padding-left:1.1rem;'>
                <li>Shannon entropy analysis</li>
                <li>Statistical pattern recognition</li>
                <li>Random Forest ML classifier (21 features)</li>
                <li>Attack priority prediction</li>
                <li>Hash computation speed comparison</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)

    with col3:
        st.markdown("""
        <div style='background:linear-gradient(160deg,#161616,#202020);border:1px solid #2e2e2e;
             border-top:3px solid #34d399;border-radius:8px;padding:1.4rem;height:100%;'>
            <div style='display:flex;align-items:center;gap:0.5rem;margin-bottom:0.7rem;'>
                <div style='font-size:1.4rem;'>🛡️</div>
                <div style='color:#34d399;font-size:0.65rem;font-weight:700;letter-spacing:3px;'>MODULE III</div>
            </div>
            <div style='color:#f0f0f0;font-size:1rem;font-weight:800;margin-bottom:0.3rem;'>Defence Architecture</div>
            <div style='color:#888888;font-size:0.75rem;margin-bottom:1rem;'>bcrypt · Argon2 · Policy · AI Guard</div>
            <hr style='border-color:#2a2a2a;margin:0.7rem 0;'/>
            <ul style='color:#b0b0b0;font-size:0.8rem;line-height:2.1;margin:0;padding-left:1.1rem;'>
                <li>bcrypt &amp; Argon2 secure hashing</li>
                <li>Automatic salting &amp; key stretching</li>
                <li>Multi-rule password policy engine</li>
                <li>AI-based weak password detection</li>
                <li>Quantified security improvement metrics</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    section("ATTACK PIPELINE — HOW IT WORKS")

    st.markdown("""
    <div style='display:flex;align-items:stretch;gap:0;margin:0.5rem 0 1.5rem;overflow:hidden;border-radius:8px;border:1px solid #2a2a2a;'>
        <div style='flex:1;background:#202020;padding:1.2rem;text-align:center;border-right:1px solid #2a2a2a;'>
            <div style='font-size:1.6rem;margin-bottom:0.4rem;'>🗂️</div>
            <div style='color:#f97316;font-size:0.65rem;font-weight:700;letter-spacing:2px;'>STEP 1</div>
            <div style='color:#f0f0f0;font-size:0.85rem;font-weight:700;margin-top:0.3rem;'>Dataset Generation</div>
            <div style='color:#888888;font-size:0.72rem;margin-top:0.3rem;'>Weak passwords + MD5/SHA-1 hashes</div>
        </div>
        <div style='flex:1;background:#202020;padding:1.2rem;text-align:center;border-right:1px solid #2a2a2a;'>
            <div style='font-size:1.6rem;margin-bottom:0.4rem;'>⚔️</div>
            <div style='color:#ef4444;font-size:0.65rem;font-weight:700;letter-spacing:2px;'>STEP 2</div>
            <div style='color:#f0f0f0;font-size:0.85rem;font-weight:700;margin-top:0.3rem;'>Attack Simulation</div>
            <div style='color:#888888;font-size:0.72rem;margin-top:0.3rem;'>Dictionary &amp; brute-force cracking</div>
        </div>
        <div style='flex:1;background:#202020;padding:1.2rem;text-align:center;border-right:1px solid #2a2a2a;'>
            <div style='font-size:1.6rem;margin-bottom:0.4rem;'>📊</div>
            <div style='color:#a78bfa;font-size:0.65rem;font-weight:700;letter-spacing:2px;'>STEP 3</div>
            <div style='color:#f0f0f0;font-size:0.85rem;font-weight:700;margin-top:0.3rem;'>Cryptanalysis</div>
            <div style='color:#888888;font-size:0.72rem;margin-top:0.3rem;'>Entropy · ML prediction · Timing</div>
        </div>
        <div style='flex:1;background:#202020;padding:1.2rem;text-align:center;border-right:1px solid #2a2a2a;'>
            <div style='font-size:1.6rem;margin-bottom:0.4rem;'>🛡️</div>
            <div style='color:#34d399;font-size:0.65rem;font-weight:700;letter-spacing:2px;'>STEP 4</div>
            <div style='color:#f0f0f0;font-size:0.85rem;font-weight:700;margin-top:0.3rem;'>Secure Defence</div>
            <div style='color:#888888;font-size:0.72rem;margin-top:0.3rem;'>bcrypt · Argon2 · AI guard</div>
        </div>
        <div style='flex:1;background:#202020;padding:1.2rem;text-align:center;'>
            <div style='font-size:1.6rem;margin-bottom:0.4rem;'>✅</div>
            <div style='color:#c9a428;font-size:0.65rem;font-weight:700;letter-spacing:2px;'>STEP 5</div>
            <div style='color:#f0f0f0;font-size:0.85rem;font-weight:700;margin-top:0.3rem;'>Validation</div>
            <div style='color:#888888;font-size:0.72rem;margin-top:0.3rem;'>Quantify security improvement</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    section("TECHNOLOGY STACK")
    tools = [
        ("🐍  Python 3.12", "Core implementation language"),
        ("🔑  hashlib", "MD5 / SHA-1 hashing primitives"),
        ("🔒  bcrypt", "Adaptive salted password hashing"),
        ("🛡️  argon2-cffi", "Memory-hard hashing (PHC winner)"),
        ("🤖  scikit-learn", "Random Forest ML classifier"),
        ("📊  NumPy / Pandas", "Numerical analysis & data handling"),
        ("📈  Matplotlib", "Attack visualisation & charts"),
        ("📄  ReportLab", "10-page academic PDF export"),
    ]
    cols = st.columns(4)
    for i, (tool, desc) in enumerate(tools):
        with cols[i % 4]:
            st.markdown(f"""
            <div style='background:#202020;border:1px solid #2a2a2a;border-radius:6px;
                 padding:0.8rem;margin-bottom:0.6rem;'>
                <div style='color:#c9a428;font-weight:700;font-size:0.82rem;margin-bottom:0.2rem;'>{tool}</div>
                <div style='color:#888888;font-size:0.7rem;'>{desc}</div>
            </div>""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    section("KEY RESEARCH FINDINGS — QUICK REFERENCE")

    fc1, fc2, fc3, fc4 = st.columns(4)
    with fc1:
        st.markdown("""
        <div style='background:#202020;border:1px solid #ef4444;border-radius:8px;padding:1rem;text-align:center;'>
            <div style='color:#ef4444;font-size:1.8rem;font-weight:900;'>10⁸</div>
            <div style='color:#d0d0d0;font-size:0.78rem;margin-top:0.3rem;'>MD5 hashes/second<br><span style='color:#888888;'>attacker can compute</span></div>
        </div>""", unsafe_allow_html=True)
    with fc2:
        st.markdown("""
        <div style='background:#202020;border:1px solid #f97316;border-radius:8px;padding:1rem;text-align:center;'>
            <div style='color:#f97316;font-size:1.8rem;font-weight:900;'>~100%</div>
            <div style='color:#d0d0d0;font-size:0.78rem;margin-top:0.3rem;'>Dictionary attack<br><span style='color:#888888;'>success on weak passwords</span></div>
        </div>""", unsafe_allow_html=True)
    with fc3:
        st.markdown("""
        <div style='background:#202020;border:1px solid #34d399;border-radius:8px;padding:1rem;text-align:center;'>
            <div style='color:#34d399;font-size:1.8rem;font-weight:900;'>10,000×</div>
            <div style='color:#d0d0d0;font-size:0.78rem;margin-top:0.3rem;'>bcrypt slower than MD5<br><span style='color:#888888;'>→ dramatically safer</span></div>
        </div>""", unsafe_allow_html=True)
    with fc4:
        st.markdown("""
        <div style='background:#202020;border:1px solid #c9a428;border-radius:8px;padding:1rem;text-align:center;'>
            <div style='color:#c9a428;font-size:1.8rem;font-weight:900;'>21</div>
            <div style='color:#d0d0d0;font-size:0.78rem;margin-top:0.3rem;'>ML model features<br><span style='color:#888888;'>Random Forest classifier</span></div>
        </div>""", unsafe_allow_html=True)


# ══════════════════════════════════════════
# PAGE: HASH LAB
# ══════════════════════════════════════════
elif "Hash Lab" in page:
    page_header("Hash Lab", "Weak Hashing  ·  MD5 & SHA-1 Vulnerability Demonstration")

    tab1, tab2, tab3 = st.tabs(["HASH A PASSWORD", "GENERATE DATASET", "VULNERABILITY DEMO"])

    with tab1:
        section("Live MD5 / SHA-1 Hashing")
        st.info("MD5 and SHA-1 are **cryptographically broken** — used here only to demonstrate why weak passwords are easy to crack.")

        inp_col, algo_col = st.columns([3, 1])
        with inp_col:
            pwd_input = st.text_input("Password input", placeholder="Enter any password...", label_visibility="collapsed")
        with algo_col:
            algo = st.selectbox("Algorithm", ["md5", "sha1", "both"], label_visibility="collapsed")

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
# PAGE: ATTACK SIMULATION
# ══════════════════════════════════════════
elif "Attack Simulation" in page:
    page_header("Attack Simulation", "Dictionary & Brute-Force  ·  Active Attack Demonstration")

    pwd_path  = DATA_DIR / "passwords.txt"
    dict_path = DATA_DIR / "dictionary.txt"

    if not pwd_path.exists():
        st.warning("⚠  Dataset not found. Go to **Hash Lab → Generate Dataset** first.")
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
                fig.patch.set_facecolor("#1a1a1a")

                success = [r["success_rate"] for r in results]
                axes[0].bar(labels, success, color=["#f97316", "#a78bfa"][:len(results)], edgecolor="#2e2e2e")
                axes[0].set_ylabel("Success Rate (%)", color="#888888")
                axes[0].set_ylim(0, 110)
                for bar, v in zip(axes[0].patches, success):
                    axes[0].text(bar.get_x()+bar.get_width()/2, bar.get_height()+1, f"{v:.1f}%", ha="center", color="#f0f0f0", fontsize=9)
                style_axes(axes[0], "Success Rate (%)")

                times = [r["elapsed_seconds"] for r in results]
                axes[1].bar(labels, times, color=["#c9a428", "#34d399"][:len(results)], edgecolor="#2e2e2e")
                axes[1].set_ylabel("Time (seconds)", color="#888888")
                for bar, v in zip(axes[1].patches, times):
                    axes[1].text(bar.get_x()+bar.get_width()/2, bar.get_height(), f"{v:.3f}s", ha="center", va="bottom", color="#f0f0f0", fontsize=9)
                style_axes(axes[1], "Cracking Time (s)")

                attempts = [r["attempts"] for r in results]
                axes[2].bar(labels, attempts, color=["#f472b6", "#facc15"][:len(results)], edgecolor="#2e2e2e")
                axes[2].set_ylabel("Attempts", color="#888888")
                axes[2].set_yscale("log")
                style_axes(axes[2], "Hash Attempts (log)")

                plt.tight_layout()
                st.image(make_chart(fig), use_container_width=True)


# ══════════════════════════════════════════
# PAGE: CRYPTANALYSIS
# ══════════════════════════════════════════
elif "Cryptanalysis" in page:
    page_header("Cryptanalysis", "Entropy Analysis  ·  Statistical Patterns  ·  ML Classifier")

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
        fig.patch.set_facecolor("#1a1a1a")

        axes[0].hist(df_feats["entropy"], bins=12, color="#c9a428", edgecolor="#1a1a1a", alpha=0.85)
        axes[0].set_xlabel("Shannon Entropy (bits/char)")
        axes[0].set_ylabel("Password Count")
        style_axes(axes[0], "Entropy Distribution")

        axes[1].scatter(df_feats["length"], df_feats["entropy"], color="#f97316", alpha=0.7, s=40, edgecolors="#2e2e2e")
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
        fig.patch.set_facecolor("#1a1a1a")

        len_counts = patterns["length_counts"]
        axes[0].bar(list(len_counts.keys()), list(len_counts.values()), color="#a78bfa", edgecolor="#1a1a1a")
        axes[0].set_xlabel("Password Length")
        axes[0].set_ylabel("Count")
        style_axes(axes[0], "Length Distribution")

        top_pref = patterns["top_prefixes"][:8]
        axes[1].barh([p[0] for p in top_pref], [p[1] for p in top_pref], color="#f97316", edgecolor="#1a1a1a")
        axes[1].set_xlabel("Frequency")
        style_axes(axes[1], "Top Prefixes (first 3 chars)")

        feat_means = df_feats2[["digits","lower","upper","special"]].mean()
        axes[2].bar(["Digits","Lower","Upper","Special"], feat_means.values,
                    color=["#c9a428","#34d399","#f97316","#a78bfa"], edgecolor="#1a1a1a")
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
            fig.patch.set_facecolor("#1a1a1a")
            bars = ax.bar(["MD5", "SHA-1"], [md5_t*1e6, sha1_t*1e6],
                          color=["#f97316","#a78bfa"], edgecolor="#2e2e2e", width=0.4)
            for bar, v in zip(bars, [md5_t*1e6, sha1_t*1e6]):
                ax.text(bar.get_x()+bar.get_width()/2, bar.get_height()+0.01,
                        f"{v:.3f} µs", ha="center", color="#f0f0f0", fontsize=10)
            ax.set_ylabel("Avg Time per Hash (µs)")
            style_axes(ax, "MD5 vs SHA-1 — Average Hash Time")
            plt.tight_layout()
            st.image(make_chart(fig), use_container_width=True)
            st.error("🚨  At millions of hashes/sec, weak passwords fall in seconds. Use bcrypt/argon2 instead!")


# ══════════════════════════════════════════
# PAGE: DEFENCE SYSTEM
# ══════════════════════════════════════════
elif "Defence" in page:
    page_header("Defence System", "Secure Hashing  ·  Salting  ·  Password Policy  ·  AI Detection")

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
                st.markdown("<div style='color:#c9a428;font-weight:700;letter-spacing:2px;font-size:0.8rem;'>ARGON2</div>", unsafe_allow_html=True)
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
    page_header("Validation Metrics", "Security Improvements  ·  Weak vs Secure System Comparison")

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
        fig.patch.set_facecolor("#1a1a1a")

        algos = ["MD5", "SHA-1", "bcrypt", "Argon2"]
        times = [
            metrics["md5_time"]    * 1000,
            metrics["sha1_time"]   * 1000,
            metrics["bcrypt_time"] * 1000,
            metrics["argon2_time"] * 1000,
        ]
        colors = ["#ef4444","#f97316","#34d399","#c9a428"]

        axes[0].bar(algos, times, color=colors, edgecolor="#2e2e2e")
        axes[0].set_ylabel("Time per hash (ms)")
        axes[0].set_yscale("log")
        for bar, v in zip(axes[0].patches, times):
            axes[0].text(bar.get_x()+bar.get_width()/2, bar.get_height()*1.05,
                         f"{v:.3f}", ha="center", color="#f0f0f0", fontsize=8)
        style_axes(axes[0], "Hash Speed Comparison (log scale)")

        hashes_per_sec = [int(1/(t/1000)) for t in times]
        axes[1].bar(algos, hashes_per_sec, color=colors, edgecolor="#2e2e2e")
        axes[1].set_ylabel("Hashes per second")
        axes[1].set_yscale("log")
        style_axes(axes[1], "Hashes/sec — Attacker Speed")

        attack_time_sec = [hs / 1e9 for hs in hashes_per_sec]  # assume 1B password keyspace
        axes[2].bar(algos, [1/h if h > 0 else 0 for h in hashes_per_sec],
                    color=colors, edgecolor="#2e2e2e")
        axes[2].set_ylabel("Seconds per attempt")
        axes[2].set_yscale("log")
        style_axes(axes[2], "Attacker: Time per Attempt (log)")

        plt.tight_layout()
        st.image(make_chart(fig), use_container_width=True)

        section("Summary — Security Gains")
        st.markdown(f"""
        <div style='background:#202020;border:1px solid #2e2e2e;border-radius:8px;padding:1.5rem;'>
        <table style='width:100%;border-collapse:collapse;font-size:0.85rem;'>
        <tr style='border-bottom:1px solid #2e2e2e;'>
            <th style='color:#c9a428;padding:0.5rem;text-align:left;'>Metric</th>
            <th style='color:#ef4444;padding:0.5rem;'>MD5 (Weak)</th>
            <th style='color:#ef4444;padding:0.5rem;'>SHA-1 (Weak)</th>
            <th style='color:#34d399;padding:0.5rem;'>bcrypt (Secure)</th>
            <th style='color:#c9a428;padding:0.5rem;'>Argon2 (Secure)</th>
        </tr>
        <tr style='border-bottom:1px solid #202020;'>
            <td style='color:#d0d0d0;padding:0.5rem;'>Avg Hash Time</td>
            <td style='color:#ef4444;padding:0.5rem;text-align:center;'>{metrics["md5_time"]*1000:.4f} ms</td>
            <td style='color:#ef4444;padding:0.5rem;text-align:center;'>{metrics["sha1_time"]*1000:.4f} ms</td>
            <td style='color:#34d399;padding:0.5rem;text-align:center;'>{metrics["bcrypt_time"]*1000:.1f} ms</td>
            <td style='color:#c9a428;padding:0.5rem;text-align:center;'>{metrics["argon2_time"]*1000:.1f} ms</td>
        </tr>
        <tr style='border-bottom:1px solid #202020;'>
            <td style='color:#d0d0d0;padding:0.5rem;'>Built-in Salt</td>
            <td style='color:#ef4444;padding:0.5rem;text-align:center;'>✗ No</td>
            <td style='color:#ef4444;padding:0.5rem;text-align:center;'>✗ No</td>
            <td style='color:#34d399;padding:0.5rem;text-align:center;'>✓ Yes</td>
            <td style='color:#c9a428;padding:0.5rem;text-align:center;'>✓ Yes</td>
        </tr>
        <tr style='border-bottom:1px solid #202020;'>
            <td style='color:#d0d0d0;padding:0.5rem;'>GPU Resistant</td>
            <td style='color:#ef4444;padding:0.5rem;text-align:center;'>✗ No</td>
            <td style='color:#ef4444;padding:0.5rem;text-align:center;'>✗ No</td>
            <td style='color:#34d399;padding:0.5rem;text-align:center;'>⚠ Partial</td>
            <td style='color:#c9a428;padding:0.5rem;text-align:center;'>✓ Yes (memory-hard)</td>
        </tr>
        <tr>
            <td style='color:#d0d0d0;padding:0.5rem;'>Recommended Use</td>
            <td style='color:#ef4444;padding:0.5rem;text-align:center;'>Never</td>
            <td style='color:#ef4444;padding:0.5rem;text-align:center;'>Never</td>
            <td style='color:#34d399;padding:0.5rem;text-align:center;'>✓ Passwords</td>
            <td style='color:#c9a428;padding:0.5rem;text-align:center;'>✓ Best Choice</td>
        </tr>
        </table>
        </div>
        """, unsafe_allow_html=True)

        section("Conclusion")
        st.markdown("""
        <div style='background:#161616;border-left:4px solid #34d399;padding:1.2rem;border-radius:0 6px 6px 0;'>
            <p style='color:#d0d0d0;line-height:1.8;margin:0;'>
            This project demonstrates that <b style='color:#ef4444;'>MD5 and SHA-1</b> are fundamentally broken for password storage —
            they are too fast, have no salting, and are trivially crackable via dictionary and brute-force attacks.
            The proposed defence system using <b style='color:#34d399;'>bcrypt/Argon2</b> with built-in salting,
            combined with an <b style='color:#c9a428;'>AI-based weak password detector</b> and
            <b style='color:#a78bfa;'>strict password policies</b>, significantly improves security
            and drastically reduces the attack success rate.
            </p>
        </div>
        """, unsafe_allow_html=True)


# ══════════════════════════════════════════
# PAGE: SECURITY INTELLIGENCE CENTER
# ══════════════════════════════════════════
elif "Security Intelligence" in page:
    page_header("Security Intelligence", "Live Password Threat Analysis  ·  Full-Spectrum Audit")

    st.markdown("""
    <div style='background:linear-gradient(135deg,#1a1a1a,#0a1535);border:1px solid #2e2e2e;
         border-left:4px solid #c9a428;border-radius:8px;padding:1.2rem 1.5rem;margin-bottom:1.5rem;'>
        <span style='color:#b0b0b0;font-size:0.88rem;line-height:1.8;'>
        Enter any password and instantly receive a <b style='color:#c9a428;'>full intelligence report</b> — 
        entropy score, AI threat classification, estimated crack time, real hash outputs, policy compliance, 
        and a visualised character composition. All analyses run live using every module of this project.
        </span>
    </div>
    """, unsafe_allow_html=True)

    si_pwd = st.text_input("🔑  Enter password to analyse:", placeholder="Type any password...",
                            type="password", key="si_pwd_input")

    show_plain = st.checkbox("Show password in plain text", value=False)
    if show_plain and si_pwd:
        st.markdown(f"<code style='color:#c9a428;font-size:0.9rem;'>{si_pwd}</code>", unsafe_allow_html=True)

    if si_pwd:
        import string as _string
        ent = shannon_entropy(si_pwd)
        feats = password_features([si_pwd]).iloc[0]
        ai_prob = predict_weak_password(si_pwd)
        policy_ok = check_password_policy(si_pwd)
        policy_fb = password_policy_feedback(si_pwd)

        has_upper   = any(c.isupper() for c in si_pwd)
        has_lower   = any(c.islower() for c in si_pwd)
        has_digit   = any(c.isdigit() for c in si_pwd)
        has_special = any(c in _string.punctuation for c in si_pwd)
        charset_size = (26 if has_lower else 0) + (26 if has_upper else 0) + \
                       (10 if has_digit else 0) + (32 if has_special else 0)
        total_combinations = charset_size ** len(si_pwd) if charset_size else 1

        DICT_RATE   = 10_000
        BRUTE_RATE  = 1_000_000_000
        BCRYPT_RATE = 15

        def fmt_time(seconds):
            if seconds < 1:        return f"{seconds*1000:.1f} milliseconds"
            if seconds < 60:       return f"{seconds:.1f} seconds"
            if seconds < 3600:     return f"{seconds/60:.1f} minutes"
            if seconds < 86400:    return f"{seconds/3600:.1f} hours"
            if seconds < 2592000:  return f"{seconds/86400:.1f} days"
            if seconds < 31536000: return f"{seconds/2592000:.1f} months"
            return f"{seconds/31536000:.1f} years"

        crack_dict   = fmt_time(total_combinations / DICT_RATE)
        crack_brute  = fmt_time(total_combinations / BRUTE_RATE)
        crack_bcrypt = fmt_time(total_combinations / BCRYPT_RATE)

        score = 0
        score += min(30, len(si_pwd) * 2)
        score += 15 if has_upper else 0
        score += 15 if has_lower else 0
        score += 15 if has_digit else 0
        score += 15 if has_special else 0
        score += int(ent * 3)
        score += 10 if policy_ok else 0
        score = min(100, score)

        if score >= 80:    threat_level, threat_color, threat_label = "LOW",      "#34d399", "STRONG"
        elif score >= 55:  threat_level, threat_color, threat_label = "MODERATE", "#facc15", "MODERATE"
        elif score >= 30:  threat_level, threat_color, threat_label = "HIGH",     "#f97316", "WEAK"
        else:              threat_level, threat_color, threat_label = "CRITICAL", "#ef4444", "CRITICAL"

        st.markdown(f"""
        <div style='background:linear-gradient(135deg,#1a1a1a,#0a1535);border:1px solid {threat_color};
             border-radius:12px;padding:1.8rem;margin:1.2rem 0;'>
            <div style='display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:1rem;'>
                <div>
                    <div style='color:#888888;font-size:0.65rem;font-weight:700;letter-spacing:3px;'>OVERALL THREAT LEVEL</div>
                    <div style='color:{threat_color};font-size:2.8rem;font-weight:900;letter-spacing:4px;margin-top:0.2rem;line-height:1;'>{threat_level}</div>
                    <div style='color:#b0b0b0;font-size:0.78rem;margin-top:0.4rem;'>Password classified as <b style='color:{threat_color};'>{threat_label}</b></div>
                </div>
                <div style='text-align:right;'>
                    <div style='color:#888888;font-size:0.65rem;font-weight:700;letter-spacing:3px;'>SECURITY SCORE</div>
                    <div style='color:{threat_color};font-size:3.5rem;font-weight:900;line-height:1;'>{score}<span style='font-size:1.2rem;color:#888888;'>/100</span></div>
                </div>
            </div>
            <div style='margin-top:1rem;background:#202020;border-radius:6px;height:10px;overflow:hidden;'>
                <div style='width:{score}%;background:linear-gradient(90deg,{threat_color}88,{threat_color});
                     height:100%;border-radius:6px;transition:width 0.8s;'></div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        si1, si2, si3, si4, si5 = st.columns(5)
        si1.metric("Length",         len(si_pwd))
        si2.metric("Entropy",        f"{ent:.2f} bits/char")
        si3.metric("AI Weak Prob.",  f"{ai_prob:.1%}")
        si4.metric("Charset Size",   charset_size)
        si5.metric("Combinations",   f"{total_combinations:.2e}")

        st.markdown("<br>", unsafe_allow_html=True)
        section("ESTIMATED CRACK TIME")

        c1, c2, c3 = st.columns(3)
        with c1:
            st.markdown(f"""
            <div style='background:#202020;border:1px solid #ef4444;border-radius:8px;padding:1.2rem;text-align:center;'>
                <div style='color:#ef4444;font-size:0.65rem;font-weight:700;letter-spacing:2px;'>DICTIONARY ATTACK</div>
                <div style='color:#f0f0f0;font-size:1.3rem;font-weight:800;margin:0.5rem 0;'>{crack_dict}</div>
                <div style='color:#888888;font-size:0.72rem;'>at {DICT_RATE:,} attempts/sec</div>
            </div>""", unsafe_allow_html=True)
        with c2:
            st.markdown(f"""
            <div style='background:#202020;border:1px solid #f97316;border-radius:8px;padding:1.2rem;text-align:center;'>
                <div style='color:#f97316;font-size:0.65rem;font-weight:700;letter-spacing:2px;'>BRUTE-FORCE (GPU)</div>
                <div style='color:#f0f0f0;font-size:1.3rem;font-weight:800;margin:0.5rem 0;'>{crack_brute}</div>
                <div style='color:#888888;font-size:0.72rem;'>at {BRUTE_RATE/1e9:.0f}B attempts/sec</div>
            </div>""", unsafe_allow_html=True)
        with c3:
            st.markdown(f"""
            <div style='background:#202020;border:1px solid #34d399;border-radius:8px;padding:1.2rem;text-align:center;'>
                <div style='color:#34d399;font-size:0.65rem;font-weight:700;letter-spacing:2px;'>WITH BCRYPT DEFENCE</div>
                <div style='color:#f0f0f0;font-size:1.3rem;font-weight:800;margin:0.5rem 0;'>{crack_bcrypt}</div>
                <div style='color:#888888;font-size:0.72rem;'>at only {BCRYPT_RATE} attempts/sec</div>
            </div>""", unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)
        t_hash, t_ai, t_policy, t_compose = st.tabs([
            "🔑  LIVE HASH COMPARISON", "🤖  AI DEEP ANALYSIS", "🛡️  POLICY AUDIT", "📊  COMPOSITION CHART"
        ])

        with t_hash:
            section("ALL FOUR ALGORITHMS — LIVE OUTPUT")
            st.markdown("<div style='color:#b0b0b0;font-size:0.82rem;margin-bottom:1rem;'>Same password — four completely different algorithms. See why algorithm choice matters.</div>", unsafe_allow_html=True)

            h_md5  = hash_md5(si_pwd)
            h_sha1 = hash_sha1(si_pwd)

            col_a, col_b = st.columns(2)
            with col_a:
                st.markdown("""<div style='background:#202020;border:1px solid #ef4444;border-radius:8px;padding:1rem;margin-bottom:0.8rem;'>
                    <div style='color:#ef4444;font-size:0.65rem;font-weight:700;letter-spacing:2px;margin-bottom:0.5rem;'>
                    ⚠ MD5 — BROKEN &amp; INSECURE</div>""", unsafe_allow_html=True)
                st.code(h_md5, language=None)
                st.markdown("<div style='color:#888888;font-size:0.72rem;'>No salt · 128-bit · Crackable in milliseconds</div></div>", unsafe_allow_html=True)

                st.markdown("""<div style='background:#202020;border:1px solid #f97316;border-radius:8px;padding:1rem;'>
                    <div style='color:#f97316;font-size:0.65rem;font-weight:700;letter-spacing:2px;margin-bottom:0.5rem;'>
                    ⚠ SHA-1 — DEPRECATED &amp; WEAK</div>""", unsafe_allow_html=True)
                st.code(h_sha1, language=None)
                st.markdown("<div style='color:#888888;font-size:0.72rem;'>No salt · 160-bit · Collision attacks known</div></div>", unsafe_allow_html=True)

            with col_b:
                if st.button("🔒 Generate bcrypt & Argon2 Hashes"):
                    with st.spinner("Computing secure hashes..."):
                        t0 = time.perf_counter()
                        h_bcrypt = hash_bcrypt(si_pwd)
                        bcrypt_ms = (time.perf_counter() - t0) * 1000
                        t0 = time.perf_counter()
                        h_argon2 = hash_argon2(si_pwd)
                        argon2_ms = (time.perf_counter() - t0) * 1000
                    st.session_state["si_bcrypt"] = (h_bcrypt, bcrypt_ms)
                    st.session_state["si_argon2"] = (h_argon2, argon2_ms)

                if "si_bcrypt" in st.session_state:
                    h_b, ms_b = st.session_state["si_bcrypt"]
                    st.markdown(f"""<div style='background:#202020;border:1px solid #34d399;border-radius:8px;padding:1rem;margin-bottom:0.8rem;'>
                        <div style='color:#34d399;font-size:0.65rem;font-weight:700;letter-spacing:2px;margin-bottom:0.5rem;'>
                        ✓ BCRYPT — SECURE ({ms_b:.0f} ms)</div>""", unsafe_allow_html=True)
                    st.code(h_b, language=None)
                    st.markdown("<div style='color:#888888;font-size:0.72rem;'>Built-in salt · Adaptive cost · Attacker-hostile</div></div>", unsafe_allow_html=True)

                if "si_argon2" in st.session_state:
                    h_a, ms_a = st.session_state["si_argon2"]
                    st.markdown(f"""<div style='background:#202020;border:1px solid #c9a428;border-radius:8px;padding:1rem;'>
                        <div style='color:#c9a428;font-size:0.65rem;font-weight:700;letter-spacing:2px;margin-bottom:0.5rem;'>
                        ✓ ARGON2 — MOST SECURE ({ms_a:.0f} ms)</div>""", unsafe_allow_html=True)
                    st.code(h_a, language=None)
                    st.markdown("<div style='color:#888888;font-size:0.72rem;'>Memory-hard · PHC winner · GPU-resistant</div></div>", unsafe_allow_html=True)
                elif "si_bcrypt" not in st.session_state:
                    st.info("Click the button above to generate secure hashes.")

        with t_ai:
            section("AI MODEL — DEEP FEATURE ANALYSIS")
            ai_feats = extract_features(si_pwd)
            ai_feat_dict = ai_feats.iloc[0].to_dict()

            a1, a2, a3 = st.columns(3)
            a1.metric("Weak Probability",   f"{ai_prob:.1%}")
            a2.metric("Strong Probability", f"{1-ai_prob:.1%}")
            a3.metric("AI Verdict",         "⚠ WEAK" if ai_prob > 0.5 else "✓ STRONG")

            st.markdown("**AI Confidence:**")
            st.progress(float(ai_prob))
            if ai_prob > 0.75:
                st.error(f"🚨 Model is {ai_prob:.1%} confident — this password is a prime attack target.")
            elif ai_prob > 0.45:
                st.warning(f"⚠ Borderline strength — moderate resistance to ML-based attacks.")
            else:
                st.success(f"✓ Model classifies as STRONG — resistant to ML-predicted attack patterns.")

            st.markdown("<br>", unsafe_allow_html=True)
            section("ALL 21 EXTRACTED FEATURES")
            items = list(ai_feat_dict.items())
            r1c, r2c, r3c = st.columns(3)
            for i, (k, v) in enumerate(items):
                [r1c, r2c, r3c][i % 3].metric(k.replace("_", " ").title(), round(float(v), 3))

        with t_policy:
            section("MULTI-RULE POLICY COMPLIANCE ENGINE")
            rules = [
                ("Minimum 8 characters",                        len(si_pwd) >= 8,                             f"Length: {len(si_pwd)}"),
                ("Contains uppercase letter (A–Z)",             has_upper,                                    "✓ Found" if has_upper else "✗ Missing"),
                ("Contains lowercase letter (a–z)",             has_lower,                                    "✓ Found" if has_lower else "✗ Missing"),
                ("Contains digit (0–9)",                        has_digit,                                    "✓ Found" if has_digit else "✗ Missing"),
                ("Contains special character (!@#$...)",        has_special,                                  "✓ Found" if has_special else "✗ Missing"),
                ("Strong length (12+ characters)",              len(si_pwd) >= 12,                            f"Length: {len(si_pwd)}"),
                ("No all-same characters",                      len(set(si_pwd)) > 1,                         "✓ Diverse" if len(set(si_pwd)) > 1 else "✗ Repetitive"),
                ("Entropy above 3 bits/char",                   ent >= 3.0,                                   f"{ent:.2f} bits/char"),
            ]
            passed_count = sum(1 for _, p, _ in rules if p)
            compliance_pct = passed_count / len(rules) * 100

            st.markdown(f"""
            <div style='background:#202020;border:1px solid #2e2e2e;border-radius:8px;padding:1rem;margin-bottom:1rem;'>
                <div style='display:flex;justify-content:space-between;align-items:center;'>
                    <span style='color:#d0d0d0;font-size:0.85rem;'>Compliance Score</span>
                    <span style='color:{"#34d399" if compliance_pct>=75 else "#f97316" if compliance_pct>=50 else "#ef4444"};
                          font-size:1.3rem;font-weight:800;'>{passed_count}/{len(rules)} rules passed ({compliance_pct:.0f}%)</span>
                </div>
            </div>
            """, unsafe_allow_html=True)

            for rule, passed, detail in rules:
                icon = "✓" if passed else "✗"
                col_r = "#34d399" if passed else "#ef4444"
                st.markdown(f"""
                <div style='display:flex;align-items:center;justify-content:space-between;
                     padding:0.55rem 1rem;border-radius:6px;margin-bottom:0.3rem;
                     background:{"#071f12" if passed else "#1f0707"};
                     border:1px solid {"#1e4a2a" if passed else "#4a1e1e"};'>
                    <span style='color:{col_r};font-size:0.82rem;'><b>{icon}</b>&nbsp; {rule}</span>
                    <span style='color:#888888;font-size:0.75rem;'>{detail}</span>
                </div>""", unsafe_allow_html=True)

        with t_compose:
            section("CHARACTER COMPOSITION VISUALISATION")
            digits  = sum(c.isdigit()   for c in si_pwd)
            lowers  = sum(c.islower()   for c in si_pwd)
            uppers  = sum(c.isupper()   for c in si_pwd)
            specials= sum(c in _string.punctuation for c in si_pwd)
            total   = len(si_pwd)

            fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4))
            fig.patch.set_facecolor("#1a1a1a")

            categories = ["Lowercase", "Uppercase", "Digits", "Special"]
            counts     = [lowers, uppers, digits, specials]
            colors_bar = ["#c9a428", "#a78bfa", "#f97316", "#34d399"]
            bars = ax1.bar(categories, counts, color=colors_bar, edgecolor="#2e2e2e", width=0.5)
            for bar, v in zip(bars, counts):
                if v > 0:
                    ax1.text(bar.get_x()+bar.get_width()/2, bar.get_height()+0.05,
                             str(v), ha="center", color="#f0f0f0", fontsize=11, fontweight="bold")
            style_axes(ax1, "Character Type Count")
            ax1.set_ylabel("Count", color="#888888")

            nonzero_vals   = [v for v in counts if v > 0]
            nonzero_labels = [f"{categories[i]}\n{counts[i]} ({counts[i]/total*100:.0f}%)"
                              for i, v in enumerate(counts) if v > 0]
            nonzero_colors = [colors_bar[i] for i, v in enumerate(counts) if v > 0]

            if nonzero_vals:
                wedges, texts, autotexts = ax2.pie(
                    nonzero_vals, labels=nonzero_labels,
                    colors=nonzero_colors, autopct='',
                    startangle=90, wedgeprops={"edgecolor": "#1a1a1a", "linewidth": 2}
                )
                for t in texts:
                    t.set_color("#b0b0b0")
                    t.set_fontsize(8)
            ax2.set_facecolor("#1a1a1a")
            style_axes(ax2, "Composition Distribution")

            plt.tight_layout()
            st.image(make_chart(fig), use_container_width=True)

            sc1, sc2, sc3, sc4 = st.columns(4)
            sc1.metric("Lowercase",  f"{lowers}  ({lowers/total*100:.0f}%)")
            sc2.metric("Uppercase",  f"{uppers}  ({uppers/total*100:.0f}%)")
            sc3.metric("Digits",     f"{digits}  ({digits/total*100:.0f}%)")
            sc4.metric("Special",    f"{specials} ({specials/total*100:.0f}%)")

    else:
        st.markdown("""
        <div style='background:#202020;border:2px dashed #2e2e2e;border-radius:12px;
             padding:3rem;text-align:center;margin-top:1rem;'>
            <div style='font-size:2.5rem;margin-bottom:1rem;'>🔍</div>
            <div style='color:#c9a428;font-size:1rem;font-weight:700;letter-spacing:2px;'>AWAITING INPUT</div>
            <div style='color:#888888;font-size:0.82rem;margin-top:0.5rem;'>
                Enter a password above to generate a full security intelligence report.
            </div>
        </div>
        """, unsafe_allow_html=True)


# ══════════════════════════════════════════
# PAGE: ABOUT
# ══════════════════════════════════════════
elif "About" in page:
    page_header("About", "Research Team  ·  Project Overview  ·  Academic Context")

    st.markdown("""
    <div style='background:linear-gradient(135deg,#1a1a1a,#161616);
         border:1px solid #2e2e2e;border-radius:12px;padding:2.5rem;margin-bottom:1.5rem;text-align:center;'>
        <div style='font-size:2.2rem;margin-bottom:0.6rem;'>🔐</div>
        <div style='color:#c9a428;font-size:1.4rem;font-weight:900;letter-spacing:3px;'>CRYPTANALYSIS LAB</div>
        <div style='color:#888888;font-size:0.78rem;letter-spacing:2px;margin-top:0.5rem;'>
            Cryptanalysis of Weak Password Hashing Systems and AI-Based Defence Mechanism
        </div>
        <hr style='border-color:#2e2e2e;margin:1.5rem auto;max-width:400px;'/>
        <div style='color:#b0b0b0;font-size:0.88rem;line-height:1.9;max-width:650px;margin:0 auto;'>
            A university-level research project investigating cryptographic vulnerabilities in legacy 
            password hashing algorithms, performing systematic attack simulations, and designing 
            an AI-augmented defence architecture using modern memory-hard hashing and machine learning.
        </div>
    </div>
    """, unsafe_allow_html=True)

    section("DEVELOPED BY")

    team = [
        ("👩‍💻", "Amina Noor",    "Full Stack Developer",    "Module I — Hash Lab & Attack Simulation",        "#f97316"),
        ("👩‍🎨", "Hamail Fatima", "UI/UX Designer",          "Module II — Cryptanalysis & AI Analysis",        "#a78bfa"),
        ("👩‍🔬", "Hajra Sarwar",  "Full Stack AI Developer", "Module III — Defence Architecture & Validation", "#34d399"),
    ]

    t1, t2, t3 = st.columns(3)
    for col, (icon, name, title, module, color) in zip([t1, t2, t3], team):
        with col:
            st.markdown(f"""
            <div style='background:linear-gradient(160deg,#161616,#202020);
                 border:1px solid #2e2e2e;border-top:3px solid {color};
                 border-radius:10px;padding:1.8rem 1.4rem;text-align:center;'>
                <div style='font-size:2.5rem;margin-bottom:0.8rem;'>{icon}</div>
                <div style='color:#f0f0f0;font-size:1.05rem;font-weight:800;letter-spacing:1px;'>{name}</div>
                <div style='color:{color};font-size:0.65rem;font-weight:700;letter-spacing:2px;
                     margin:0.5rem 0;text-transform:uppercase;'>{title}</div>
                <hr style='border-color:#2a2a2a;margin:0.8rem 0;'/>
                <div style='color:#888888;font-size:0.75rem;line-height:1.6;'>{module}</div>
            </div>
            """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    section("PROJECT DETAILS")

    d1, d2 = st.columns(2)
    with d1:
        st.markdown("""
        <div style='background:#202020;border:1px solid #2e2e2e;border-radius:8px;padding:1.4rem;'>
            <div style='color:#c9a428;font-size:0.68rem;font-weight:700;letter-spacing:3px;margin-bottom:1rem;'>SCOPE & OBJECTIVES</div>
            <ul style='color:#b0b0b0;font-size:0.82rem;line-height:2.2;margin:0;padding-left:1.2rem;'>
                <li>Analyse MD5 &amp; SHA-1 cryptographic weaknesses</li>
                <li>Simulate real-world dictionary and brute-force attacks</li>
                <li>Measure attack success rates and cracking time</li>
                <li>Implement Shannon entropy &amp; statistical cryptanalysis</li>
                <li>Train Random Forest ML classifier (21 features)</li>
                <li>Design bcrypt/Argon2-based defence system</li>
                <li>Validate security improvements with measurable metrics</li>
                <li>Generate full 10-page academic PDF report</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)

    with d2:
        st.markdown("""
        <div style='background:#202020;border:1px solid #2e2e2e;border-radius:8px;padding:1.4rem;'>
            <div style='color:#c9a428;font-size:0.68rem;font-weight:700;letter-spacing:3px;margin-bottom:1rem;'>TECHNOLOGY STACK</div>
            <table style='width:100%;border-collapse:collapse;font-size:0.8rem;'>
                <tr style='border-bottom:1px solid #2a2a2a;'>
                    <td style='color:#c9a428;padding:0.4rem 0;font-weight:700;'>Python 3.12</td>
                    <td style='color:#b0b0b0;padding:0.4rem 0;'>Core implementation language</td>
                </tr>
                <tr style='border-bottom:1px solid #2a2a2a;'>
                    <td style='color:#c9a428;padding:0.4rem 0;font-weight:700;'>hashlib</td>
                    <td style='color:#b0b0b0;padding:0.4rem 0;'>MD5 / SHA-1 primitives</td>
                </tr>
                <tr style='border-bottom:1px solid #2a2a2a;'>
                    <td style='color:#c9a428;padding:0.4rem 0;font-weight:700;'>bcrypt / Argon2</td>
                    <td style='color:#b0b0b0;padding:0.4rem 0;'>Memory-hard secure hashing</td>
                </tr>
                <tr style='border-bottom:1px solid #2a2a2a;'>
                    <td style='color:#c9a428;padding:0.4rem 0;font-weight:700;'>scikit-learn</td>
                    <td style='color:#b0b0b0;padding:0.4rem 0;'>Random Forest ML model</td>
                </tr>
                <tr style='border-bottom:1px solid #2a2a2a;'>
                    <td style='color:#c9a428;padding:0.4rem 0;font-weight:700;'>Streamlit</td>
                    <td style='color:#b0b0b0;padding:0.4rem 0;'>Interactive web interface</td>
                </tr>
                <tr>
                    <td style='color:#c9a428;padding:0.4rem 0;font-weight:700;'>ReportLab</td>
                    <td style='color:#b0b0b0;padding:0.4rem 0;'>PDF academic report export</td>
                </tr>
            </table>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("""
    <div style='background:#161616;border:1px solid #2a2a2a;border-radius:8px;
         padding:1.2rem 1.5rem;text-align:center;'>
        <span style='color:#555555;font-size:0.72rem;letter-spacing:2px;'>
        CRYPTANALYSIS OF WEAK PASSWORD HASHING SYSTEMS AND AI-BASED DEFENCE MECHANISM
        &nbsp;·&nbsp; UNIVERSITY PROJECT &nbsp;·&nbsp; 2024–2025
        </span>
    </div>
    """, unsafe_allow_html=True)


# ─────────────────────────────────────────
# FOOTER
# ─────────────────────────────────────────
st.markdown("---")
st.markdown("""
<div style='text-align:center;padding:0.8rem;'>
    <span style='color:#555555;font-size:0.7rem;letter-spacing:2px;'>
    CRYPTANALYSIS OF WEAK PASSWORD HASHING SYSTEMS AND AI-BASED DEFENCE MECHANISM
    </span>
</div>
""", unsafe_allow_html=True)
