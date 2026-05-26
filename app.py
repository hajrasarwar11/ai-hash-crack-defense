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
    page_title="CryptLab",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ─────────────────────────────────────────
# CSS  ── Premium Dark · Inter + Playfair
# ─────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&family=Playfair+Display:ital,wght@0,400;0,500;1,400;1,500&family=JetBrains+Mono:wght@400;500&display=swap');

:root {
    --bg:        #080808;
    --bg2:       #0e0e0e;
    --bg3:       #141414;
    --bg4:       #1a1a1a;
    --border:    #1f1f1f;
    --border2:   #252525;
    --border3:   #2e2e2e;
    --gold:      #c9a84c;
    --gold2:     #e2c97a;
    --gold-dim:  #8a7040;
    --gold-glow: rgba(201,168,76,0.10);
    --text:      #efefef;
    --text-mid:  #888888;
    --text-dim:  #484848;
    --text-faint:#222222;
    --red:       #c05555;
    --green:     #4aaa7a;
    --purple:    #8066cc;
    --orange:    #c47a44;
    --font:      Inter, system-ui, sans-serif;
    --mono:      JetBrains Mono, monospace;
    --display:   Playfair Display, Georgia, serif;
}

*, *::before, *::after { box-sizing: border-box; margin: 0; }

html, body, [class*='css'] {
    font-family: var(--font) !important;
    -webkit-font-smoothing: antialiased !important;
    background-color: var(--bg) !important;
    color: var(--text);
}

/* ── PRESERVE INLINE GOLD COLORS ─────────────────── */
[style*="color:#c9a84c"],
[style*="color: #c9a84c"],
[style*="color:#e2c97a"],
[style*="color:#c9a84c;"] { color: #c9a84c !important; }

[style*="color:#efefef"],
[style*="color: #efefef"] { color: #efefef !important; }

[style*="color:#4aaa7a"],
[style*="color: #4aaa7a"] { color: #4aaa7a !important; }

[style*="color:#c05555"],
[style*="color: #c05555"] { color: #c05555 !important; }

[style*="color:#8066cc"],
[style*="color: #8066cc"] { color: #8066cc !important; }

[style*="color:#c47a44"],
[style*="color: #c47a44"] { color: #c47a44 !important; }

/* STREAMLIT CHROME */
header[data-testid='stHeader'],
[data-testid='stToolbar'] {
    background: var(--bg) !important;
    border-bottom: 1px solid var(--border) !important;
    height: 2.6rem !important;
}
[data-testid='stDecoration'] { display: none !important; }
#MainMenu, footer { visibility: hidden !important; }

/* BACKGROUNDS */
.stApp,
[data-testid='stAppViewContainer'],
[data-testid='stAppViewBlockContainer'],
.main, .block-container {
    background-color: var(--bg) !important;
}
[data-testid='stAppViewBlockContainer'] {
    padding-top: 2.5rem !important;
    padding-left: 2.8rem !important;
    padding-right: 2.8rem !important;
    max-width: 1180px !important;
}

/* ── SIDEBAR ─────────────────────────────────────── */
section[data-testid='stSidebar'] {
    background: var(--bg2) !important;
    border-right: 1px solid var(--border2) !important;
    width: 226px !important;
    min-width: 226px !important;
}
section[data-testid='stSidebar'] > div {
    background: var(--bg2) !important;
}

/* hide radio dots */
[data-testid='stSidebar'] [data-baseweb='radio'],
[data-testid='stSidebar'] [role='radio'],
[data-testid='stSidebar'] .stRadio [data-testid='stWidgetLabel'],
[data-testid='stSidebar'] .stRadio span[data-baseweb='radio'],
[data-testid='stSidebar'] .stRadio div[role='radiogroup'] > label > div:first-child,
[data-testid='stSidebar'] input[type='radio'] { display: none !important; }

[data-testid='stSidebar'] .stRadio > div {
    gap: 0 !important;
    padding: 0 10px !important;
}
[data-testid='stSidebar'] .stRadio label {
    display: flex !important;
    align-items: center !important;
    padding: 0.5rem 0.9rem !important;
    border-radius: 7px !important;
    cursor: pointer !important;
    font-size: 0.83rem !important;
    font-weight: 400 !important;
    text-transform: none !important;
    letter-spacing: 0.005em !important;
    white-space: nowrap !important;
    overflow: hidden !important;
    text-overflow: ellipsis !important;
    color: var(--text-dim) !important;
    border-left: 2px solid transparent !important;
    transition: all 0.12s ease !important;
    margin-bottom: 2px !important;
    line-height: 1.4 !important;
}
[data-testid='stSidebar'] .stRadio label:hover {
    background: rgba(255,255,255,0.035) !important;
    color: var(--text-mid) !important;
    border-left-color: var(--border3) !important;
}
[data-testid='stSidebar'] .stRadio label[data-checked='true'],
[data-testid='stSidebar'] .stRadio [aria-checked='true'] ~ label,
[data-testid='stSidebar'] .stRadio input:checked + div {
    background: rgba(201,168,76,0.07) !important;
    color: var(--gold) !important;
    border-left-color: var(--gold) !important;
    font-weight: 500 !important;
}

/* TYPOGRAPHY */
h1, h2, h3, h4 {
    font-family: var(--display) !important;
    color: var(--text) !important;
    font-weight: 400 !important;
    letter-spacing: -0.02em !important;
    line-height: 1.15 !important;
}
p, span, div, label, li, .stMarkdown, .stText {
    color: var(--text) !important;
    font-family: var(--font) !important;
}
.stMarkdown p {
    color: var(--text-mid) !important;
    font-size: 0.9rem !important;
    line-height: 1.85 !important;
    font-weight: 400 !important;
}

/* BUTTONS */
.stButton > button {
    background: transparent !important;
    color: var(--gold) !important;
    border: 1px solid var(--border3) !important;
    border-radius: 7px !important;
    font-family: var(--font) !important;
    font-size: 0.74rem !important;
    font-weight: 500 !important;
    letter-spacing: 0.06em !important;
    text-transform: uppercase !important;
    padding: 0.6rem 1.3rem !important;
    width: 100% !important;
    transition: all 0.14s ease !important;
}
.stButton > button:hover {
    border-color: var(--gold) !important;
    background: var(--gold-glow) !important;
    color: var(--gold2) !important;
}
.stButton > button:active { transform: scale(0.98) !important; }

/* INPUTS */
.stTextInput > div > div > input,
.stTextArea > div > div > textarea {
    background: var(--bg3) !important;
    color: var(--text) !important;
    border: 1px solid var(--border2) !important;
    border-radius: 7px !important;
    font-family: var(--font) !important;
    font-size: 0.88rem !important;
    font-weight: 400 !important;
    padding: 0.65rem 1rem !important;
    transition: border-color 0.14s !important;
    caret-color: var(--gold) !important;
}
.stTextInput > div > div > input::placeholder,
.stTextArea > div > div > textarea::placeholder {
    color: var(--text-dim) !important;
}
.stTextInput > div > div > input:focus,
.stTextArea > div > div > textarea:focus {
    border-color: var(--gold-dim) !important;
    background: var(--bg4) !important;
    outline: none !important;
    box-shadow: 0 0 0 3px rgba(201,168,76,0.05) !important;
}

/* SELECT */
.stSelectbox > div > div {
    background: var(--bg3) !important;
    color: var(--text) !important;
    border: 1px solid var(--border2) !important;
    border-radius: 7px !important;
    font-family: var(--font) !important;
    font-size: 0.88rem !important;
}
.stSelectbox svg { fill: var(--gold) !important; }

/* METRICS */
[data-testid='stMetric'] {
    background: var(--bg2) !important;
    border: 1px solid var(--border2) !important;
    border-radius: 12px !important;
    padding: 1.3rem 1.4rem 1.1rem !important;
    position: relative !important;
    overflow: hidden !important;
    transition: border-color 0.15s, transform 0.15s !important;
}
[data-testid='stMetric']::before {
    content: '' !important;
    position: absolute !important;
    top: 0; left: 15%; right: 15% !important;
    height: 1px !important;
    background: linear-gradient(90deg, transparent, var(--gold-dim) 35%, var(--gold) 50%, var(--gold-dim) 65%, transparent) !important;
}
[data-testid='stMetric']:hover {
    border-color: var(--border3) !important;
    transform: translateY(-1px) !important;
}
[data-testid='stMetric'] * { color: var(--text) !important; }
[data-testid='stMetricLabel'] {
    font-size: 0.58rem !important;
    font-weight: 600 !important;
    letter-spacing: 0.14em !important;
    text-transform: uppercase !important;
    color: var(--text-dim) !important;
    font-family: var(--font) !important;
    line-height: 1.5 !important;
}
[data-testid='stMetricValue'] {
    font-size: 2rem !important;
    font-weight: 400 !important;
    font-family: var(--display) !important;
    color: var(--text) !important;
    letter-spacing: -0.02em !important;
    line-height: 1.2 !important;
    margin: 0.2rem 0 !important;
}
[data-testid='stMetricDelta'] {
    font-size: 0.67rem !important;
    color: var(--text-dim) !important;
    font-family: var(--font) !important;
    font-weight: 400 !important;
}

/* TABS */
.stTabs [data-baseweb='tab-list'] {
    background: transparent !important;
    border-bottom: 1px solid var(--border) !important;
    gap: 0 !important;
    padding: 0 !important;
}
.stTabs [data-baseweb='tab'] {
    background: transparent !important;
    color: var(--text-dim) !important;
    font-size: 0.67rem !important;
    font-weight: 500 !important;
    letter-spacing: 0.09em !important;
    text-transform: uppercase !important;
    padding: 0.78rem 1.2rem !important;
    border-bottom: 2px solid transparent !important;
    border-radius: 0 !important;
    transition: color 0.12s !important;
    font-family: var(--font) !important;
    white-space: nowrap !important;
}
.stTabs [data-baseweb='tab']:hover { color: var(--text-mid) !important; }
.stTabs [aria-selected='true'] {
    color: var(--gold) !important;
    border-bottom-color: var(--gold) !important;
    background: transparent !important;
}
.stTabs [data-baseweb='tab-panel'] { padding-top: 1.6rem !important; }

/* PROGRESS */
.stProgress > div > div > div {
    background: linear-gradient(90deg, var(--gold-dim), var(--gold)) !important;
    border-radius: 99px !important;
}
.stProgress > div > div {
    background: var(--border2) !important;
    border-radius: 99px !important;
    height: 3px !important;
}

/* CODE */
code, .stCode, pre {
    background: var(--bg3) !important;
    color: var(--gold2) !important;
    font-family: var(--mono) !important;
    font-size: 0.8rem !important;
    border: 1px solid var(--border2) !important;
    border-radius: 6px !important;
}

/* DATAFRAMES */
[data-testid='stDataFrame'] {
    background: var(--bg2) !important;
    border: 1px solid var(--border) !important;
    border-radius: 10px !important;
    overflow: hidden !important;
    font-size: 0.83rem !important;
}

/* ALERTS */
[data-testid='stAlert'] {
    border-radius: 8px !important;
    font-size: 0.85rem !important;
    font-family: var(--font) !important;
    font-weight: 400 !important;
    border-width: 1px !important;
}

/* EXPANDERS */
[data-testid='stExpander'] {
    background: var(--bg2) !important;
    border: 1px solid var(--border) !important;
    border-radius: 10px !important;
    transition: border-color 0.14s !important;
}
[data-testid='stExpander']:hover { border-color: var(--border2) !important; }
[data-testid='stExpander'] * { color: var(--text) !important; }
[data-testid='stExpander'] summary {
    font-size: 0.88rem !important;
    font-weight: 400 !important;
    padding: 0.85rem 1.1rem !important;
}
[data-testid='stExpander'] summary:hover { color: var(--gold) !important; }

/* SLIDER */
.stSlider > div > div > div { background: var(--gold) !important; }
[data-testid='stSlider'] > div > div > div > div { background: var(--border2) !important; }

/* CHECKBOX */
.stCheckbox > label {
    color: var(--text-mid) !important;
    font-size: 0.86rem !important;
    font-weight: 400 !important;
}

/* HR */
hr {
    border: none !important;
    border-top: 1px solid var(--border) !important;
    margin: 2rem 0 !important;
}

/* SCROLLBAR */
::-webkit-scrollbar { width: 4px; height: 4px; }
::-webkit-scrollbar-track { background: var(--bg); }
::-webkit-scrollbar-thumb { background: var(--border3); border-radius: 99px; }
::-webkit-scrollbar-thumb:hover { background: var(--gold-dim); }

/* ANIMATIONS */
@keyframes fadeUp {
    from { opacity: 0; transform: translateY(8px); }
    to   { opacity: 1; transform: translateY(0); }
}
@keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }

.main .block-container { animation: fadeUp 0.3s cubic-bezier(0.22,1,0.36,1) both !important; }
section[data-testid='stSidebar'] { animation: fadeIn 0.25s ease both !important; }

/* TEXT SELECTION */
::selection { background: rgba(201,168,76,0.18); color: var(--text); }
</style>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────
# HELPER FUNCTIONS
# ─────────────────────────────────────────

def page_header(title, subtitle=""):
    parts = title.split("&", 1)
    main  = parts[0].strip()
    rest  = ("& " + parts[1].strip()) if len(parts) > 1 else ""

    sub_html = ""
    if subtitle:
        sub_html = (
            f"<div style='font-size:0.6rem;font-weight:600;color:#c9a84c;"
            f"letter-spacing:0.2em;text-transform:uppercase;"
            f"margin-bottom:1rem;font-family:Inter,sans-serif;'>"
            f"{subtitle}</div>"
        )

    gold_html = ""
    if rest:
        gold_html = (
            f"<div style='font-size:2.8rem;font-weight:400;line-height:1.1;"
            f"letter-spacing:-0.02em;color:#c9a84c;font-style:italic;"
            f"font-family:Playfair Display,Georgia,serif;'>"
            f"{rest}</div>"
        )

    main_html = (
        f"<div style='font-size:2.8rem;font-weight:400;line-height:1.1;"
        f"letter-spacing:-0.02em;color:#efefef;"
        f"font-family:Playfair Display,Georgia,serif;'>"
        f"{main}</div>"
    )

    st.markdown(
        f"<div style='padding:2.8rem 0 2rem;border-bottom:1px solid #1f1f1f;"
        f"margin-bottom:1.8rem;'>"
        f"{sub_html}{main_html}{gold_html}"
        f"</div>",
        unsafe_allow_html=True
    )


def section(text):
    st.markdown(
        f"<div style='font-size:0.58rem;font-weight:600;letter-spacing:0.18em;"
        f"text-transform:uppercase;color:#c9a84c;"
        f"padding-bottom:0.5rem;margin:2rem 0 1.1rem;"
        f"border-bottom:1px solid #1f1f1f;font-family:Inter,sans-serif;'>"
        f"{text}</div>",
        unsafe_allow_html=True
    )


def make_chart(fig):
    import io
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=130, bbox_inches="tight",
                facecolor='#0e0e0e', edgecolor="none")
    import matplotlib.pyplot as plt
    plt.close(fig)
    buf.seek(0)
    return buf


def style_axes(ax, title=""):
    ax.set_facecolor('#111111')
    ax.tick_params(colors='#484848', labelsize=8)
    for spine in ax.spines.values():
        spine.set_edgecolor('#1e1a10')
    if title:
        ax.set_title(title, color='#907860', fontsize=9,
                     fontweight="normal", pad=10)
    ax.xaxis.label.set_color('#484848')
    ax.yaxis.label.set_color('#484848')
    ax.figure.patch.set_facecolor('#0c0c0c')
    

# ─────────────────────────────────────────
# SIDEBAR
# ─────────────────────────────────────────
with st.sidebar:
    st.markdown(
        "<div style='padding:1.8rem 0.6rem 1.3rem 1rem;'>"
        "<div style='display:flex;align-items:center;gap:0.6rem;margin-bottom:0.45rem;'>"
        "<span style='font-size:1.1rem;'>🔐</span>"
        "<span style='font-size:0.88rem;font-weight:700;color:#c9a84c;"
        "letter-spacing:0.14em;font-family:Inter,sans-serif;'>CRYPTLAB</span>"
        "</div>"
        "<div style='font-size:0.52rem;color:#484848;letter-spacing:0.16em;"
        "text-transform:uppercase;font-family:Inter,sans-serif;'>Vulnerability Assessment</div>"
        "</div>",
        unsafe_allow_html=True
    )
    st.markdown(
        "<div style='height:1px;background:#1a1a1a;margin:0 0 0.6rem;'></div>",
        unsafe_allow_html=True
    )

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

    st.markdown(
        "<div style='height:1px;background:#1a1a1a;margin:1.2rem 0 0.8rem;'></div>"
        "<div style='font-size:0.52rem;color:#2e2e2e;letter-spacing:0.12em;"
        "text-transform:uppercase;margin-bottom:0.45rem;padding:0 0.4rem;"
        "font-family:Inter,sans-serif;'>Project</div>"
        "<div style='font-size:0.71rem;color:#484848;line-height:1.75;"
        "padding:0 0.4rem;font-family:Inter,sans-serif;'>"
        "Cryptanalysis of Weak Password Hashing Systems and AI-Based Defence Mechanism"
        "</div>"
        "<div style='height:1px;background:#1a1a1a;margin:0.9rem 0 0.6rem;'></div>"
        "<div style='font-size:0.6rem;color:#2a2a2a;padding:0 0.4rem;"
        "font-family:JetBrains Mono,monospace;'>Python · hashlib · bcrypt · argon2</div>",
        unsafe_allow_html=True
    )


# ══════════════════════════════════════════
# PAGE: OVERVIEW
# ══════════════════════════════════════════
if "Overview" in page:
    st.markdown(
        "<style>"
        ".ov-label { color: #c9a84c !important; }"
        ".ov-title { color: #efefef !important; }"
        ".ov-gold  { color: #c9a84c !important; }"
        ".ov-desc  { color: #666666 !important; }"
        ".ov-desc .ov-gold { color: #c9a84c !important; font-weight:500 !important; }"
        "</style>"
        "<div style='padding:2.8rem 0 2rem;border-bottom:1px solid #1f1f1f;margin-bottom:1.8rem;'>"
        "<div class='ov-label' style='font-size:0.6rem;font-weight:600;letter-spacing:0.2em;"
        "text-transform:uppercase;margin-bottom:1rem;font-family:Inter,sans-serif;'>"
        "Cryptanalysis Lab  &middot;  University Research Project"
        "</div>"
        "<div class='ov-title' style='font-size:2.8rem;font-weight:400;line-height:1.1;"
        "letter-spacing:-0.02em;margin-bottom:0.05rem;"
        "font-family:Playfair Display,Georgia,serif;'>"
        "Weak Password Hashing"
        "</div>"
        "<div class='ov-gold' style='font-size:2.8rem;font-weight:400;line-height:1.1;"
        "letter-spacing:-0.02em;margin-bottom:1rem;font-style:italic;"
        "font-family:Playfair Display,Georgia,serif;'>"
        "&amp; AI-Based Defence"
        "</div>"
        "<p class='ov-desc' style='line-height:1.9;max-width:640px;font-size:0.87rem;"
        "font-weight:400;margin:0;font-family:Inter,sans-serif;'>"
        "Investigating cryptographic vulnerabilities in legacy hashing algorithms (MD5, SHA-1), "
        "simulating dictionary and brute-force attacks, and building a robust "
        "<span class='ov-gold'>machine-learning defence system</span>"
        " with memory-hard hashing."
        "</p>"
        "</div>",
        unsafe_allow_html=True
    )

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
        <div style='background:#0e0e0e;border:1px solid #1f1f1f;border-top:2px solid #c47a44;
             border-radius:9px;padding:1.5rem;height:100%;'>
            <div style='color:#c47a44;font-size:0.57rem;font-weight:700;letter-spacing:0.18em;margin-bottom:0.9rem;font-family:Inter,sans-serif;'>MODULE I</div>
            <div style='color:#efefef;font-size:1rem;font-family:Playfair Display,Georgia,serif;margin-bottom:0.2rem;'>Vulnerability Assessment</div>
            <div style='color:#484848;font-size:0.7rem;margin-bottom:1rem;font-family:Inter,sans-serif;'>Hash Lab · Attack Simulation</div>
            <div style='height:1px;background:#1a1a1a;margin:0.7rem 0;'></div>
            <ul style='color:#484848;font-size:0.74rem;line-height:2.1;margin:0;padding-left:1rem;font-family:Inter,sans-serif;'>
                <li>MD5 &amp; SHA-1 analysis</li>
                <li>Weak password dataset generation</li>
                <li>Dictionary attack simulation</li>
                <li>Brute-force attack simulation</li>
                <li>Cracking time benchmarking</li>
                <li>No-salt vulnerability demo</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown("""
        <div style='background:#0e0e0e;border:1px solid #1f1f1f;border-top:2px solid #8066cc;
             border-radius:9px;padding:1.5rem;height:100%;'>
            <div style='color:#8066cc;font-size:0.57rem;font-weight:700;letter-spacing:0.18em;margin-bottom:0.9rem;font-family:Inter,sans-serif;'>MODULE II</div>
            <div style='color:#efefef;font-size:1rem;font-family:Playfair Display,Georgia,serif;margin-bottom:0.2rem;'>Cryptanalysis &amp; AI</div>
            <div style='color:#484848;font-size:0.7rem;margin-bottom:1rem;font-family:Inter,sans-serif;'>Entropy · Patterns · ML Classifier</div>
            <div style='height:1px;background:#1a1a1a;margin:0.7rem 0;'></div>
            <ul style='color:#484848;font-size:0.74rem;line-height:2.1;margin:0;padding-left:1rem;font-family:Inter,sans-serif;'>
                <li>Shannon entropy analysis</li>
                <li>Statistical pattern recognition</li>
                <li>Random Forest ML classifier</li>
                <li>Attack priority prediction</li>
                <li>Hash computation speed comparison</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)

    with col3:
        st.markdown("""
        <div style='background:#0e0e0e;border:1px solid #1f1f1f;border-top:2px solid #4aaa7a;
             border-radius:9px;padding:1.5rem;height:100%;'>
            <div style='color:#4aaa7a;font-size:0.57rem;font-weight:700;letter-spacing:0.18em;margin-bottom:0.9rem;font-family:Inter,sans-serif;'>MODULE III</div>
            <div style='color:#efefef;font-size:1rem;font-family:Playfair Display,Georgia,serif;margin-bottom:0.2rem;'>Defence Architecture</div>
            <div style='color:#484848;font-size:0.7rem;margin-bottom:1rem;font-family:Inter,sans-serif;'>bcrypt · Argon2 · Policy · AI Guard</div>
            <div style='height:1px;background:#1a1a1a;margin:0.7rem 0;'></div>
            <ul style='color:#484848;font-size:0.74rem;line-height:2.1;margin:0;padding-left:1rem;font-family:Inter,sans-serif;'>
                <li>bcrypt &amp; Argon2 secure hashing</li>
                <li>Automatic salting &amp; key stretching</li>
                <li>Multi-rule password policy engine</li>
                <li>AI-based weak password detection</li>
                <li>Quantified security improvements</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    section("ATTACK PIPELINE — HOW IT WORKS")

    st.markdown("""
    <div style='display:flex;align-items:stretch;border:1px solid #1f1f1f;border-radius:9px;overflow:hidden;margin:0.5rem 0 1.5rem;'>
        <div style='flex:1;background:#0e0e0e;padding:1.4rem 1rem;text-align:center;border-right:1px solid #1a1a1a;'>
            <div style='font-size:1.3rem;margin-bottom:0.6rem;'>🗂️</div>
            <div style='color:#c47a44;font-size:0.55rem;font-weight:700;letter-spacing:0.18em;font-family:Inter,sans-serif;'>STEP 1</div>
            <div style='color:#efefef;font-size:0.8rem;font-weight:600;margin-top:0.4rem;font-family:Inter,sans-serif;'>Dataset</div>
            <div style='color:#484848;font-size:0.66rem;margin-top:0.2rem;font-family:Inter,sans-serif;'>Weak passwords + hashes</div>
        </div>
        <div style='flex:1;background:#0e0e0e;padding:1.4rem 1rem;text-align:center;border-right:1px solid #1a1a1a;'>
            <div style='font-size:1.3rem;margin-bottom:0.6rem;'>⚔️</div>
            <div style='color:#c45c5c;font-size:0.55rem;font-weight:700;letter-spacing:0.18em;font-family:Inter,sans-serif;'>STEP 2</div>
            <div style='color:#efefef;font-size:0.8rem;font-weight:600;margin-top:0.4rem;font-family:Inter,sans-serif;'>Attack</div>
            <div style='color:#484848;font-size:0.66rem;margin-top:0.2rem;font-family:Inter,sans-serif;'>Dictionary &amp; brute-force</div>
        </div>
        <div style='flex:1;background:#0e0e0e;padding:1.4rem 1rem;text-align:center;border-right:1px solid #1a1a1a;'>
            <div style='font-size:1.3rem;margin-bottom:0.6rem;'>📊</div>
            <div style='color:#8066cc;font-size:0.55rem;font-weight:700;letter-spacing:0.18em;font-family:Inter,sans-serif;'>STEP 3</div>
            <div style='color:#efefef;font-size:0.8rem;font-weight:600;margin-top:0.4rem;font-family:Inter,sans-serif;'>Cryptanalysis</div>
            <div style='color:#484848;font-size:0.66rem;margin-top:0.2rem;font-family:Inter,sans-serif;'>Entropy · ML · Timing</div>
        </div>
        <div style='flex:1;background:#0e0e0e;padding:1.4rem 1rem;text-align:center;border-right:1px solid #1a1a1a;'>
            <div style='font-size:1.3rem;margin-bottom:0.6rem;'>🛡️</div>
            <div style='color:#4aaa7a;font-size:0.55rem;font-weight:700;letter-spacing:0.18em;font-family:Inter,sans-serif;'>STEP 4</div>
            <div style='color:#efefef;font-size:0.8rem;font-weight:600;margin-top:0.4rem;font-family:Inter,sans-serif;'>Defence</div>
            <div style='color:#484848;font-size:0.66rem;margin-top:0.2rem;font-family:Inter,sans-serif;'>bcrypt · Argon2 · AI</div>
        </div>
        <div style='flex:1;background:#0e0e0e;padding:1.4rem 1rem;text-align:center;'>
            <div style='font-size:1.3rem;margin-bottom:0.6rem;'>✅</div>
            <div style='color:#c9a84c;font-size:0.55rem;font-weight:700;letter-spacing:0.18em;font-family:Inter,sans-serif;'>STEP 5</div>
            <div style='color:#efefef;font-size:0.8rem;font-weight:600;margin-top:0.4rem;font-family:Inter,sans-serif;'>Validation</div>
            <div style='color:#484848;font-size:0.66rem;margin-top:0.2rem;font-family:Inter,sans-serif;'>Quantify improvement</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    section("TECHNOLOGY STACK")
    tools = [
        ("Python 3.12", "Core implementation language"),
        ("hashlib", "MD5 / SHA-1 hashing primitives"),
        ("bcrypt", "Adaptive salted password hashing"),
        ("argon2-cffi", "Memory-hard hashing (PHC winner)"),
        ("scikit-learn", "Random Forest ML classifier"),
        ("NumPy / Pandas", "Numerical analysis & data handling"),
        ("Matplotlib", "Attack visualisation & charts"),
        ("ReportLab", "10-page academic PDF export"),
    ]
    cols = st.columns(4)
    for i, (tool, desc) in enumerate(tools):
        with cols[i % 4]:
            st.markdown(f"""
            <div style='background:#0e0e0e;border:1px solid #1f1f1f;border-radius:7px;
                 padding:0.9rem;margin-bottom:0.6rem;'>
                <div style='color:#c9a84c;font-weight:600;font-size:0.79rem;margin-bottom:0.3rem;font-family:JetBrains Mono,monospace;'>{tool}</div>
                <div style='color:#484848;font-size:0.68rem;font-family:Inter,sans-serif;'>{desc}</div>
            </div>""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    section("KEY FINDINGS")

    fc1, fc2, fc3, fc4 = st.columns(4)
    with fc1:
        st.markdown("""
        <div style='background:#0e0e0e;border:1px solid #1f1212;border-radius:9px;padding:1.2rem;text-align:center;'>
            <div style='color:#c45c5c;font-size:2rem;font-weight:400;font-family:Playfair Display,Georgia,serif;'>10⁸</div>
            <div style='color:#555555;font-size:0.72rem;margin-top:0.3rem;font-family:Inter,sans-serif;'>MD5 hashes/second</div>
            <div style='color:#484848;font-size:0.65rem;font-family:Inter,sans-serif;'>attacker can compute</div>
        </div>""", unsafe_allow_html=True)
    with fc2:
        st.markdown("""
        <div style='background:#0e0e0e;border:1px solid #1f1510;border-radius:9px;padding:1.2rem;text-align:center;'>
            <div style='color:#c47a44;font-size:2rem;font-weight:400;font-family:Playfair Display,Georgia,serif;'>~100%</div>
            <div style='color:#555555;font-size:0.72rem;margin-top:0.3rem;font-family:Inter,sans-serif;'>Dictionary attack success</div>
            <div style='color:#484848;font-size:0.65rem;font-family:Inter,sans-serif;'>on weak passwords</div>
        </div>""", unsafe_allow_html=True)
    with fc3:
        st.markdown("""
        <div style='background:#0e0e0e;border:1px solid #121f15;border-radius:9px;padding:1.2rem;text-align:center;'>
            <div style='color:#4aaa7a;font-size:2rem;font-weight:400;font-family:Playfair Display,Georgia,serif;'>10,000×</div>
            <div style='color:#555555;font-size:0.72rem;margin-top:0.3rem;font-family:Inter,sans-serif;'>bcrypt slower than MD5</div>
            <div style='color:#484848;font-size:0.65rem;font-family:Inter,sans-serif;'>dramatically safer</div>
        </div>""", unsafe_allow_html=True)
    with fc4:
        st.markdown("""
        <div style='background:#0e0e0e;border:1px solid #1f1a12;border-radius:9px;padding:1.2rem;text-align:center;'>
            <div style='color:#c9a84c;font-size:2rem;font-weight:400;font-family:Playfair Display,Georgia,serif;'>21</div>
            <div style='color:#555555;font-size:0.72rem;margin-top:0.3rem;font-family:Inter,sans-serif;'>ML model features</div>
            <div style='color:#484848;font-size:0.65rem;font-family:Inter,sans-serif;'>Random Forest classifier</div>
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
                c1.markdown("<div style='color:#c47a44;font-weight:600;padding-top:0.5rem;font-size:0.8rem;font-family:JetBrains Mono,monospace;'>MD5</div>", unsafe_allow_html=True)
                c2.code(h, language=None)
            if algo in ("sha1", "both"):
                h = hash_sha1(pwd_input)
                c1, c2 = st.columns([1, 3])
                c1.markdown("<div style='color:#8066cc;font-weight:600;padding-top:0.5rem;font-size:0.8rem;font-family:JetBrains Mono,monospace;'>SHA-1</div>", unsafe_allow_html=True)
                c2.code(h, language=None)

            st.markdown("---")
            section("Why This Is Dangerous")
            vc1, vc2, vc3 = st.columns(3)
            vc1.error("✗  No salt — same password always gives same hash")
            vc2.error("✗  Extremely fast — billions of attempts per second")
            vc3.error("✗  Rainbow table lookups crack common passwords instantly")

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

            section("Sample — Password → Hash")
            sample_df = pd.DataFrame(
                [(p, hash_md5(p), hash_sha1(p)) for p in passwords[:15]],
                columns=["Password", "MD5 Hash", "SHA-1 Hash"]
            )
            st.dataframe(sample_df, width='stretch')

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
        st.dataframe(pd.DataFrame(rows), width='stretch')

        st.markdown("<br>", unsafe_allow_html=True)
        section("Hash Speed — Why MD5/SHA1 Are Dangerous")
        if st.button("🔬 Measure Hash Speed"):
            samples = ["password", "abc123", "qwerty", "letmein", "dragon"]
            iters = 10000
            t0 = time.perf_counter()
            for _ in range(iters): hash_md5(samples[_ % len(samples)])
            md5_t = (time.perf_counter() - t0) / iters
            t0 = time.perf_counter()
            for _ in range(iters): hash_sha1(samples[_ % len(samples)])
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

                r1, r2, r3, r4 = st.columns(4)
                r1.metric("Targets", result["total_targets"])
                r2.metric("Cracked", len(result["cracked"]))
                r3.metric("Success Rate", f"{result['success_rate']:.1f}%")
                r4.metric("Time", f"{result['elapsed_seconds']:.4f}s")

                if result["cracked"]:
                    section("Recovered Passwords")
                    cracked_df = pd.DataFrame(
                        [(h[:20]+"...", p) for h, p in result["cracked"].items()],
                        columns=["Hash (truncated)", "Cracked Password"]
                    )
                    st.dataframe(cracked_df, width='stretch')
                    st.success(f"✓  Dictionary attack cracked {len(result['cracked'])} out of {result['total_targets']} hashes!")

        with tab2:
            section("Brute-Force Attack")
            st.write("Tries **every possible character combination** up to a max length.")
            bf_algo = st.selectbox("Hash Algorithm", ["md5", "sha1"], key="bf_algo")
            bf_maxlen = st.slider("Max password length to try:", 2, 5, 3)
            bf_count = st.slider("Number of short target passwords:", 1, 5, 3)
            bf_charset = st.selectbox("Character set", [
                "abcdefghijklmnopqrstuvwxyz0123456789",
                "abcdefghijklmnopqrstuvwxyz",
                "0123456789",
            ])

            if st.button("💥 Run Brute-Force Attack"):
                short_pwds = [p for p in passwords if len(p) <= bf_maxlen][:bf_count]
                if not short_pwds:
                    short_pwds = ["abc", "123", "hi"][:bf_count]
                target_hashes = [hash_password(p, bf_algo) for p in short_pwds]
                with st.spinner(f"Running brute-force..."):
                    result = brute_force_attack(
                        target_hashes, bf_algo,
                        charset=bf_charset, min_length=1,
                        max_length=bf_maxlen, max_attempts=2_000_000,
                    )
                st.session_state["brute_result"] = result

                b1, b2, b3, b4 = st.columns(4)
                b1.metric("Targets", result["total_targets"])
                b2.metric("Cracked", len(result["cracked"]))
                b3.metric("Success Rate", f"{result['success_rate']:.1f}%")
                b4.metric("Time", f"{result['elapsed_seconds']:.4f}s")

                if result["cracked"]:
                    section("Recovered Passwords")
                    cracked_df = pd.DataFrame(
                        [(h[:20]+"...", p) for h, p in result["cracked"].items()],
                        columns=["Hash (truncated)", "Cracked Password"]
                    )
                    st.dataframe(cracked_df, width='stretch')

        with tab3:
            section("Attack Comparison Charts")
            if "dict_result" not in st.session_state and "brute_result" not in st.session_state:
                st.info("Run attacks in the other tabs first to see comparison charts here.")
            else:
                results = []
                if "dict_result" in st.session_state: results.append(st.session_state["dict_result"])
                if "brute_result" in st.session_state: results.append(st.session_state["brute_result"])

                labels = [f"{r['attack_type'].replace('_',' ').title()}\n({r['algorithm'].upper()})" for r in results]
                fig, axes = plt.subplots(1, 3, figsize=(13, 4))
                fig.patch.set_facecolor("#070707")

                success = [r["success_rate"] for r in results]
                axes[0].bar(labels, success, color=["#c47a44", "#8066cc"][:len(results)], edgecolor='#1e1a10')
                axes[0].set_ylabel("Success Rate (%)", color="#383838")
                axes[0].set_ylim(0, 110)
                for bar, v in zip(axes[0].patches, success):
                    axes[0].text(bar.get_x()+bar.get_width()/2, bar.get_height()+1, f"{v:.1f}%", ha='center', color='#f0e8d5', fontsize=9)
                style_axes(axes[0], "Success Rate (%)")

                times = [r["elapsed_seconds"] for r in results]
                axes[1].bar(labels, times, color=["#c8a84b", "#4aaa7a"][:len(results)], edgecolor='#1e1a10')
                axes[1].set_ylabel("Time (seconds)", color="#383838")
                style_axes(axes[1], "Cracking Time (s)")

                attempts = [r["attempts"] for r in results]
                axes[2].bar(labels, attempts, color=["#c45c5c", "#c8a84b"][:len(results)], edgecolor='#1e1a10')
                axes[2].set_ylabel("Attempts", color="#383838")
                axes[2].set_yscale("log")
                style_axes(axes[2], "Hash Attempts (log)")

                plt.tight_layout()
                st.image(make_chart(fig), width='stretch')


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
            if ent < 2.0: st.error("✗  Very LOW entropy — easily predictable.")
            elif ent < 3.0: st.warning("⚠  Moderate entropy — some patterns detected.")
            else: st.success("✓  High entropy — good randomness.")

        st.markdown("---")
        section("Entropy Distribution — Dataset")
        df_feats = password_features(passwords)
        df_feats["entropy"] = [shannon_entropy(p) for p in passwords]

        fig, axes = plt.subplots(1, 2, figsize=(12, 4))
        fig.patch.set_facecolor("#070707")
        axes[0].hist(df_feats["entropy"], bins=12, color="#c8a84b", edgecolor='#0d0b07', alpha=0.85)
        axes[0].set_xlabel("Shannon Entropy (bits/char)")
        axes[0].set_ylabel("Password Count")
        style_axes(axes[0], "Entropy Distribution")
        axes[1].scatter(df_feats["length"], df_feats["entropy"], color="#c47a44", alpha=0.7, s=40, edgecolors="#181818")
        axes[1].set_xlabel("Password Length")
        axes[1].set_ylabel("Entropy (bits/char)")
        style_axes(axes[1], "Length vs Entropy")
        plt.tight_layout()
        st.image(make_chart(fig), width='stretch')

    with tab2:
        section("Statistical Pattern Analysis")
        df_feats2 = password_features(passwords)
        df_feats2["entropy"] = [shannon_entropy(p) for p in passwords]
        p1, p2, p3, p4 = st.columns(4)
        p1.metric("Avg Length", f"{df_feats2['length'].mean():.1f}")
        p2.metric("Avg Entropy", f"{df_feats2['entropy'].mean():.2f} bits")
        p3.metric("Avg Unique Chars", f"{df_feats2['unique_chars'].mean():.1f}")
        p4.metric("Total Passwords", len(passwords))

        patterns = analyze_patterns(passwords, top_n=8)
        fig, axes = plt.subplots(1, 3, figsize=(14, 4))
        fig.patch.set_facecolor("#070707")

        len_counts = patterns["length_counts"]
        axes[0].bar(list(len_counts.keys()), list(len_counts.values()), color="#8066cc", edgecolor='#0d0b07')
        axes[0].set_xlabel("Password Length"); axes[0].set_ylabel("Count")
        style_axes(axes[0], "Length Distribution")

        top_pref = patterns["top_prefixes"][:8]
        axes[1].barh([p[0] for p in top_pref], [p[1] for p in top_pref], color="#c47a44", edgecolor='#0d0b07')
        axes[1].set_xlabel("Frequency")
        style_axes(axes[1], "Top Prefixes (first 3 chars)")

        feat_means = df_feats2[["digits","lower","upper","special"]].mean()
        axes[2].bar(["Digits","Lower","Upper","Special"], feat_means.values,
                    color=["#c8a84b","#4aaa7a","#c47a44","#8066cc"], edgecolor='#0d0b07')
        axes[2].set_ylabel("Avg Count per Password")
        style_axes(axes[2], "Char Type Breakdown")

        plt.tight_layout()
        st.image(make_chart(fig), width='stretch')
        section("Password Feature Table (Sample)")
        st.dataframe(df_feats2.head(15), width='stretch')

    with tab3:
        section("ML Password Strength Classifier")
        st.write("Random Forest model trained on weak vs strong passwords.")
        single_pwd = st.text_input("Test a password against the AI model:", placeholder="Enter password...")
        if single_pwd:
            prob = predict_weak_password(single_pwd)
            mc1, mc2, mc3 = st.columns(3)
            mc1.metric("Weak Probability", f"{prob:.1%}")
            mc2.metric("Strong Probability", f"{1-prob:.1%}")
            mc3.metric("Prediction", "WEAK" if prob > 0.5 else "STRONG")
            st.progress(float(prob))
            if prob > 0.7: st.error(f"🚨  Model is {prob:.1%} confident this password is WEAK.")
            elif prob > 0.4: st.warning(f"⚠  Moderate password strength.")
            else: st.success(f"✓  Model classifies this as STRONG ({(1-prob):.1%} confidence).")

        st.markdown("---")
        section("Attack Prediction — Rank Dataset by Weakness")
        if st.button("🤖 Run Attack Prediction on Dataset"):
            probs = []
            for p in passwords:
                try: probs.append((p, predict_weak_password(p)))
                except: probs.append((p, 0.5))
            ranked = sorted(probs, key=lambda x: x[1], reverse=True)
            df_ranked = pd.DataFrame(ranked[:20], columns=["Password", "Weak Probability"])
            df_ranked["Weak Probability"] = df_ranked["Weak Probability"].apply(lambda x: f"{x:.1%}")
            df_ranked["Attack Priority"] = [f"#{i+1}" for i in range(len(df_ranked))]
            st.dataframe(df_ranked, width='stretch')

    with tab4:
        section("Hash Computation Time Comparison")
        if st.button("⏱️ Run Hash Timing Benchmark"):
            samples = passwords[:10] if len(passwords) >= 5 else ["password", "abc", "123456", "admin", "qwerty"]
            with st.spinner("Benchmarking..."):
                md5_t  = measure_hash_time(hash_md5,  samples[0], iterations=5000)
                sha1_t = measure_hash_time(hash_sha1, samples[0], iterations=5000)
            t1, t2, t3, t4 = st.columns(4)
            t1.metric("MD5 avg", f"{md5_t*1e6:.2f} µs")
            t2.metric("SHA-1 avg", f"{sha1_t*1e6:.2f} µs")
            t3.metric("MD5 hashes/sec", f"{int(1/md5_t):,}")
            t4.metric("SHA-1 hashes/sec", f"{int(1/sha1_t):,}")
            fig, ax = plt.subplots(figsize=(7, 3.5))
            fig.patch.set_facecolor("#070707")
            bars = ax.bar(["MD5", "SHA-1"], [md5_t*1e6, sha1_t*1e6],
                          color=["#c47a44","#8066cc"], edgecolor='#1e1a10', width=0.4)
            for bar, v in zip(bars, [md5_t*1e6, sha1_t*1e6]):
                ax.text(bar.get_x()+bar.get_width()/2, bar.get_height()+0.01,
                        f"{v:.3f} µs", ha='center', color='#f0e8d5', fontsize=10)
            ax.set_ylabel("Avg Time per Hash (µs)")
            style_axes(ax, "MD5 vs SHA-1 — Average Hash Time")
            plt.tight_layout()
            st.image(make_chart(ax.figure), width='stretch')
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
                st.markdown("<div style='color:#4aaa7a;font-weight:700;letter-spacing:0.12em;font-size:0.75rem;font-family:JetBrains Mono,monospace;margin-bottom:0.5rem;'>BCRYPT</div>", unsafe_allow_html=True)
                if st.button("🔒 Hash with bcrypt"):
                    with st.spinner("Hashing..."):
                        t0 = time.perf_counter(); bh = hash_bcrypt(sec_pwd); bt = time.perf_counter() - t0
                    st.code(bh, language=None)
                    st.metric("Time taken", f"{bt*1000:.1f} ms")
                    st.success("✓  bcrypt includes automatic salt!")
                    st.metric("Verification", "✓ PASS" if verify_bcrypt(sec_pwd, bh) else "✗ FAIL")
            with sh2:
                st.markdown("<div style='color:#c9a84c;font-weight:700;letter-spacing:0.12em;font-size:0.75rem;font-family:JetBrains Mono,monospace;margin-bottom:0.5rem;'>ARGON2</div>", unsafe_allow_html=True)
                if st.button("🔒 Hash with Argon2"):
                    with st.spinner("Hashing..."):
                        t0 = time.perf_counter(); ah = hash_argon2(sec_pwd); at = time.perf_counter() - t0
                    st.code(ah, language=None)
                    st.metric("Time taken", f"{at*1000:.1f} ms")
                    st.success("✓  Argon2 is memory-hard — resistant to GPU attacks!")
                    st.metric("Verification", "✓ PASS" if verify_argon2(sec_pwd, ah) else "✗ FAIL")

        st.markdown("---")
        section("Why Slow Hashing Matters")
        sc1, sc2, sc3 = st.columns(3)
        sc1.success("✓  bcrypt: ~100ms per hash → ~10 attempts/sec for attacker")
        sc2.success("✓  Argon2: memory-hard → GPU farms ineffective")
        sc3.success("✓  Cost factor configurable → grows with hardware")

    with tab2:
        section("Salting Demonstration")
        salt_pwd = st.text_input("Password to salt and hash:", placeholder="e.g. password123", key="salt_input")
        if salt_pwd and st.button("🎲 Generate Salted Hashes"):
            salts = [generate_salt() for _ in range(4)]
            rows = []
            for s in salts:
                salted = salt_pwd + s
                rows.append({"Salt (hex)": s, "Salted Input": salted[:20]+"...", "MD5(password+salt)": hash_md5(salted)})
            st.dataframe(pd.DataFrame(rows), width='stretch')
            st.success("✓  Same password produces 4 completely different hashes — rainbow table attacks defeated!")

        st.markdown("---")
        section("bcrypt Built-in Salting")
        salt_demo_pwd = st.text_input("Password:", placeholder="test password", key="bcrypt_salt_demo")
        if salt_demo_pwd and st.button("Show bcrypt Salt Demo"):
            h1 = hash_bcrypt(salt_demo_pwd); h2 = hash_bcrypt(salt_demo_pwd)
            sd1, sd2 = st.columns(2)
            sd1.markdown("**Hash 1:**"); sd1.code(h1, language=None)
            sd2.markdown("**Hash 2 (same password):**"); sd2.code(h2, language=None)
            st.success(f"✓  Different every time, but both verify correctly!")

    with tab3:
        section("Password Policy Enforcement")
        pol_pwd = st.text_input("Test a password against policy:", placeholder="e.g. mypassword", key="pol_input")
        if pol_pwd:
            compliant = check_password_policy(pol_pwd)
            if compliant: st.success("✓  Password meets all policy requirements!")
            else: st.error("✗  Password fails policy check!")

            section("Policy Checklist")
            rules = [
                ("Minimum 8 characters", len(pol_pwd) >= 8),
                ("Contains uppercase letter (A-Z)", any(c.isupper() for c in pol_pwd)),
                ("Contains lowercase letter (a-z)", any(c.islower() for c in pol_pwd)),
                ("Contains digit (0-9)", any(c.isdigit() for c in pol_pwd)),
                ("Contains special character", any(not c.isalnum() for c in pol_pwd)),
            ]
            for rule, passed in rules:
                if passed: st.success(f"✓  {rule}")
                else: st.error(f"✗  {rule}")

        st.markdown("---")
        section("Batch Policy Audit")
        batch = st.text_area("Paste passwords (one per line):", height=120, placeholder="password123\nAdmin@2024!\nabc")
        if batch.strip() and st.button("Run Policy Audit"):
            pwds = [p.strip() for p in batch.strip().splitlines() if p.strip()]
            rows = []
            for p in pwds:
                fb = password_policy_feedback(p)
                rows.append({"Password (masked)": "*" * len(p), "Compliant": "✓" if not fb else "✗", "Issues": "; ".join(fb) if fb else "None"})
            df = pd.DataFrame(rows)
            st.dataframe(df, width='stretch')
            st.metric("Policy Compliance Rate", f"{(df['Compliant']=='✓').sum()/len(df)*100:.1f}%")

    with tab4:
        section("AI-Based Weak Password Detector")
        ai_pwd = st.text_input("Enter password for AI analysis:", placeholder="Any password...", key="ai_input")
        if ai_pwd:
            prob = predict_weak_password(ai_pwd)
            feats = extract_features(ai_pwd).iloc[0]
            ac1, ac2, ac3 = st.columns(3)
            ac1.metric("AI: Weak Probability", f"{prob:.1%}")
            ac2.metric("AI: Strong Probability", f"{1-prob:.1%}")
            ac3.metric("Classification", "⚠ WEAK" if prob > 0.5 else "✓ STRONG")
            st.progress(float(prob))

            section("Feature Breakdown (21 Features)")
            feat_dict = feats.to_dict()
            fd1, fd2, fd3 = st.columns(3)
            for i, (k, v) in enumerate(feat_dict.items()):
                [fd1, fd2, fd3][i % 3].metric(k.replace("_", " ").title(), round(float(v), 3))


# ══════════════════════════════════════════
# PAGE: VALIDATION METRICS
# ══════════════════════════════════════════
elif "Validation" in page:
    page_header("Validation Metrics", "Security Improvements  ·  Weak vs Secure System Comparison")

    pwd_path = DATA_DIR / "passwords.txt"
    passwords = generate_weak_passwords(extra_count=10) if not pwd_path.exists() else [l.strip() for l in pwd_path.read_text().splitlines() if l.strip()]

    st.write("Run the full validation to compare weak hashing (MD5/SHA-1) vs secure hashing (bcrypt/Argon2) and AI detection.")

    if st.button("🔬 Run Full Validation"):
        with st.spinner("Running validation metrics — bcrypt/argon2 are intentionally slow..."):
            metrics = validate_improvements(passwords[:10])

        section("Hash Speed Comparison — Weak vs Secure")
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("MD5 avg time", f"{metrics['md5_time']*1000:.4f} ms", delta="FAST = DANGEROUS", delta_color="inverse")
        m2.metric("SHA-1 avg time", f"{metrics['sha1_time']*1000:.4f} ms", delta="FAST = DANGEROUS", delta_color="inverse")
        m3.metric("bcrypt avg time", f"{metrics['bcrypt_time']*1000:.1f} ms", delta="SLOW = SECURE", delta_color="normal")
        m4.metric("Argon2 avg time", f"{metrics['argon2_time']*1000:.1f} ms", delta="SLOW = SECURE", delta_color="normal")

        bcrypt_ratio = metrics['bcrypt_time'] / metrics['md5_time']
        argon2_ratio = metrics['argon2_time'] / metrics['md5_time']

        section("Security Improvement Factors")
        r1, r2, r3 = st.columns(3)
        r1.metric("bcrypt vs MD5", f"{bcrypt_ratio:,.0f}x slower", delta="harder to brute-force", delta_color="normal")
        r2.metric("Argon2 vs MD5", f"{argon2_ratio:,.0f}x slower", delta="harder to brute-force", delta_color="normal")
        r3.metric("AI Weak Detection", f"{metrics['avg_weak_prob']:.1%}", delta="correctly identifies weak")

        st.markdown("---")
        section("Visual Comparison")
        fig, axes = plt.subplots(1, 3, figsize=(15, 5))
        fig.patch.set_facecolor("#070707")
        algos = ["MD5", "SHA-1", "bcrypt", "Argon2"]
        times = [metrics["md5_time"]*1000, metrics["sha1_time"]*1000, metrics["bcrypt_time"]*1000, metrics["argon2_time"]*1000]
        colors = ["#c45c5c","#c47a44","#4aaa7a","#c8a84b"]

        axes[0].bar(algos, times, color=colors, edgecolor='#1e1a10')
        axes[0].set_ylabel("Time per hash (ms)"); axes[0].set_yscale("log")
        style_axes(axes[0], "Hash Speed (log scale)")

        hashes_per_sec = [int(1/(t/1000)) for t in times]
        axes[1].bar(algos, hashes_per_sec, color=colors, edgecolor='#1e1a10')
        axes[1].set_ylabel("Hashes per second"); axes[1].set_yscale("log")
        style_axes(axes[1], "Hashes/sec — Attacker Speed")

        axes[2].bar(algos, [1/h if h > 0 else 0 for h in hashes_per_sec], color=colors, edgecolor='#1e1a10')
        axes[2].set_ylabel("Seconds per attempt"); axes[2].set_yscale("log")
        style_axes(axes[2], "Time per Attempt (log)")

        plt.tight_layout()
        st.image(make_chart(fig), width='stretch')

        section("Summary Table")
        st.markdown(f"""
        <div style='background:#0e0e0e;border:1px solid #1f1f1f;border-radius:9px;padding:1.5rem;'>
        <table style='width:100%;border-collapse:collapse;font-size:0.8rem;font-family:Inter,sans-serif;'>
        <tr style='border-bottom:1px solid #1f1f1f;'>
            <th style='color:#c9a84c;padding:0.5rem;text-align:left;letter-spacing:0.08em;'>Metric</th>
            <th style='color:#c45c5c;padding:0.5rem;'>MD5</th>
            <th style='color:#c47a44;padding:0.5rem;'>SHA-1</th>
            <th style='color:#4aaa7a;padding:0.5rem;'>bcrypt</th>
            <th style='color:#c9a84c;padding:0.5rem;'>Argon2</th>
        </tr>
        <tr style='border-bottom:1px solid #141414;'>
            <td style='color:#555555;padding:0.5rem;'>Avg Hash Time</td>
            <td style='color:#c45c5c;padding:0.5rem;text-align:center;'>{metrics["md5_time"]*1000:.4f} ms</td>
            <td style='color:#c47a44;padding:0.5rem;text-align:center;'>{metrics["sha1_time"]*1000:.4f} ms</td>
            <td style='color:#4aaa7a;padding:0.5rem;text-align:center;'>{metrics["bcrypt_time"]*1000:.1f} ms</td>
            <td style='color:#c9a84c;padding:0.5rem;text-align:center;'>{metrics["argon2_time"]*1000:.1f} ms</td>
        </tr>
        <tr style='border-bottom:1px solid #141414;'>
            <td style='color:#555555;padding:0.5rem;'>Built-in Salt</td>
            <td style='color:#c45c5c;padding:0.5rem;text-align:center;'>✗ No</td>
            <td style='color:#c47a44;padding:0.5rem;text-align:center;'>✗ No</td>
            <td style='color:#4aaa7a;padding:0.5rem;text-align:center;'>✓ Yes</td>
            <td style='color:#c9a84c;padding:0.5rem;text-align:center;'>✓ Yes</td>
        </tr>
        <tr>
            <td style='color:#555555;padding:0.5rem;'>Recommended Use</td>
            <td style='color:#c45c5c;padding:0.5rem;text-align:center;'>Never</td>
            <td style='color:#c47a44;padding:0.5rem;text-align:center;'>Never</td>
            <td style='color:#4aaa7a;padding:0.5rem;text-align:center;'>✓ Passwords</td>
            <td style='color:#c9a84c;padding:0.5rem;text-align:center;'>✓ Best Choice</td>
        </tr>
        </table>
        </div>
        """, unsafe_allow_html=True)

        section("Conclusion")
        st.markdown("""
        <div style='background:#0e0e0e;border-left:2px solid #4aaa7a;padding:1.3rem 1.6rem;border-radius:0 7px 7px 0;'>
            <p style='color:#666666;line-height:2;margin:0;font-size:0.84rem;font-family:Inter,sans-serif;'>
            This project demonstrates that <b style='color:#c45c5c;'>MD5 and SHA-1</b> are fundamentally broken for password storage.
            The defence system using <b style='color:#4aaa7a;'>bcrypt/Argon2</b> with built-in salting,
            combined with an <b style='color:#c9a84c;'>AI-based weak password detector</b> and
            <b style='color:#8066cc;'>strict password policies</b>, significantly improves security.
            </p>
        </div>
        """, unsafe_allow_html=True)


# ══════════════════════════════════════════
# PAGE: SECURITY INTELLIGENCE
# ══════════════════════════════════════════
elif "Security Intelligence" in page:
    page_header("Security Intelligence", "Live Password Threat Analysis  ·  Full-Spectrum Audit")

    st.markdown("""
    <div style='background:#0e0e0e;border:1px solid #1e1e12;border-left:2px solid #c9a84c;
         border-radius:0 7px 7px 0;padding:1.1rem 1.4rem;margin-bottom:1.5rem;'>
        <span style='color:#555555;font-size:0.84rem;line-height:1.9;font-family:Inter,sans-serif;'>
        Enter any password for a <b style='color:#c9a84c;'>full intelligence report</b> — 
        entropy, AI threat classification, estimated crack time, live hashes, policy compliance, and character composition.
        </span>
    </div>
    """, unsafe_allow_html=True)

    si_pwd = st.text_input("Enter password to analyse:", placeholder="Type any password...", type="password", key="si_pwd_input")
    show_plain = st.checkbox("Show password in plain text", value=False)
    if show_plain and si_pwd:
        st.markdown(f"<code style='color:#c9a84c;font-size:0.88rem;'>{si_pwd}</code>", unsafe_allow_html=True)

    if si_pwd:
        import string as _string
        ent = shannon_entropy(si_pwd)
        feats = password_features([si_pwd]).iloc[0]
        ai_prob = predict_weak_password(si_pwd)
        policy_ok = check_password_policy(si_pwd)

        has_upper   = any(c.isupper() for c in si_pwd)
        has_lower   = any(c.islower() for c in si_pwd)
        has_digit   = any(c.isdigit() for c in si_pwd)
        has_special = any(c in _string.punctuation for c in si_pwd)
        charset_size = (26 if has_lower else 0)+(26 if has_upper else 0)+(10 if has_digit else 0)+(32 if has_special else 0)
        total_combinations = charset_size ** len(si_pwd) if charset_size else 1

        DICT_RATE=10_000; BRUTE_RATE=1_000_000_000; BCRYPT_RATE=15

        def fmt_time(s):
            if s<1: return f"{s*1000:.1f} ms"
            if s<60: return f"{s:.1f} sec"
            if s<3600: return f"{s/60:.1f} min"
            if s<86400: return f"{s/3600:.1f} hrs"
            if s<2592000: return f"{s/86400:.1f} days"
            if s<31536000: return f"{s/2592000:.1f} months"
            return f"{s/31536000:.1f} years"

        crack_dict   = fmt_time(total_combinations/DICT_RATE)
        crack_brute  = fmt_time(total_combinations/BRUTE_RATE)
        crack_bcrypt = fmt_time(total_combinations/BCRYPT_RATE)

        score = min(100, min(30,len(si_pwd)*2) + (15 if has_upper else 0) + (15 if has_lower else 0) +
                    (15 if has_digit else 0) + (15 if has_special else 0) + int(ent*3) + (10 if policy_ok else 0))

        if score>=80: threat_level,threat_color,threat_label="LOW","#4aaa7a","STRONG"
        elif score>=55: threat_level,threat_color,threat_label="MODERATE","#c8a84b","MODERATE"
        elif score>=30: threat_level,threat_color,threat_label="HIGH","#c47a44","WEAK"
        else: threat_level,threat_color,threat_label="CRITICAL","#c45c5c","CRITICAL"

        st.markdown(f"""
        <div style='background:#0e0e0e;border:1px solid {threat_color}22;border-radius:10px;padding:2rem;margin:1.2rem 0;'>
            <div style='display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:1rem;'>
                <div>
                    <div style='color:#303030;font-size:0.57rem;font-weight:700;letter-spacing:0.2em;font-family:Inter,sans-serif;'>OVERALL THREAT LEVEL</div>
                    <div style='color:{threat_color};font-size:3rem;font-weight:400;letter-spacing:0.04em;margin-top:0.3rem;line-height:1;font-family:Playfair Display,Georgia,serif;'>{threat_level}</div>
                    <div style='color:#555555;font-size:0.76rem;margin-top:0.5rem;font-family:Inter,sans-serif;'>Classified as <b style='color:{threat_color};'>{threat_label}</b></div>
                </div>
                <div style='text-align:right;'>
                    <div style='color:#303030;font-size:0.57rem;font-weight:700;letter-spacing:0.2em;font-family:Inter,sans-serif;'>SECURITY SCORE</div>
                    <div style='color:{threat_color};font-size:3.8rem;font-weight:400;line-height:1;font-family:Playfair Display,Georgia,serif;'>{score}<span style='font-size:1rem;color:#303030;'>/100</span></div>
                </div>
            </div>
            <div style='margin-top:1.3rem;background:#1e1a10;border-radius:4px;height:2px;overflow:hidden;'>
                <div style='width:{score}%;background:{threat_color};height:100%;border-radius:4px;'></div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        si1, si2, si3, si4, si5 = st.columns(5)
        si1.metric("Length", len(si_pwd))
        si2.metric("Entropy", f"{ent:.2f} bits/char")
        si3.metric("AI Weak Prob.", f"{ai_prob:.1%}")
        si4.metric("Charset Size", charset_size)
        si5.metric("Combinations", f"{total_combinations:.2e}")

        st.markdown("<br>", unsafe_allow_html=True)
        section("ESTIMATED CRACK TIME")
        c1, c2, c3 = st.columns(3)
        with c1:
            st.markdown(f"""<div style='background:#0e0e0e;border:1px solid #1f1212;border-radius:9px;padding:1.3rem;text-align:center;'>
                <div style='color:#c45c5c;font-size:0.57rem;font-weight:700;letter-spacing:0.15em;font-family:Inter,sans-serif;'>DICTIONARY ATTACK</div>
                <div style='color:#efefef;font-size:1.5rem;font-weight:400;margin:0.5rem 0;font-family:Playfair Display,Georgia,serif;'>{crack_dict}</div>
                <div style='color:#484848;font-size:0.68rem;font-family:Inter,sans-serif;'>at {DICT_RATE:,} attempts/sec</div>
            </div>""", unsafe_allow_html=True)
        with c2:
            st.markdown(f"""<div style='background:#0e0e0e;border:1px solid #1f1510;border-radius:9px;padding:1.3rem;text-align:center;'>
                <div style='color:#c47a44;font-size:0.57rem;font-weight:700;letter-spacing:0.15em;font-family:Inter,sans-serif;'>BRUTE-FORCE (GPU)</div>
                <div style='color:#efefef;font-size:1.5rem;font-weight:400;margin:0.5rem 0;font-family:Playfair Display,Georgia,serif;'>{crack_brute}</div>
                <div style='color:#484848;font-size:0.68rem;font-family:Inter,sans-serif;'>at {BRUTE_RATE/1e9:.0f}B attempts/sec</div>
            </div>""", unsafe_allow_html=True)
        with c3:
            st.markdown(f"""<div style='background:#0e0e0e;border:1px solid #121f15;border-radius:9px;padding:1.3rem;text-align:center;'>
                <div style='color:#4aaa7a;font-size:0.57rem;font-weight:700;letter-spacing:0.15em;font-family:Inter,sans-serif;'>WITH BCRYPT DEFENCE</div>
                <div style='color:#efefef;font-size:1.5rem;font-weight:400;margin:0.5rem 0;font-family:Playfair Display,Georgia,serif;'>{crack_bcrypt}</div>
                <div style='color:#484848;font-size:0.68rem;font-family:Inter,sans-serif;'>at only {BCRYPT_RATE} attempts/sec</div>
            </div>""", unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)
        t_hash, t_ai, t_policy, t_compose = st.tabs(["🔑  LIVE HASHES", "🤖  AI ANALYSIS", "🛡️  POLICY AUDIT", "📊  COMPOSITION"])

        with t_hash:
            section("ALL FOUR ALGORITHMS — LIVE OUTPUT")
            h_md5 = hash_md5(si_pwd); h_sha1 = hash_sha1(si_pwd)
            col_a, col_b = st.columns(2)
            with col_a:
                st.markdown("""<div style='background:#0e0e0e;border:1px solid #1f1212;border-radius:7px;padding:1rem;margin-bottom:0.8rem;'>
                    <div style='color:#c45c5c;font-size:0.6rem;font-weight:700;letter-spacing:0.12em;margin-bottom:0.5rem;font-family:JetBrains Mono,monospace;'>⚠ MD5 — BROKEN</div>""", unsafe_allow_html=True)
                st.code(h_md5, language=None)
                st.markdown("<div style='color:#303030;font-size:0.68rem;font-family:Inter,sans-serif;'>No salt · 128-bit · Crackable in milliseconds</div></div>", unsafe_allow_html=True)
                st.markdown("""<div style='background:#0e0e0e;border:1px solid #1f1510;border-radius:7px;padding:1rem;'>
                    <div style='color:#c47a44;font-size:0.6rem;font-weight:700;letter-spacing:0.12em;margin-bottom:0.5rem;font-family:JetBrains Mono,monospace;'>⚠ SHA-1 — DEPRECATED</div>""", unsafe_allow_html=True)
                st.code(h_sha1, language=None)
                st.markdown("<div style='color:#303030;font-size:0.68rem;font-family:Inter,sans-serif;'>No salt · 160-bit · Collision attacks known</div></div>", unsafe_allow_html=True)
            with col_b:
                if st.button("🔒 Generate bcrypt & Argon2 Hashes"):
                    with st.spinner("Computing secure hashes..."):
                        t0=time.perf_counter(); h_bcrypt=hash_bcrypt(si_pwd); bcrypt_ms=(time.perf_counter()-t0)*1000
                        t0=time.perf_counter(); h_argon2=hash_argon2(si_pwd); argon2_ms=(time.perf_counter()-t0)*1000
                    st.session_state["si_bcrypt"]=(h_bcrypt,bcrypt_ms)
                    st.session_state["si_argon2"]=(h_argon2,argon2_ms)
                if "si_bcrypt" in st.session_state:
                    h_b,ms_b=st.session_state["si_bcrypt"]
                    st.markdown(f"""<div style='background:#0e0e0e;border:1px solid #121f15;border-radius:7px;padding:1rem;margin-bottom:0.8rem;'>
                        <div style='color:#4aaa7a;font-size:0.6rem;font-weight:700;letter-spacing:0.12em;margin-bottom:0.5rem;font-family:JetBrains Mono,monospace;'>✓ BCRYPT ({ms_b:.0f} ms)</div>""", unsafe_allow_html=True)
                    st.code(h_b, language=None)
                    st.markdown("<div style='color:#303030;font-size:0.68rem;font-family:Inter,sans-serif;'>Built-in salt · Adaptive cost · Attacker-hostile</div></div>", unsafe_allow_html=True)
                if "si_argon2" in st.session_state:
                    h_a,ms_a=st.session_state["si_argon2"]
                    st.markdown(f"""<div style='background:#0e0e0e;border:1px solid #1f1a12;border-radius:7px;padding:1rem;'>
                        <div style='color:#c9a84c;font-size:0.6rem;font-weight:700;letter-spacing:0.12em;margin-bottom:0.5rem;font-family:JetBrains Mono,monospace;'>✓ ARGON2 ({ms_a:.0f} ms)</div>""", unsafe_allow_html=True)
                    st.code(h_a, language=None)
                    st.markdown("<div style='color:#303030;font-size:0.68rem;font-family:Inter,sans-serif;'>Memory-hard · PHC winner · GPU-resistant</div></div>", unsafe_allow_html=True)

        with t_ai:
            section("AI MODEL — DEEP FEATURE ANALYSIS")
            ai_feats = extract_features(si_pwd); ai_feat_dict = ai_feats.iloc[0].to_dict()
            a1, a2, a3 = st.columns(3)
            a1.metric("Weak Probability", f"{ai_prob:.1%}")
            a2.metric("Strong Probability", f"{1-ai_prob:.1%}")
            a3.metric("AI Verdict", "⚠ WEAK" if ai_prob > 0.5 else "✓ STRONG")
            st.progress(float(ai_prob))
            section("ALL 21 EXTRACTED FEATURES")
            items = list(ai_feat_dict.items())
            r1c,r2c,r3c = st.columns(3)
            for i,(k,v) in enumerate(items):
                [r1c,r2c,r3c][i%3].metric(k.replace("_"," ").title(), round(float(v),3))

        with t_policy:
            section("MULTI-RULE POLICY COMPLIANCE")
            rules = [
                ("Minimum 8 characters", len(si_pwd)>=8, f"Length: {len(si_pwd)}"),
                ("Contains uppercase (A–Z)", has_upper, "✓ Found" if has_upper else "✗ Missing"),
                ("Contains lowercase (a–z)", has_lower, "✓ Found" if has_lower else "✗ Missing"),
                ("Contains digit (0–9)", has_digit, "✓ Found" if has_digit else "✗ Missing"),
                ("Contains special character", has_special, "✓ Found" if has_special else "✗ Missing"),
                ("Strong length (12+)", len(si_pwd)>=12, f"Length: {len(si_pwd)}"),
                ("No all-same characters", len(set(si_pwd))>1, "✓ Diverse" if len(set(si_pwd))>1 else "✗ Repetitive"),
                ("Entropy above 3 bits/char", ent>=3.0, f"{ent:.2f} bits/char"),
            ]
            passed_count = sum(1 for _,p,_ in rules if p)
            compliance_pct = passed_count/len(rules)*100
            comp_color = "#4aaa7a" if compliance_pct>=75 else "#c47a44" if compliance_pct>=50 else "#c45c5c"
            st.markdown(f"""
            <div style='background:#0e0e0e;border:1px solid #1f1f1f;border-radius:7px;padding:1rem;margin-bottom:1rem;display:flex;justify-content:space-between;align-items:center;'>
                <span style='color:#555555;font-size:0.82rem;font-family:Inter,sans-serif;'>Compliance Score</span>
                <span style='color:{comp_color};font-size:1.2rem;font-weight:400;font-family:Playfair Display,Georgia,serif;'>{passed_count}/{len(rules)} <span style='font-size:0.78rem;color:#484848;'>({compliance_pct:.0f}%)</span></span>
            </div>""", unsafe_allow_html=True)
            for rule, passed, detail in rules:
                col_r = "#4aaa7a" if passed else "#c45c5c"
                bg_r  = "#0a150e" if passed else "#150a0a"
                bd_r  = "#152a1a" if passed else "#2a1515"
                st.markdown(f"""
                <div style='display:flex;align-items:center;justify-content:space-between;
                     padding:0.52rem 1rem;border-radius:6px;margin-bottom:0.3rem;
                     background:{bg_r};border:1px solid {bd_r};'>
                    <span style='color:{col_r};font-size:0.78rem;font-family:Inter,sans-serif;'>{"✓" if passed else "✗"}&nbsp; {rule}</span>
                    <span style='color:#303030;font-size:0.7rem;font-family:JetBrains Mono,monospace;'>{detail}</span>
                </div>""", unsafe_allow_html=True)

        with t_compose:
            section("CHARACTER COMPOSITION")
            digits  = sum(c.isdigit() for c in si_pwd)
            lowers  = sum(c.islower() for c in si_pwd)
            uppers  = sum(c.isupper() for c in si_pwd)
            specials= sum(c in _string.punctuation for c in si_pwd)
            total   = len(si_pwd)

            fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4))
            fig.patch.set_facecolor("#070707")
            categories=["Lowercase","Uppercase","Digits","Special"]
            counts=[lowers,uppers,digits,specials]
            colors_bar=["#c8a84b","#8066cc","#c47a44","#4aaa7a"]
            bars=ax1.bar(categories, counts, color=colors_bar, edgecolor='#1e1a10', width=0.5)
            for bar,v in zip(bars,counts):
                if v>0: ax1.text(bar.get_x()+bar.get_width()/2, bar.get_height()+0.05, str(v), ha='center', color='#f0e8d5', fontsize=11)
            style_axes(ax1,"Character Type Count"); ax1.set_ylabel("Count",color="#383838")

            nonzero_vals=[v for v in counts if v>0]
            nonzero_labels=[f"{categories[i]}\n{counts[i]} ({counts[i]/total*100:.0f}%)" for i,v in enumerate(counts) if v>0]
            nonzero_colors=[colors_bar[i] for i,v in enumerate(counts) if v>0]
            if nonzero_vals:
                wedges,texts,_=ax2.pie(nonzero_vals,labels=nonzero_labels,colors=nonzero_colors,autopct='',startangle=90,wedgeprops={"edgecolor":"#070707","linewidth":2})
                for t in texts: t.set_color("#555"); t.set_fontsize(8)
            ax2.set_facecolor("#070707"); style_axes(ax2,"Composition Distribution")
            plt.tight_layout()
            st.image(make_chart(fig), width='stretch')

            sc1,sc2,sc3,sc4=st.columns(4)
            sc1.metric("Lowercase",f"{lowers} ({lowers/total*100:.0f}%)")
            sc2.metric("Uppercase",f"{uppers} ({uppers/total*100:.0f}%)")
            sc3.metric("Digits",f"{digits} ({digits/total*100:.0f}%)")
            sc4.metric("Special",f"{specials} ({specials/total*100:.0f}%)")
    else:
        st.markdown("""
        <div style='background:#0e0e0e;border:1px dashed #1f1f1f;border-radius:10px;
             padding:3.5rem;text-align:center;margin-top:1rem;'>
            <div style='font-size:2rem;margin-bottom:1rem;'>🔍</div>
            <div style='color:#c9a84c;font-size:0.95rem;font-weight:400;font-family:Playfair Display,Georgia,serif;font-style:italic;'>Awaiting Input</div>
            <div style='color:#303030;font-size:0.76rem;margin-top:0.5rem;font-family:Inter,sans-serif;'>
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
    <div style='background:#0e0e0e;border:1px solid #1f1f1f;border-radius:10px;
         padding:2.8rem;margin-bottom:1.5rem;text-align:center;'>
        <div style='font-size:1.8rem;margin-bottom:0.7rem;'>🔐</div>
        <div style='color:#c9a84c;font-size:1.4rem;font-weight:400;font-style:italic;font-family:Playfair Display,Georgia,serif;'>CryptLab</div>
        <div style='color:#2a2a2a;font-size:0.58rem;letter-spacing:0.18em;margin-top:0.5rem;text-transform:uppercase;font-family:Inter,sans-serif;'>
            Cryptanalysis of Weak Password Hashing Systems and AI-Based Defence Mechanism
        </div>
        <div style='height:1px;background:#1a1a1a;margin:1.5rem auto;max-width:280px;'></div>
        <div style='color:#555555;font-size:0.84rem;line-height:2;max-width:600px;margin:0 auto;font-family:Inter,sans-serif;'>
            A university-level research project investigating cryptographic vulnerabilities in legacy
            password hashing algorithms, performing systematic attack simulations, and designing
            an AI-augmented defence architecture using modern memory-hard hashing and machine learning.
        </div>
    </div>
    """, unsafe_allow_html=True)

    section("DEVELOPED BY")
    team = [
        ("👩‍💻", "Amina Noor",    "Full Stack Developer",    "Module I — Hash Lab & Attack Simulation",        "#c47a44"),
        ("👩‍🎨", "Hamail Fatima", "UI/UX Designer",          "Module II — Cryptanalysis & AI Analysis",        "#8066cc"),
        ("👩‍🔬", "Hajra Sarwar",  "Full Stack AI Developer", "Module III — Defence Architecture & Validation", "#4aaa7a"),
    ]
    t1, t2, t3 = st.columns(3)
    for col, (icon, name, title, module, color) in zip([t1,t2,t3], team):
        with col:
            st.markdown(f"""
            <div style='background:#0e0e0e;border:1px solid #1f1f1f;border-top:2px solid {color};
                 border-radius:9px;padding:1.8rem 1.5rem;text-align:center;'>
                <div style='font-size:1.8rem;margin-bottom:0.8rem;'>{icon}</div>
                <div style='color:#efefef;font-size:1rem;font-weight:400;font-family:Playfair Display,Georgia,serif;font-style:italic;'>{name}</div>
                <div style='color:{color};font-size:0.58rem;font-weight:700;letter-spacing:0.14em;
                     margin:0.5rem 0;text-transform:uppercase;font-family:Inter,sans-serif;'>{title}</div>
                <div style='height:1px;background:#1a1a1a;margin:0.8rem 0;'></div>
                <div style='color:#484848;font-size:0.72rem;line-height:1.8;font-family:Inter,sans-serif;'>{module}</div>
            </div>
            """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    section("PROJECT DETAILS")
    d1, d2 = st.columns(2)
    with d1:
        st.markdown("""
        <div style='background:#0e0e0e;border:1px solid #1f1f1f;border-radius:9px;padding:1.5rem;'>
            <div style='color:#c9a84c;font-size:0.58rem;font-weight:700;letter-spacing:0.18em;margin-bottom:1rem;text-transform:uppercase;font-family:Inter,sans-serif;'>SCOPE & OBJECTIVES</div>
            <ul style='color:#484848;font-size:0.78rem;line-height:2.2;margin:0;padding-left:1.1rem;font-family:Inter,sans-serif;'>
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
        <div style='background:#0e0e0e;border:1px solid #1f1f1f;border-radius:9px;padding:1.5rem;'>
            <div style='color:#c9a84c;font-size:0.58rem;font-weight:700;letter-spacing:0.18em;margin-bottom:1rem;text-transform:uppercase;font-family:Inter,sans-serif;'>TECHNOLOGY STACK</div>
            <table style='width:100%;border-collapse:collapse;font-size:0.77rem;font-family:Inter,sans-serif;'>
                <tr style='border-bottom:1px solid #151515;'><td style='color:#c9a84c;padding:0.45rem 0;font-family:JetBrains Mono,monospace;'>Python 3.12</td><td style='color:#484848;padding:0.45rem 0;'>Core language</td></tr>
                <tr style='border-bottom:1px solid #151515;'><td style='color:#c9a84c;padding:0.45rem 0;font-family:JetBrains Mono,monospace;'>hashlib</td><td style='color:#484848;padding:0.45rem 0;'>MD5 / SHA-1 primitives</td></tr>
                <tr style='border-bottom:1px solid #151515;'><td style='color:#c9a84c;padding:0.45rem 0;font-family:JetBrains Mono,monospace;'>bcrypt / Argon2</td><td style='color:#484848;padding:0.45rem 0;'>Memory-hard secure hashing</td></tr>
                <tr style='border-bottom:1px solid #151515;'><td style='color:#c9a84c;padding:0.45rem 0;font-family:JetBrains Mono,monospace;'>scikit-learn</td><td style='color:#484848;padding:0.45rem 0;'>Random Forest ML model</td></tr>
                <tr style='border-bottom:1px solid #151515;'><td style='color:#c9a84c;padding:0.45rem 0;font-family:JetBrains Mono,monospace;'>Streamlit</td><td style='color:#484848;padding:0.45rem 0;'>Interactive web interface</td></tr>
                <tr><td style='color:#c9a84c;padding:0.45rem 0;font-family:JetBrains Mono,monospace;'>ReportLab</td><td style='color:#484848;padding:0.45rem 0;'>PDF academic report export</td></tr>
            </table>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("""
    <div style='background:#0e0e0e;border:1px solid #1f1f1f;border-radius:7px;padding:1rem 1.5rem;text-align:center;'>
        <span style='color:#2a2a2a;font-size:0.65rem;letter-spacing:0.14em;font-family:JetBrains Mono,monospace;'>
        CRYPTANALYSIS OF WEAK PASSWORD HASHING SYSTEMS AND AI-BASED DEFENCE MECHANISM · UNIVERSITY PROJECT · 2026–2027
        </span>
    </div>
    """, unsafe_allow_html=True)


# ─────────────────────────────────────────
# FOOTER
# ─────────────────────────────────────────
st.markdown("---")
st.markdown("""
<div style='text-align:center;padding:0.6rem;'>
    <span style='color:#2a2a2a;font-size:0.62rem;letter-spacing:0.14em;font-family:JetBrains Mono,monospace;'>
    CRYPTANALYSIS OF WEAK PASSWORD HASHING SYSTEMS AND AI-BASED DEFENCE MECHANISM
    </span>
</div>
""", unsafe_allow_html=True)
