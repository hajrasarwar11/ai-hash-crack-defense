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

# ═══════════════════════════════════════════════════════════════
# DESIGN SYSTEM — Luxury Cyber Intelligence · Obsidian + Gold
# ═══════════════════════════════════════════════════════════════
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=Playfair+Display:ital,wght@0,400;0,500;0,600;1,400;1,500&family=JetBrains+Mono:wght@300;400;500&display=swap');

/* ── DESIGN TOKENS ────────────────────────────────────────── */
:root {
    /* Backgrounds — Obsidian depth stack */
    --bg:        #0C0B14;
    --bg2:       #11101A;
    --bg3:       #161524;
    --bg4:       #1C1B2E;
    --bg5:       #222138;

    /* Borders */
    --border:    #1C1B2E;
    --border2:   #232240;
    --border3:   #2E2C50;
    --border-gold: rgba(212,175,55,0.25);

    /* Gold system — Burnished luxury */
    --gold:      #D4AF37;
    --gold2:     #F0CF6A;
    --gold3:     #EEC84A;
    --gold-dim:  #8A6E1A;
    --gold-glow: rgba(212,175,55,0.08);
    --gold-glow2:rgba(212,175,55,0.15);

    /* Accent palette */
    --copper:    #B87333;
    --copper2:   #D4915A;
    --crimson:   #8B2635;
    --crimson2:  #C03050;
    --amber:     #D4922A;
    --amber2:    #F0AE4A;
    --plum:      #2E1A3C;
    --plum2:     #3D2450;

    /* Text */
    --text:      #EDE9E0;
    --text-mid:  #8A8478;
    --text-dim:  #4A4540;
    --text-faint:#282520;

    /* Functional */
    --red:       #C05555;
    --green:     #4AAA7A;
    --purple:    #7A5CC0;
    --teal:      #3A9A8A;

    /* Typography */
    --font:      'Inter', system-ui, sans-serif;
    --mono:      'JetBrains Mono', monospace;
    --display:   'Playfair Display', Georgia, serif;

    /* Motion */
    --ease:      cubic-bezier(0.22, 1, 0.36, 1);
    --ease-in:   cubic-bezier(0.4, 0, 1, 1);
}

/* ── RESET ───────────────────────────────────────────────── */
*, *::before, *::after { box-sizing: border-box; margin: 0; }

html, body, [class*='css'] {
    font-family: var(--font) !important;
    -webkit-font-smoothing: antialiased !important;
    -moz-osx-font-smoothing: grayscale !important;
    background-color: var(--bg) !important;
    color: var(--text);
}

/* ── HIDE STREAMLIT ARTIFACTS ───────────────────────────── */
/* ── SIDEBAR TOGGLE BUTTONS — << / >> ──────────────────── */
/* Collapse button inside sidebar (click to hide sidebar) */
section[data-testid='stSidebar'] button[data-testid='baseButton-header'],
section[data-testid='stSidebar'] [data-testid='stSidebarCollapseButton'] button {
    background: transparent !important;
    border: 1px solid #2E2C50 !important;
    border-radius: 6px !important;
    width: 28px !important; height: 28px !important;
    min-width: 28px !important;
    display: flex !important; align-items: center !important;
    justify-content: center !important;
    cursor: pointer !important;
    transition: all 0.15s ease !important;
    padding: 0 !important;
}
section[data-testid='stSidebar'] button[data-testid='baseButton-header']:hover,
section[data-testid='stSidebar'] [data-testid='stSidebarCollapseButton'] button:hover {
    border-color: #D4AF37 !important;
    background: rgba(212,175,55,0.07) !important;
}
section[data-testid='stSidebar'] button[data-testid='baseButton-header'] span,
section[data-testid='stSidebar'] [data-testid='stSidebarCollapseButton'] button span,
section[data-testid='stSidebar'] button[data-testid='baseButton-header'] svg,
section[data-testid='stSidebar'] [data-testid='stSidebarCollapseButton'] svg {
    display: none !important;
}
section[data-testid='stSidebar'] button[data-testid='baseButton-header']::after,
section[data-testid='stSidebar'] [data-testid='stSidebarCollapseButton'] button::after {
    content: '«' !important;
    font-size: 0.85rem !important; font-weight: 700 !important;
    color: #4A4540 !important; font-family: Inter, sans-serif !important;
    line-height: 1 !important;
}
section[data-testid='stSidebar'] button[data-testid='baseButton-header']:hover::after,
section[data-testid='stSidebar'] [data-testid='stSidebarCollapseButton'] button:hover::after {
    color: #D4AF37 !important;
}

/* Expand button in main area when sidebar is collapsed */
[data-testid="collapsedControl"],
button[data-testid="collapsedControl"] {
    display: flex !important; align-items: center !important;
    justify-content: center !important;
    background: transparent !important;
    border: 1px solid #2E2C50 !important;
    border-radius: 6px !important;
    width: 28px !important; height: 28px !important;
    min-width: 28px !important;
    cursor: pointer !important;
    transition: all 0.15s ease !important;
    padding: 0 !important;
}
[data-testid="collapsedControl"]:hover,
button[data-testid="collapsedControl"]:hover {
    border-color: #D4AF37 !important;
    background: rgba(212,175,55,0.07) !important;
}
[data-testid="collapsedControl"] *,
button[data-testid="collapsedControl"] * { display: none !important; }
[data-testid="collapsedControl"]::after,
button[data-testid="collapsedControl"]::after {
    content: '»' !important;
    font-size: 0.85rem !important; font-weight: 700 !important;
    color: #4A4540 !important; font-family: Inter, sans-serif !important;
    line-height: 1 !important; display: block !important;
}
[data-testid="collapsedControl"]:hover::after,
button[data-testid="collapsedControl"]:hover::after { color: #D4AF37 !important; }
[data-testid='stDecoration'] { display: none !important; }
#MainMenu, footer { visibility: hidden !important; }

/* ── PRESERVE INLINE COLORS ─────────────────────────────── */
[style*="color:#D4AF37"],[style*="color: #D4AF37"],[style*="color:#d4af37"] { color: #D4AF37 !important; }
[style*="color:#F0CF6A"],[style*="color: #F0CF6A"] { color: #F0CF6A !important; }
[style*="color:#EDE9E0"],[style*="color: #EDE9E0"] { color: #EDE9E0 !important; }
[style*="color:#B87333"],[style*="color: #B87333"] { color: #B87333 !important; }
[style*="color:#D4922A"],[style*="color: #D4922A"] { color: #D4922A !important; }
[style*="color:#4AAA7A"],[style*="color: #4AAA7A"] { color: #4AAA7A !important; }
[style*="color:#C05555"],[style*="color: #C05555"] { color: #C05555 !important; }
[style*="color:#7A5CC0"],[style*="color: #7A5CC0"] { color: #7A5CC0 !important; }
[style*="color:#8B2635"],[style*="color: #8B2635"] { color: #8B2635 !important; }
[style*="color:#3A9A8A"],[style*="color: #3A9A8A"] { color: #3A9A8A !important; }

/* ── STREAMLIT CHROME ───────────────────────────────────── */
header[data-testid='stHeader'],
[data-testid='stToolbar'] {
    background: var(--bg) !important;
    border-bottom: 1px solid var(--border) !important;
    height: 2.6rem !important;
}

/* ── APP BACKGROUNDS ────────────────────────────────────── */
.stApp,
[data-testid='stAppViewContainer'],
[data-testid='stAppViewBlockContainer'],
.main, .block-container {
    background-color: var(--bg) !important;
}
[data-testid='stAppViewBlockContainer'] {
    padding-top: 2.2rem !important;
    padding-left: 3rem !important;
    padding-right: 3rem !important;
    max-width: 1200px !important;
}

/* ══════════════════════════════════════════════════════════
   SIDEBAR — Premium Intelligence Platform Shell
══════════════════════════════════════════════════════════ */
section[data-testid='stSidebar'] {
    background: var(--bg2) !important;
    border-right: 1px solid var(--border2) !important;
    width: 290px !important;
    min-width: 290px !important;
}
section[data-testid='stSidebar'] > div {
    background: var(--bg2) !important;
}

/* Radio — hide dots, style as nav items */
[data-testid='stSidebar'] [data-baseweb='radio'],
[data-testid='stSidebar'] [role='radio'],
[data-testid='stSidebar'] .stRadio [data-testid='stWidgetLabel'],
[data-testid='stSidebar'] .stRadio span[data-baseweb='radio'],
[data-testid='stSidebar'] .stRadio div[role='radiogroup'] > label > div:first-child,
[data-testid='stSidebar'] input[type='radio'] { display: none !important; }

[data-testid='stSidebar'] .stRadio > div {
    gap: 0 !important;
    padding: 0 12px !important;
}
[data-testid='stSidebar'] .stRadio label {
    display: flex !important;
    align-items: center !important;
    padding: 0.55rem 0.85rem !important;
    border-radius: 8px !important;
    cursor: pointer !important;
    font-size: 0.80rem !important;
    font-weight: 400 !important;
    letter-spacing: 0.01em !important;
    white-space: nowrap !important;
    overflow: hidden !important;
    text-overflow: clip !important;
    color: var(--text-dim) !important;
    border-left: 2px solid transparent !important;
    transition: all 0.15s var(--ease) !important;
    margin-bottom: 1px !important;
    line-height: 1.4 !important;
    position: relative !important;
}
[data-testid='stSidebar'] .stRadio label:hover {
    background: rgba(212,175,55,0.04) !important;
    color: var(--text-mid) !important;
    border-left-color: var(--border3) !important;
    transform: translateX(1px) !important;
}
[data-testid='stSidebar'] .stRadio label[data-checked='true'],
[data-testid='stSidebar'] .stRadio [aria-checked='true'] ~ label,
[data-testid='stSidebar'] .stRadio input:checked + div {
    background: linear-gradient(90deg, rgba(212,175,55,0.10), rgba(212,175,55,0.03)) !important;
    color: var(--gold) !important;
    border-left-color: var(--gold) !important;
    font-weight: 500 !important;
}

/* ══════════════════════════════════════════════════════════
   TYPOGRAPHY SYSTEM
══════════════════════════════════════════════════════════ */
h1, h2, h3, h4 {
    font-family: var(--display) !important;
    color: var(--text) !important;
    font-weight: 400 !important;
    letter-spacing: -0.02em !important;
    line-height: 1.15 !important;
}
p, li, .stMarkdown, .stText {
    color: var(--text) !important;
    font-family: var(--font) !important;
}
span, label, div { font-family: var(--font) !important; }
.stMarkdown p {
    color: var(--text-mid) !important;
    font-size: 0.88rem !important;
    line-height: 1.9 !important;
    font-weight: 400 !important;
}

/* ══════════════════════════════════════════════════════════
   METRIC CARDS — Premium Intelligence KPI Cards
══════════════════════════════════════════════════════════ */
[data-testid='stMetric'] {
    background: linear-gradient(135deg, var(--bg3) 0%, var(--bg2) 100%) !important;
    border: 1px solid var(--border2) !important;
    border-radius: 12px !important;
    padding: 1.4rem 1.5rem 1.2rem !important;
    position: relative !important;
    overflow: hidden !important;
    transition: border-color 0.2s var(--ease), transform 0.2s var(--ease), box-shadow 0.2s var(--ease) !important;
    box-shadow: 0 0 28px rgba(212,175,55,0.06), 0 4px 16px rgba(0,0,0,0.5) !important;
    height: 100% !important;
}
[data-testid='stMetric']::before {
    content: '' !important;
    position: absolute !important;
    top: 0; left: 8%; right: 8% !important;
    height: 1px !important;
    background: linear-gradient(90deg, transparent, var(--gold-dim) 25%, var(--gold) 50%, var(--gold-dim) 75%, transparent) !important;
}
[data-testid='stMetric']::after {
    content: '' !important;
    position: absolute !important;
    inset: 0 !important;
    background: radial-gradient(ellipse at top, rgba(212,175,55,0.04) 0%, transparent 70%) !important;
    pointer-events: none !important;
}
[data-testid='stMetric']:hover {
    border-color: var(--border-gold) !important;
    transform: translateY(-3px) !important;
    box-shadow: 0 0 40px rgba(212,175,55,0.12), 0 8px 28px rgba(0,0,0,0.6) !important;
}
[data-testid='stMetric'] * { color: var(--text) !important; }
[data-testid='stMetricLabel'] {
    font-size: 0.56rem !important;
    font-weight: 700 !important;
    letter-spacing: 0.18em !important;
    text-transform: uppercase !important;
    color: var(--text-dim) !important;
    font-family: var(--font) !important;
    line-height: 1.5 !important;
}
[data-testid='stMetricValue'] {
    font-size: 2.2rem !important;
    font-weight: 400 !important;
    font-family: var(--display) !important;
    color: var(--gold2) !important;
    letter-spacing: -0.02em !important;
    line-height: 1.15 !important;
    margin: 0.25rem 0 !important;
}
[data-testid='stMetricDelta'] {
    font-size: 0.64rem !important;
    color: var(--text-dim) !important;
    font-family: var(--font) !important;
    font-weight: 400 !important;
}

/* ══════════════════════════════════════════════════════════
   CARD SYSTEM — Universal glow for custom HTML cards
══════════════════════════════════════════════════════════ */
[data-testid='stMarkdown'] div[style*="background:#11101A"][style*="border-radius"],
[data-testid='stMarkdown'] div[style*="background:#0C0B14"][style*="border-radius"],
[data-testid='stMarkdown'] div[style*="background:#161524"][style*="border-radius"],
[data-testid='stMarkdown'] div[style*="background:#1C1B2E"][style*="border-radius"] {
    box-shadow: 0 0 24px rgba(212,175,55,0.05), 0 4px 16px rgba(0,0,0,0.6) !important;
    transition: box-shadow 0.22s var(--ease), transform 0.22s var(--ease) !important;
}
[data-testid='stMarkdown'] div[style*="background:#11101A"][style*="border-radius"]:hover,
[data-testid='stMarkdown'] div[style*="background:#0C0B14"][style*="border-radius"]:hover,
[data-testid='stMarkdown'] div[style*="background:#161524"][style*="border-radius"]:hover,
[data-testid='stMarkdown'] div[style*="background:#1C1B2E"][style*="border-radius"]:hover {
    box-shadow: 0 0 42px rgba(212,175,55,0.13), 0 8px 28px rgba(0,0,0,0.7) !important;
    transform: translateY(-2px) !important;
}

/* Equal-height column cards */
[data-testid='stHorizontalBlock'] > div {
    display: flex !important;
    flex-direction: column !important;
}
[data-testid='stHorizontalBlock'] > div [data-testid='stVerticalBlock'],
[data-testid='stHorizontalBlock'] > div [data-testid='stMarkdown'] {
    flex: 1 !important;
    display: flex !important;
    flex-direction: column !important;
}
[data-testid='stHorizontalBlock'] > div [data-testid='stMarkdown'] > div {
    flex: 1 !important;
}

/* ══════════════════════════════════════════════════════════
   BUTTONS
══════════════════════════════════════════════════════════ */
.stButton > button {
    background: transparent !important;
    color: var(--gold) !important;
    border: 1px solid var(--border3) !important;
    border-radius: 8px !important;
    font-family: var(--font) !important;
    font-size: 0.72rem !important;
    font-weight: 600 !important;
    letter-spacing: 0.08em !important;
    text-transform: uppercase !important;
    padding: 0.65rem 1.4rem !important;
    width: 100% !important;
    transition: all 0.18s var(--ease) !important;
    position: relative !important;
    overflow: hidden !important;
}
.stButton > button::before {
    content: '' !important;
    position: absolute !important;
    inset: 0 !important;
    background: linear-gradient(90deg, transparent, rgba(212,175,55,0.06), transparent) !important;
    transform: translateX(-100%) !important;
    transition: transform 0.4s var(--ease) !important;
}
.stButton > button:hover {
    border-color: var(--gold) !important;
    background: linear-gradient(135deg, rgba(212,175,55,0.10), rgba(184,115,51,0.06)) !important;
    color: var(--gold2) !important;
    box-shadow: 0 0 20px rgba(212,175,55,0.18), 0 4px 12px rgba(0,0,0,0.4) !important;
    transform: translateY(-1px) !important;
}
.stButton > button:hover::before { transform: translateX(100%) !important; }
.stButton > button:active { transform: scale(0.98) translateY(0) !important; }

/* ══════════════════════════════════════════════════════════
   INPUTS & FORM CONTROLS
══════════════════════════════════════════════════════════ */
.stTextInput > div > div > input,
.stTextArea > div > div > textarea {
    background: var(--bg3) !important;
    color: var(--text) !important;
    border: 1px solid var(--border2) !important;
    border-radius: 8px !important;
    font-family: var(--font) !important;
    font-size: 0.87rem !important;
    font-weight: 400 !important;
    padding: 0.7rem 1.1rem !important;
    transition: all 0.18s var(--ease) !important;
    caret-color: var(--gold) !important;
}
.stTextInput > div > div > input::placeholder,
.stTextArea > div > div > textarea::placeholder {
    color: var(--text-dim) !important;
    font-style: italic !important;
}
.stTextInput > div > div > input:focus,
.stTextArea > div > div > textarea:focus {
    border-color: var(--gold-dim) !important;
    background: var(--bg4) !important;
    outline: none !important;
    box-shadow: 0 0 0 3px rgba(212,175,55,0.08) !important;
}

.stSelectbox > div > div {
    background: var(--bg3) !important;
    color: var(--text) !important;
    border: 1px solid var(--border2) !important;
    border-radius: 8px !important;
    font-family: var(--font) !important;
    font-size: 0.87rem !important;
    transition: border-color 0.18s !important;
}
.stSelectbox > div > div:focus-within {
    border-color: var(--gold-dim) !important;
    box-shadow: 0 0 0 3px rgba(212,175,55,0.07) !important;
}
.stSelectbox svg { fill: var(--gold) !important; }

/* ══════════════════════════════════════════════════════════
   TABS
══════════════════════════════════════════════════════════ */
.stTabs [data-baseweb='tab-list'] {
    background: transparent !important;
    border-bottom: 1px solid var(--border) !important;
    gap: 0 !important;
    padding: 0 !important;
}
.stTabs [data-baseweb='tab'] {
    background: transparent !important;
    color: var(--text-dim) !important;
    font-size: 0.65rem !important;
    font-weight: 600 !important;
    letter-spacing: 0.10em !important;
    text-transform: uppercase !important;
    padding: 0.82rem 1.3rem !important;
    border-bottom: 2px solid transparent !important;
    border-radius: 0 !important;
    transition: all 0.15s !important;
    font-family: var(--font) !important;
    white-space: nowrap !important;
}
.stTabs [data-baseweb='tab']:hover {
    color: var(--text-mid) !important;
    background: rgba(212,175,55,0.03) !important;
}
.stTabs [aria-selected='true'] {
    color: var(--gold) !important;
    border-bottom-color: var(--gold) !important;
    background: transparent !important;
}
.stTabs [data-baseweb='tab-panel'] { padding-top: 1.8rem !important; }

/* ══════════════════════════════════════════════════════════
   PROGRESS BARS
══════════════════════════════════════════════════════════ */
.stProgress > div > div > div {
    background: linear-gradient(90deg, var(--gold-dim), var(--gold), var(--gold2)) !important;
    border-radius: 99px !important;
}
.stProgress > div > div {
    background: var(--border2) !important;
    border-radius: 99px !important;
    height: 3px !important;
}

/* ══════════════════════════════════════════════════════════
   CODE BLOCKS
══════════════════════════════════════════════════════════ */
code, .stCode, pre {
    background: var(--bg3) !important;
    color: var(--gold2) !important;
    font-family: var(--mono) !important;
    font-size: 0.78rem !important;
    border: 1px solid var(--border2) !important;
    border-radius: 7px !important;
    line-height: 1.7 !important;
}

/* ══════════════════════════════════════════════════════════
   DATAFRAMES
══════════════════════════════════════════════════════════ */
[data-testid='stDataFrame'] {
    background: var(--bg2) !important;
    border: 1px solid var(--border) !important;
    border-radius: 10px !important;
    overflow: hidden !important;
    box-shadow: 0 4px 16px rgba(0,0,0,0.4) !important;
}

/* ══════════════════════════════════════════════════════════
   ALERTS
══════════════════════════════════════════════════════════ */
[data-testid='stAlert'] {
    border-radius: 9px !important;
    font-size: 0.84rem !important;
    font-family: var(--font) !important;
    font-weight: 400 !important;
    border-width: 1px !important;
    backdrop-filter: blur(4px) !important;
}

/* ══════════════════════════════════════════════════════════
   EXPANDERS
══════════════════════════════════════════════════════════ */
[data-testid='stExpander'] {
    background: var(--bg2) !important;
    border: 1px solid var(--border) !important;
    border-radius: 10px !important;
    transition: border-color 0.18s !important;
    box-shadow: 0 2px 8px rgba(0,0,0,0.3) !important;
}
[data-testid='stExpander']:hover { border-color: var(--border2) !important; }
[data-testid='stExpander'] summary {
    font-size: 0.87rem !important;
    font-weight: 400 !important;
    padding: 0.9rem 1.2rem !important;
    color: var(--text-mid) !important;
}
[data-testid='stExpander'] summary:hover { color: var(--gold) !important; }

/* ══════════════════════════════════════════════════════════
   SLIDERS & CHECKBOXES
══════════════════════════════════════════════════════════ */
.stSlider > div > div > div { background: var(--gold) !important; }
[data-testid='stSlider'] > div > div > div > div { background: var(--border2) !important; }
.stCheckbox > label { color: var(--text-mid) !important; font-size: 0.85rem !important; }

/* ══════════════════════════════════════════════════════════
   DIVIDERS
══════════════════════════════════════════════════════════ */
hr {
    border: none !important;
    border-top: 1px solid var(--border) !important;
    margin: 2.2rem 0 !important;
}

/* ══════════════════════════════════════════════════════════
   SCROLLBAR
══════════════════════════════════════════════════════════ */
::-webkit-scrollbar { width: 4px; height: 4px; }
::-webkit-scrollbar-track { background: var(--bg); }
::-webkit-scrollbar-thumb { background: var(--border3); border-radius: 99px; }
::-webkit-scrollbar-thumb:hover { background: var(--gold-dim); }

/* ══════════════════════════════════════════════════════════
   ANIMATIONS
══════════════════════════════════════════════════════════ */
@keyframes fadeUp {
    from { opacity: 0; transform: translateY(10px); }
    to   { opacity: 1; transform: translateY(0); }
}
@keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
@keyframes shimmer {
    0%   { background-position: -200% center; }
    100% { background-position: 200% center; }
}
@keyframes pulseGold {
    0%, 100% { opacity: 0.6; }
    50%       { opacity: 1; }
}

.main .block-container { animation: fadeUp 0.35s var(--ease) both !important; }
section[data-testid='stSidebar'] { animation: fadeIn 0.3s ease both !important; }

/* ══════════════════════════════════════════════════════════
   SELECTION
══════════════════════════════════════════════════════════ */
::selection { background: rgba(212,175,55,0.20); color: var(--text); }
</style>
""", unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════
# HELPER FUNCTIONS — Design System Components
# ═══════════════════════════════════════════════════════════════

def page_header(title, subtitle=""):
    parts = title.split("&", 1)
    main  = parts[0].strip()
    rest  = ("& " + parts[1].strip()) if len(parts) > 1 else ""

    sub_html = ""
    if subtitle:
        sub_html = (
            f"<div style='font-size:0.57rem;font-weight:700;color:#D4AF37;"
            f"letter-spacing:0.22em;text-transform:uppercase;"
            f"margin-bottom:1.1rem;font-family:Inter,sans-serif;"
            f"display:flex;align-items:center;gap:0.6rem;'>"
            f"<span style='display:inline-block;width:20px;height:1px;background:#D4AF37;opacity:0.5;'></span>"
            f"{subtitle}"
            f"<span style='display:inline-block;width:20px;height:1px;background:#D4AF37;opacity:0.5;'></span>"
            f"</div>"
        )

    gold_html = ""
    if rest:
        gold_html = (
            f"<div style='font-size:2.9rem;font-weight:400;line-height:1.08;"
            f"letter-spacing:-0.025em;color:#D4AF37;font-style:italic;"
            f"font-family:Playfair Display,Georgia,serif;"
            f"text-shadow:0 0 40px rgba(212,175,55,0.3);'>"
            f"{rest}</div>"
        )

    main_html = (
        f"<div style='font-size:2.9rem;font-weight:400;line-height:1.08;"
        f"letter-spacing:-0.025em;color:#EDE9E0;"
        f"font-family:Playfair Display,Georgia,serif;'>"
        f"{main}</div>"
    )

    st.markdown(
        f"<div style='padding:2.5rem 0 2rem;border-bottom:1px solid #1C1B2E;"
        f"margin-bottom:2rem;'>"
        f"{sub_html}{main_html}{gold_html}"
        f"</div>",
        unsafe_allow_html=True
    )


def section(text, accent_color="#D4AF37"):
    st.markdown(
        f"<div style='display:flex;align-items:center;gap:0.75rem;"
        f"margin:2.2rem 0 1.2rem;'>"
        f"<div style='width:3px;height:14px;background:{accent_color};"
        f"border-radius:2px;flex-shrink:0;'></div>"
        f"<div style='font-size:0.56rem;font-weight:700;letter-spacing:0.2em;"
        f"text-transform:uppercase;color:{accent_color};"
        f"font-family:Inter,sans-serif;'>{text}</div>"
        f"<div style='flex:1;height:1px;background:linear-gradient(90deg,#1C1B2E,transparent);'></div>"
        f"</div>",
        unsafe_allow_html=True
    )


def make_chart(fig):
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=140, bbox_inches="tight",
                facecolor='#0C0B14', edgecolor="none")
    plt.close(fig)
    buf.seek(0)
    return buf


def style_axes(ax, title=""):
    ax.set_facecolor('#111020')
    ax.tick_params(colors='#3A3850', labelsize=8)
    for spine in ax.spines.values():
        spine.set_edgecolor('#1C1B2E')
    if title:
        ax.set_title(title, color='#6A6050', fontsize=9,
                     fontweight="normal", pad=12)
    ax.xaxis.label.set_color('#3A3850')
    ax.yaxis.label.set_color('#3A3850')
    ax.figure.patch.set_facecolor('#0C0B14')


def status_badge(text, color="#D4AF37", bg=None):
    if bg is None:
        bg = color + "18"
    return (
        f"<span style='display:inline-flex;align-items:center;gap:0.3rem;"
        f"padding:0.22rem 0.7rem;border-radius:99px;background:{bg};"
        f"border:1px solid {color}30;font-size:0.6rem;font-weight:600;"
        f"letter-spacing:0.1em;text-transform:uppercase;color:{color};"
        f"font-family:Inter,sans-serif;'>"
        f"<span style='width:5px;height:5px;background:{color};border-radius:50%;display:inline-block;'></span>"
        f"{text}</span>"
    )


def info_card(label, value, sub="", color="#D4AF37", border_pos="top"):
    border_css = f"border-{border_pos}:2px solid {color}"
    return f"""
    <div style='background:#11101A;{border_css};border:1px solid #1C1B2E;{border_css};
         border-radius:10px;padding:1.4rem;height:100%;
         box-shadow:0 0 24px rgba(212,175,55,0.05),0 4px 16px rgba(0,0,0,0.5);
         transition:all 0.2s ease;'>
        <div style='color:{color};font-size:0.56rem;font-weight:700;letter-spacing:0.18em;
             text-transform:uppercase;margin-bottom:0.7rem;font-family:Inter,sans-serif;'>{label}</div>
        <div style='color:#EDE9E0;font-size:1.8rem;font-weight:400;
             font-family:Playfair Display,Georgia,serif;line-height:1.1;
             margin-bottom:0.4rem;'>{value}</div>
        <div style='color:#4A4540;font-size:0.7rem;font-family:Inter,sans-serif;line-height:1.6;'>{sub}</div>
    </div>"""


# ═══════════════════════════════════════════════════════════════
# SIDEBAR — Premium Intelligence Platform Navigation
# ═══════════════════════════════════════════════════════════════
with st.sidebar:
    st.markdown(
        "<div style='padding:2rem 0.8rem 1.4rem 1.1rem;'>"
        # Logo block
        "<div style='display:flex;align-items:center;gap:0.75rem;margin-bottom:0.5rem;'>"
        "<div style='width:32px;height:32px;background:linear-gradient(135deg,#D4AF37,#B87333);"
        "border-radius:8px;display:flex;align-items:center;justify-content:center;"
        "font-size:0.95rem;box-shadow:0 0 16px rgba(212,175,55,0.3);flex-shrink:0;'>🔐</div>"
        "<div>"
        "<div style='font-size:0.85rem;font-weight:700;color:#D4AF37;"
        "letter-spacing:0.16em;font-family:Inter,sans-serif;line-height:1;'>CRYPTLAB</div>"
        "<div style='font-size:0.45rem;color:#4A4540;letter-spacing:0.18em;"
        "text-transform:uppercase;font-family:Inter,sans-serif;margin-top:0.15rem;'>Intelligence Platform</div>"
        "</div>"
        "</div>"
        # Subtle divider
        "<div style='height:1px;background:linear-gradient(90deg,transparent,#1C1B2E 30%,#2E2C50 50%,#1C1B2E 70%,transparent);"
        "margin:0.9rem 0 0.3rem;'></div>"
        "</div>",
        unsafe_allow_html=True
    )

    # Navigation label
    st.markdown(
        "<div style='font-size:0.48rem;color:#2E2C50;letter-spacing:0.2em;"
        "text-transform:uppercase;font-family:Inter,sans-serif;padding:0 1.35rem;"
        "margin-bottom:0.4rem;'>Navigation</div>",
        unsafe_allow_html=True
    )

    page = st.radio("Navigation", [
        "🏠 Overview",
        "⚙️ Hash Lab",
        "⚔️ Attack Simulation",
        "🔬 Cryptanalysis",
        "🛡️ Defence System",
        "📊 Validation Metrics",
        "🔍 Security Intelligence",
        "👥 About",
    ], label_visibility="collapsed")

    st.markdown(
        "<div style='height:1px;background:linear-gradient(90deg,transparent,#1C1B2E 30%,#1C1B2E 70%,transparent);"
        "margin:1.4rem 0 1rem;'></div>"
        "<div style='font-size:0.48rem;color:#2A2840;letter-spacing:0.14em;"
        "text-transform:uppercase;margin-bottom:0.5rem;padding:0 1.1rem;"
        "font-family:Inter,sans-serif;'>Project</div>"
        "<div style='font-size:0.68rem;color:#3A3850;line-height:1.8;"
        "padding:0 1.1rem;font-family:Inter,sans-serif;'>"
        "Cryptanalysis of Weak Password Hashing Systems and AI-Based Defence Mechanism"
        "</div>"
        "<div style='height:1px;background:linear-gradient(90deg,transparent,#1C1B2E 30%,#1C1B2E 70%,transparent);"
        "margin:1rem 0 0.7rem;'></div>"
        "<div style='font-size:0.55rem;color:#252340;padding:0 1.1rem;"
        "font-family:JetBrains Mono,monospace;'>Python · hashlib · bcrypt · argon2</div>",
        unsafe_allow_html=True
    )


# ══════════════════════════════════════════════════════════════
# PAGE: OVERVIEW
# ══════════════════════════════════════════════════════════════
if "Overview" in page:
    # Inject page-specific class overrides for inline colors
    st.markdown("""
    <style>
    .ov-label { color: #D4AF37 !important; }
    .ov-title { color: #EDE9E0 !important; }
    .ov-gold  { color: #D4AF37 !important; font-weight:500 !important; }
    .ov-desc  { color: #5A5450 !important; }
    </style>
    <div style='padding:2.5rem 0 2rem;border-bottom:1px solid #1C1B2E;margin-bottom:2rem;'>
      <div class='ov-label' style='font-size:0.57rem;font-weight:700;letter-spacing:0.22em;
           text-transform:uppercase;margin-bottom:1.1rem;font-family:Inter,sans-serif;
           display:flex;align-items:center;gap:0.6rem;'>
        <span style='display:inline-block;width:20px;height:1px;background:#D4AF37;opacity:0.5;'></span>
        Cryptanalysis Lab &nbsp;&middot;&nbsp; University Research Project
        <span style='display:inline-block;width:20px;height:1px;background:#D4AF37;opacity:0.5;'></span>
      </div>
      <div class='ov-title' style='font-size:2.9rem;font-weight:400;line-height:1.08;
           letter-spacing:-0.025em;margin-bottom:0.05rem;
           font-family:Playfair Display,Georgia,serif;'>
        Weak Password Hashing
      </div>
      <div class='ov-gold' style='font-size:2.9rem;font-weight:400;line-height:1.08;
           letter-spacing:-0.025em;margin-bottom:1.2rem;font-style:italic;
           font-family:Playfair Display,Georgia,serif;
           text-shadow:0 0 40px rgba(212,175,55,0.3);'>
        &amp; AI-Based Defence
      </div>
      <p class='ov-desc' style='line-height:1.95;max-width:660px;font-size:0.87rem;
           font-weight:400;margin:0;font-family:Inter,sans-serif;'>
        Investigating cryptographic vulnerabilities in legacy hashing algorithms (MD5, SHA-1),
        simulating dictionary and brute-force attacks, and building a robust
        <span class='ov-gold'>machine-learning defence system</span>
        with memory-hard hashing and AI-driven threat detection.
      </p>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("<div style='height:0.5rem;'></div>", unsafe_allow_html=True)

    # KPI Row
    kpi1, kpi2, kpi3, kpi4, kpi5 = st.columns(5)
    kpi1.metric("Hashing Algorithms", "4", "MD5 · SHA1 · bcrypt · Argon2")
    kpi2.metric("Attack Vectors", "2", "Dictionary + Brute-Force")
    kpi3.metric("ML Features", "21", "Random Forest Classifier")
    kpi4.metric("Defence Layers", "3", "Hash · Salt · Policy · AI")
    kpi5.metric("Report Pages", "10", "Full PDF Export")

    st.markdown("<div style='height:0.5rem;'></div>", unsafe_allow_html=True)
    section("RESEARCH MODULES")

    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown(f"""
        <div style='background:#11101A;border:1px solid #1C1B2E;border-top:2px solid #B87333;
             border-radius:10px;padding:1.6rem;height:100%;'>
            <div style='color:#B87333;font-size:0.55rem;font-weight:700;letter-spacing:0.2em;
                 margin-bottom:1rem;font-family:Inter,sans-serif;'>MODULE I</div>
            <div style='color:#EDE9E0;font-size:1.05rem;font-family:Playfair Display,Georgia,serif;
                 margin-bottom:0.25rem;'>Vulnerability Assessment</div>
            <div style='color:#3A3850;font-size:0.68rem;margin-bottom:1rem;font-family:Inter,sans-serif;'>
                Hash Lab · Attack Simulation</div>
            <div style='height:1px;background:linear-gradient(90deg,#1C1B2E,transparent);margin:0.8rem 0;'></div>
            <ul style='color:#4A4540;font-size:0.73rem;line-height:2.2;margin:0;
                 padding-left:1rem;font-family:Inter,sans-serif;'>
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
        st.markdown(f"""
        <div style='background:#11101A;border:1px solid #1C1B2E;border-top:2px solid #7A5CC0;
             border-radius:10px;padding:1.6rem;height:100%;'>
            <div style='color:#7A5CC0;font-size:0.55rem;font-weight:700;letter-spacing:0.2em;
                 margin-bottom:1rem;font-family:Inter,sans-serif;'>MODULE II</div>
            <div style='color:#EDE9E0;font-size:1.05rem;font-family:Playfair Display,Georgia,serif;
                 margin-bottom:0.25rem;'>Cryptanalysis &amp; AI</div>
            <div style='color:#3A3850;font-size:0.68rem;margin-bottom:1rem;font-family:Inter,sans-serif;'>
                Entropy · Patterns · ML Classifier</div>
            <div style='height:1px;background:linear-gradient(90deg,#1C1B2E,transparent);margin:0.8rem 0;'></div>
            <ul style='color:#4A4540;font-size:0.73rem;line-height:2.2;margin:0;
                 padding-left:1rem;font-family:Inter,sans-serif;'>
                <li>Shannon entropy analysis</li>
                <li>Statistical pattern recognition</li>
                <li>Random Forest ML classifier</li>
                <li>Attack priority prediction</li>
                <li>Hash computation speed comparison</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)

    with col3:
        st.markdown(f"""
        <div style='background:#11101A;border:1px solid #1C1B2E;border-top:2px solid #4AAA7A;
             border-radius:10px;padding:1.6rem;height:100%;'>
            <div style='color:#4AAA7A;font-size:0.55rem;font-weight:700;letter-spacing:0.2em;
                 margin-bottom:1rem;font-family:Inter,sans-serif;'>MODULE III</div>
            <div style='color:#EDE9E0;font-size:1.05rem;font-family:Playfair Display,Georgia,serif;
                 margin-bottom:0.25rem;'>Defence Architecture</div>
            <div style='color:#3A3850;font-size:0.68rem;margin-bottom:1rem;font-family:Inter,sans-serif;'>
                bcrypt · Argon2 · Policy · AI Guard</div>
            <div style='height:1px;background:linear-gradient(90deg,#1C1B2E,transparent);margin:0.8rem 0;'></div>
            <ul style='color:#4A4540;font-size:0.73rem;line-height:2.2;margin:0;
                 padding-left:1rem;font-family:Inter,sans-serif;'>
                <li>bcrypt &amp; Argon2 secure hashing</li>
                <li>Automatic salting &amp; key stretching</li>
                <li>Multi-rule password policy engine</li>
                <li>AI-based weak password detection</li>
                <li>Quantified security improvements</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<div style='height:0.5rem;'></div>", unsafe_allow_html=True)
    section("ATTACK PIPELINE")

    st.markdown("""
    <div style='display:flex;align-items:stretch;border:1px solid #1C1B2E;border-radius:10px;
         overflow:hidden;margin:0.3rem 0 1.5rem;
         box-shadow:0 0 32px rgba(212,175,55,0.05),0 4px 16px rgba(0,0,0,0.5);'>
        <div style='flex:1;background:#11101A;padding:1.5rem 1rem;text-align:center;border-right:1px solid #1A1928;'>
            <div style='font-size:1.4rem;margin-bottom:0.7rem;'>🗂️</div>
            <div style='color:#B87333;font-size:0.52rem;font-weight:700;letter-spacing:0.2em;font-family:Inter,sans-serif;'>STEP 1</div>
            <div style='color:#EDE9E0;font-size:0.78rem;font-weight:600;margin-top:0.45rem;font-family:Inter,sans-serif;'>Dataset</div>
            <div style='color:#3A3850;font-size:0.64rem;margin-top:0.2rem;font-family:Inter,sans-serif;'>Weak passwords + hashes</div>
        </div>
        <div style='flex:1;background:#11101A;padding:1.5rem 1rem;text-align:center;border-right:1px solid #1A1928;'>
            <div style='font-size:1.4rem;margin-bottom:0.7rem;'>⚔️</div>
            <div style='color:#C05555;font-size:0.52rem;font-weight:700;letter-spacing:0.2em;font-family:Inter,sans-serif;'>STEP 2</div>
            <div style='color:#EDE9E0;font-size:0.78rem;font-weight:600;margin-top:0.45rem;font-family:Inter,sans-serif;'>Attack</div>
            <div style='color:#3A3850;font-size:0.64rem;margin-top:0.2rem;font-family:Inter,sans-serif;'>Dictionary &amp; brute-force</div>
        </div>
        <div style='flex:1;background:#11101A;padding:1.5rem 1rem;text-align:center;border-right:1px solid #1A1928;'>
            <div style='font-size:1.4rem;margin-bottom:0.7rem;'>📊</div>
            <div style='color:#7A5CC0;font-size:0.52rem;font-weight:700;letter-spacing:0.2em;font-family:Inter,sans-serif;'>STEP 3</div>
            <div style='color:#EDE9E0;font-size:0.78rem;font-weight:600;margin-top:0.45rem;font-family:Inter,sans-serif;'>Cryptanalysis</div>
            <div style='color:#3A3850;font-size:0.64rem;margin-top:0.2rem;font-family:Inter,sans-serif;'>Entropy · ML · Timing</div>
        </div>
        <div style='flex:1;background:#11101A;padding:1.5rem 1rem;text-align:center;border-right:1px solid #1A1928;'>
            <div style='font-size:1.4rem;margin-bottom:0.7rem;'>🛡️</div>
            <div style='color:#4AAA7A;font-size:0.52rem;font-weight:700;letter-spacing:0.2em;font-family:Inter,sans-serif;'>STEP 4</div>
            <div style='color:#EDE9E0;font-size:0.78rem;font-weight:600;margin-top:0.45rem;font-family:Inter,sans-serif;'>Defence</div>
            <div style='color:#3A3850;font-size:0.64rem;margin-top:0.2rem;font-family:Inter,sans-serif;'>bcrypt · Argon2 · AI</div>
        </div>
        <div style='flex:1;background:#11101A;padding:1.5rem 1rem;text-align:center;'>
            <div style='font-size:1.4rem;margin-bottom:0.7rem;'>✅</div>
            <div style='color:#D4AF37;font-size:0.52rem;font-weight:700;letter-spacing:0.2em;font-family:Inter,sans-serif;'>STEP 5</div>
            <div style='color:#EDE9E0;font-size:0.78rem;font-weight:600;margin-top:0.45rem;font-family:Inter,sans-serif;'>Validation</div>
            <div style='color:#3A3850;font-size:0.64rem;margin-top:0.2rem;font-family:Inter,sans-serif;'>Quantify improvement</div>
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
            <div style='background:#11101A;border:1px solid #1C1B2E;border-radius:9px;
                 padding:1rem;margin-bottom:0.7rem;
                 box-shadow:0 2px 10px rgba(0,0,0,0.4);'>
                <div style='color:#D4AF37;font-weight:600;font-size:0.77rem;margin-bottom:0.3rem;
                     font-family:JetBrains Mono,monospace;'>{tool}</div>
                <div style='color:#4A4540;font-size:0.67rem;font-family:Inter,sans-serif;
                     line-height:1.5;'>{desc}</div>
            </div>""", unsafe_allow_html=True)

    st.markdown("<div style='height:0.5rem;'></div>", unsafe_allow_html=True)
    section("KEY FINDINGS")

    fc1, fc2, fc3, fc4 = st.columns(4)
    findings = [
        (fc1, "10⁸", "MD5 hashes/second", "attacker can compute", "#C05555", "#1A1014"),
        (fc2, "~100%", "Dictionary attack success", "on weak passwords", "#B87333", "#1A1510"),
        (fc3, "10,000×", "bcrypt slower than MD5", "dramatically safer", "#4AAA7A", "#0E1A14"),
        (fc4, "21", "ML model features", "Random Forest classifier", "#D4AF37", "#1A1810"),
    ]
    for col, val, lab1, lab2, color, bg in findings:
        with col:
            st.markdown(f"""
            <div style='background:{bg};border:1px solid {color}18;border-radius:10px;
                 padding:1.4rem;text-align:center;
                 box-shadow:0 0 24px {color}08,0 4px 16px rgba(0,0,0,0.5);'>
                <div style='color:{color};font-size:2.1rem;font-weight:400;
                     font-family:Playfair Display,Georgia,serif;
                     text-shadow:0 0 20px {color}40;'>{val}</div>
                <div style='color:#6A6060;font-size:0.70rem;margin-top:0.35rem;
                     font-family:Inter,sans-serif;'>{lab1}</div>
                <div style='color:#4A4540;font-size:0.63rem;font-family:Inter,sans-serif;'>{lab2}</div>
            </div>""", unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════
# PAGE: HASH LAB
# ══════════════════════════════════════════════════════════════
elif "Hash Lab" in page:
    page_header("Hash Lab", "Weak Hashing  ·  MD5 & SHA-1 Vulnerability Demonstration")

    tab1, tab2, tab3 = st.tabs(["HASH A PASSWORD", "GENERATE DATASET", "VULNERABILITY DEMO"])

    with tab1:
        section("Live MD5 / SHA-1 Hashing")
        st.markdown("""
        <div style='background:#1A0E0E;border:1px solid #C0555520;border-left:3px solid #C05555;
             border-radius:0 9px 9px 0;padding:0.9rem 1.3rem;margin-bottom:1.2rem;font-family:Inter,sans-serif;'>
            <span style='color:#6A4A4A;font-size:0.82rem;line-height:1.8;'>
            MD5 and SHA-1 are <b style='color:#C05555;'>cryptographically broken</b> — used here only to
            demonstrate why weak passwords are trivially cracked.
            </span>
        </div>""", unsafe_allow_html=True)

        inp_col, algo_col = st.columns([3, 1])
        with inp_col:
            pwd_input = st.text_input("Password input", placeholder="Enter any password to hash...", label_visibility="collapsed")
        with algo_col:
            algo = st.selectbox("Algorithm", ["md5", "sha1", "both"], label_visibility="collapsed")

        if pwd_input:
            st.markdown("<div style='height:0.5rem;'></div>", unsafe_allow_html=True)
            section("Hash Output")
            if algo in ("md5", "both"):
                h = hash_md5(pwd_input)
                c1, c2 = st.columns([1, 3])
                c1.markdown("<div style='color:#B87333;font-weight:700;padding-top:0.5rem;font-size:0.75rem;font-family:JetBrains Mono,monospace;'>MD5</div>", unsafe_allow_html=True)
                c2.code(h, language=None)
            if algo in ("sha1", "both"):
                h = hash_sha1(pwd_input)
                c1, c2 = st.columns([1, 3])
                c1.markdown("<div style='color:#7A5CC0;font-weight:700;padding-top:0.5rem;font-size:0.75rem;font-family:JetBrains Mono,monospace;'>SHA-1</div>", unsafe_allow_html=True)
                c2.code(h, language=None)

            st.markdown("---")
            section("Why This Is Dangerous", "#C05555")
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

        st.markdown("<div style='height:0.5rem;'></div>", unsafe_allow_html=True)
        section("Hash Speed — Why MD5/SHA1 Are Dangerous", "#C05555")
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


# ══════════════════════════════════════════════════════════════
# PAGE: ATTACK SIMULATION
# ══════════════════════════════════════════════════════════════
elif "Attack Simulation" in page:
    page_header("Attack Simulation", "Dictionary & Brute-Force  ·  Active Attack Demonstration")

    pwd_path  = DATA_DIR / "passwords.txt"
    dict_path = DATA_DIR / "dictionary.txt"

    if not pwd_path.exists():
        st.markdown("""
        <div style='background:#1A1510;border:1px solid #B8733330;border-left:3px solid #B87333;
             border-radius:0 9px 9px 0;padding:1rem 1.4rem;font-family:Inter,sans-serif;'>
            <span style='color:#6A5030;font-size:0.84rem;'>
            ⚠&nbsp; Dataset not found. Navigate to
            <b style='color:#B87333;'>Hash Lab → Generate Dataset</b> first.
            </span>
        </div>""", unsafe_allow_html=True)
    else:
        passwords = [l.strip() for l in pwd_path.read_text().splitlines() if l.strip()]
        tab1, tab2, tab3 = st.tabs(["DICTIONARY ATTACK", "BRUTE-FORCE ATTACK", "RESULTS & CHARTS"])

        with tab1:
            section("Dictionary Attack")
            st.markdown("""
            <div style='background:#11101A;border:1px solid #1C1B2E;border-radius:9px;
                 padding:1rem 1.3rem;margin-bottom:1.2rem;'>
                <span style='color:#5A5470;font-size:0.82rem;font-family:Inter,sans-serif;line-height:1.8;'>
                Tries every word from a pre-built wordlist against target hashes.
                <b style='color:#D4AF37;'>Extremely effective against common passwords.</b>
                </span>
            </div>""", unsafe_allow_html=True)
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
                    section("Recovered Passwords", "#C05555")
                    cracked_df = pd.DataFrame(
                        [(h[:20]+"...", p) for h, p in result["cracked"].items()],
                        columns=["Hash (truncated)", "Cracked Password"]
                    )
                    st.dataframe(cracked_df, use_container_width=True)
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
                with st.spinner("Running brute-force..."):
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
                    section("Recovered Passwords", "#C05555")
                    cracked_df = pd.DataFrame(
                        [(h[:20]+"...", p) for h, p in result["cracked"].items()],
                        columns=["Hash (truncated)", "Cracked Password"]
                    )
                    st.dataframe(cracked_df, use_container_width=True)

        with tab3:
            section("Attack Comparison Charts")
            if "dict_result" not in st.session_state and "brute_result" not in st.session_state:
                st.markdown("""
                <div style='background:#11101A;border:1px dashed #1C1B2E;border-radius:10px;
                     padding:3rem;text-align:center;'>
                    <div style='font-size:1.8rem;margin-bottom:0.8rem;'>⚔️</div>
                    <div style='color:#D4AF37;font-size:0.9rem;font-family:Playfair Display,Georgia,serif;
                         font-style:italic;'>Awaiting Attack Data</div>
                    <div style='color:#3A3850;font-size:0.74rem;margin-top:0.4rem;font-family:Inter,sans-serif;'>
                        Run attacks in the other tabs first to generate comparison charts.
                    </div>
                </div>""", unsafe_allow_html=True)
            else:
                results = []
                if "dict_result" in st.session_state: results.append(st.session_state["dict_result"])
                if "brute_result" in st.session_state: results.append(st.session_state["brute_result"])

                labels = [f"{r['attack_type'].replace('_',' ').title()}\n({r['algorithm'].upper()})" for r in results]
                fig, axes = plt.subplots(1, 3, figsize=(13, 4))
                fig.patch.set_facecolor("#0C0B14")

                success = [r["success_rate"] for r in results]
                axes[0].bar(labels, success, color=["#B87333", "#7A5CC0"][:len(results)], edgecolor='#1C1B2E')
                axes[0].set_ylabel("Success Rate (%)", color="#3A3850")
                axes[0].set_ylim(0, 110)
                for bar, v in zip(axes[0].patches, success):
                    axes[0].text(bar.get_x()+bar.get_width()/2, bar.get_height()+1, f"{v:.1f}%", ha='center', color='#EDE9E0', fontsize=9)
                style_axes(axes[0], "Success Rate (%)")

                times = [r["elapsed_seconds"] for r in results]
                axes[1].bar(labels, times, color=["#D4AF37", "#4AAA7A"][:len(results)], edgecolor='#1C1B2E')
                axes[1].set_ylabel("Time (seconds)", color="#3A3850")
                style_axes(axes[1], "Cracking Time (s)")

                attempts = [r["attempts"] for r in results]
                axes[2].bar(labels, attempts, color=["#C05555", "#D4AF37"][:len(results)], edgecolor='#1C1B2E')
                axes[2].set_ylabel("Attempts", color="#3A3850")
                axes[2].set_yscale("log")
                style_axes(axes[2], "Hash Attempts (log)")

                plt.tight_layout()
                st.image(make_chart(fig), use_container_width=True)


# ══════════════════════════════════════════════════════════════
# PAGE: CRYPTANALYSIS
# ══════════════════════════════════════════════════════════════
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
        fig.patch.set_facecolor("#0C0B14")
        axes[0].hist(df_feats["entropy"], bins=12, color="#D4AF37", edgecolor='#0C0B14', alpha=0.85)
        axes[0].set_xlabel("Shannon Entropy (bits/char)")
        axes[0].set_ylabel("Password Count")
        style_axes(axes[0], "Entropy Distribution")
        axes[1].scatter(df_feats["length"], df_feats["entropy"], color="#B87333", alpha=0.75, s=45, edgecolors="#1C1B2E")
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
        p1.metric("Avg Length", f"{df_feats2['length'].mean():.1f}")
        p2.metric("Avg Entropy", f"{df_feats2['entropy'].mean():.2f} bits")
        p3.metric("Avg Unique Chars", f"{df_feats2['unique_chars'].mean():.1f}")
        p4.metric("Total Passwords", len(passwords))

        patterns = analyze_patterns(passwords, top_n=8)
        fig, axes = plt.subplots(1, 3, figsize=(14, 4))
        fig.patch.set_facecolor("#0C0B14")

        len_counts = patterns["length_counts"]
        axes[0].bar(list(len_counts.keys()), list(len_counts.values()), color="#7A5CC0", edgecolor='#0C0B14')
        axes[0].set_xlabel("Password Length"); axes[0].set_ylabel("Count")
        style_axes(axes[0], "Length Distribution")

        top_pref = patterns["top_prefixes"][:8]
        axes[1].barh([p[0] for p in top_pref], [p[1] for p in top_pref], color="#B87333", edgecolor='#0C0B14')
        axes[1].set_xlabel("Frequency")
        style_axes(axes[1], "Top Prefixes (first 3 chars)")

        feat_means = df_feats2[["digits","lower","upper","special"]].mean()
        axes[2].bar(["Digits","Lower","Upper","Special"], feat_means.values,
                    color=["#D4AF37","#4AAA7A","#B87333","#7A5CC0"], edgecolor='#0C0B14')
        axes[2].set_ylabel("Avg Count per Password")
        style_axes(axes[2], "Char Type Breakdown")

        plt.tight_layout()
        st.image(make_chart(fig), use_container_width=True)
        section("Password Feature Table (Sample)")
        st.dataframe(df_feats2.head(15), use_container_width=True)

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
            st.dataframe(df_ranked, use_container_width=True)

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
            fig.patch.set_facecolor("#0C0B14")
            bars = ax.bar(["MD5", "SHA-1"], [md5_t*1e6, sha1_t*1e6],
                          color=["#B87333","#7A5CC0"], edgecolor='#1C1B2E', width=0.4)
            for bar, v in zip(bars, [md5_t*1e6, sha1_t*1e6]):
                ax.text(bar.get_x()+bar.get_width()/2, bar.get_height()+0.01,
                        f"{v:.3f} µs", ha='center', color='#EDE9E0', fontsize=10)
            ax.set_ylabel("Avg Time per Hash (µs)")
            style_axes(ax, "MD5 vs SHA-1 — Average Hash Time")
            plt.tight_layout()
            st.image(make_chart(ax.figure), use_container_width=True)
            st.error("🚨  At millions of hashes/sec, weak passwords fall in seconds. Use bcrypt/argon2 instead!")


# ══════════════════════════════════════════════════════════════
# PAGE: DEFENCE SYSTEM
# ══════════════════════════════════════════════════════════════
elif "Defence" in page:
    page_header("Defence System", "Secure Hashing  ·  Salting  ·  Password Policy  ·  AI Detection")

    tab1, tab2, tab3, tab4 = st.tabs(["SECURE HASHING", "SALTING DEMO", "PASSWORD POLICY", "AI WEAK DETECTOR"])

    with tab1:
        section("bcrypt & Argon2 — Secure Hashing")
        st.markdown("""
        <div style='background:#0E1A14;border:1px solid #4AAA7A20;border-left:3px solid #4AAA7A;
             border-radius:0 9px 9px 0;padding:0.9rem 1.3rem;margin-bottom:1.2rem;font-family:Inter,sans-serif;'>
            <span style='color:#3A6050;font-size:0.82rem;line-height:1.8;'>
            Modern algorithms are <b style='color:#4AAA7A;'>intentionally slow</b> with built-in salting —
            designed to resist brute-force at scale.
            </span>
        </div>""", unsafe_allow_html=True)
        sec_pwd = st.text_input("Enter a password to securely hash:", placeholder="Any password...", key="sec_hash_input")

        if sec_pwd:
            sh1, sh2 = st.columns(2)
            with sh1:
                st.markdown("<div style='color:#4AAA7A;font-weight:700;letter-spacing:0.12em;font-size:0.75rem;font-family:JetBrains Mono,monospace;margin-bottom:0.6rem;'>BCRYPT</div>", unsafe_allow_html=True)
                if st.button("🔒 Hash with bcrypt"):
                    with st.spinner("Hashing..."):
                        t0 = time.perf_counter(); bh = hash_bcrypt(sec_pwd); bt = time.perf_counter() - t0
                    st.code(bh, language=None)
                    st.metric("Time taken", f"{bt*1000:.1f} ms")
                    st.success("✓  bcrypt includes automatic salt!")
                    st.metric("Verification", "✓ PASS" if verify_bcrypt(sec_pwd, bh) else "✗ FAIL")
            with sh2:
                st.markdown("<div style='color:#D4AF37;font-weight:700;letter-spacing:0.12em;font-size:0.75rem;font-family:JetBrains Mono,monospace;margin-bottom:0.6rem;'>ARGON2</div>", unsafe_allow_html=True)
                if st.button("🔒 Hash with Argon2"):
                    with st.spinner("Hashing..."):
                        t0 = time.perf_counter(); ah = hash_argon2(sec_pwd); at = time.perf_counter() - t0
                    st.code(ah, language=None)
                    st.metric("Time taken", f"{at*1000:.1f} ms")
                    st.success("✓  Argon2 is memory-hard — resistant to GPU attacks!")
                    st.metric("Verification", "✓ PASS" if verify_argon2(sec_pwd, ah) else "✗ FAIL")

        st.markdown("---")
        section("Why Slow Hashing Matters", "#4AAA7A")
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
            st.dataframe(pd.DataFrame(rows), use_container_width=True)
            st.success("✓  Same password produces 4 completely different hashes — rainbow table attacks defeated!")

        st.markdown("---")
        section("bcrypt Built-in Salting")
        salt_demo_pwd = st.text_input("Password:", placeholder="test password", key="bcrypt_salt_demo")
        if salt_demo_pwd and st.button("Show bcrypt Salt Demo"):
            h1 = hash_bcrypt(salt_demo_pwd); h2 = hash_bcrypt(salt_demo_pwd)
            sd1, sd2 = st.columns(2)
            sd1.markdown("**Hash 1:**"); sd1.code(h1, language=None)
            sd2.markdown("**Hash 2 (same password):**"); sd2.code(h2, language=None)
            st.success("✓  Different every time, but both verify correctly!")

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
            st.dataframe(df, use_container_width=True)
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


# ══════════════════════════════════════════════════════════════
# PAGE: VALIDATION METRICS
# ══════════════════════════════════════════════════════════════
elif "Validation" in page:
    page_header("Validation Metrics", "Security Improvements  ·  Weak vs Secure System Comparison")

    pwd_path = DATA_DIR / "passwords.txt"
    passwords = generate_weak_passwords(extra_count=10) if not pwd_path.exists() else [l.strip() for l in pwd_path.read_text().splitlines() if l.strip()]

    st.markdown("""
    <div style='background:#11101A;border:1px solid #1C1B2E;border-radius:9px;
         padding:1rem 1.4rem;margin-bottom:1.5rem;'>
        <span style='color:#5A5470;font-size:0.84rem;font-family:Inter,sans-serif;line-height:1.9;'>
        Run the full validation to compare <b style='color:#C05555;'>weak hashing (MD5/SHA-1)</b> vs
        <b style='color:#4AAA7A;'>secure hashing (bcrypt/Argon2)</b> and AI detection effectiveness.
        </span>
    </div>""", unsafe_allow_html=True)

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

        section("Security Improvement Factors", "#4AAA7A")
        r1, r2, r3 = st.columns(3)
        r1.metric("bcrypt vs MD5", f"{bcrypt_ratio:,.0f}x slower", delta="harder to brute-force", delta_color="normal")
        r2.metric("Argon2 vs MD5", f"{argon2_ratio:,.0f}x slower", delta="harder to brute-force", delta_color="normal")
        r3.metric("AI Weak Detection", f"{metrics['avg_weak_prob']:.1%}", delta="correctly identifies weak")

        st.markdown("---")
        section("Visual Comparison")
        fig, axes = plt.subplots(1, 3, figsize=(15, 5))
        fig.patch.set_facecolor("#0C0B14")
        algos = ["MD5", "SHA-1", "bcrypt", "Argon2"]
        times = [metrics["md5_time"]*1000, metrics["sha1_time"]*1000, metrics["bcrypt_time"]*1000, metrics["argon2_time"]*1000]
        colors = ["#C05555","#B87333","#4AAA7A","#D4AF37"]

        axes[0].bar(algos, times, color=colors, edgecolor='#1C1B2E')
        axes[0].set_ylabel("Time per hash (ms)"); axes[0].set_yscale("log")
        style_axes(axes[0], "Hash Speed (log scale)")

        hashes_per_sec = [int(1/(t/1000)) for t in times]
        axes[1].bar(algos, hashes_per_sec, color=colors, edgecolor='#1C1B2E')
        axes[1].set_ylabel("Hashes per second"); axes[1].set_yscale("log")
        style_axes(axes[1], "Hashes/sec — Attacker Speed")

        axes[2].bar(algos, [1/h if h > 0 else 0 for h in hashes_per_sec], color=colors, edgecolor='#1C1B2E')
        axes[2].set_ylabel("Seconds per attempt"); axes[2].set_yscale("log")
        style_axes(axes[2], "Time per Attempt (log)")

        plt.tight_layout()
        st.image(make_chart(fig), use_container_width=True)

        section("Summary Table")
        st.markdown(f"""
        <div style='background:#11101A;border:1px solid #1C1B2E;border-radius:10px;padding:1.6rem;
             box-shadow:0 4px 16px rgba(0,0,0,0.5);'>
        <table style='width:100%;border-collapse:collapse;font-size:0.79rem;font-family:Inter,sans-serif;'>
        <tr style='border-bottom:1px solid #1C1B2E;'>
            <th style='color:#D4AF37;padding:0.6rem;text-align:left;letter-spacing:0.09em;'>Metric</th>
            <th style='color:#C05555;padding:0.6rem;text-align:center;'>MD5</th>
            <th style='color:#B87333;padding:0.6rem;text-align:center;'>SHA-1</th>
            <th style='color:#4AAA7A;padding:0.6rem;text-align:center;'>bcrypt</th>
            <th style='color:#D4AF37;padding:0.6rem;text-align:center;'>Argon2</th>
        </tr>
        <tr style='border-bottom:1px solid #161524;'>
            <td style='color:#4A4540;padding:0.55rem 0.6rem;'>Avg Hash Time</td>
            <td style='color:#C05555;padding:0.55rem;text-align:center;'>{metrics["md5_time"]*1000:.4f} ms</td>
            <td style='color:#B87333;padding:0.55rem;text-align:center;'>{metrics["sha1_time"]*1000:.4f} ms</td>
            <td style='color:#4AAA7A;padding:0.55rem;text-align:center;'>{metrics["bcrypt_time"]*1000:.1f} ms</td>
            <td style='color:#D4AF37;padding:0.55rem;text-align:center;'>{metrics["argon2_time"]*1000:.1f} ms</td>
        </tr>
        <tr style='border-bottom:1px solid #161524;'>
            <td style='color:#4A4540;padding:0.55rem 0.6rem;'>Built-in Salt</td>
            <td style='color:#C05555;padding:0.55rem;text-align:center;'>✗ No</td>
            <td style='color:#B87333;padding:0.55rem;text-align:center;'>✗ No</td>
            <td style='color:#4AAA7A;padding:0.55rem;text-align:center;'>✓ Yes</td>
            <td style='color:#D4AF37;padding:0.55rem;text-align:center;'>✓ Yes</td>
        </tr>
        <tr>
            <td style='color:#4A4540;padding:0.55rem 0.6rem;'>Recommended Use</td>
            <td style='color:#C05555;padding:0.55rem;text-align:center;'>Never</td>
            <td style='color:#B87333;padding:0.55rem;text-align:center;'>Never</td>
            <td style='color:#4AAA7A;padding:0.55rem;text-align:center;'>✓ Passwords</td>
            <td style='color:#D4AF37;padding:0.55rem;text-align:center;'>✓ Best Choice</td>
        </tr>
        </table>
        </div>
        """, unsafe_allow_html=True)

        section("Conclusion", "#4AAA7A")
        st.markdown("""
        <div style='background:#0E1A14;border-left:3px solid #4AAA7A;padding:1.5rem 1.8rem;
             border-radius:0 10px 10px 0;
             box-shadow:0 0 24px rgba(74,170,122,0.08),0 4px 16px rgba(0,0,0,0.4);'>
            <p style='color:#506050;line-height:2.1;margin:0;font-size:0.84rem;font-family:Inter,sans-serif;'>
            This project demonstrates that <b style='color:#C05555;'>MD5 and SHA-1</b> are fundamentally broken for password storage.
            The defence system using <b style='color:#4AAA7A;'>bcrypt/Argon2</b> with built-in salting,
            combined with an <b style='color:#D4AF37;'>AI-based weak password detector</b> and
            <b style='color:#7A5CC0;'>strict password policies</b>, significantly improves security posture.
            </p>
        </div>
        """, unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════
# PAGE: SECURITY INTELLIGENCE
# ══════════════════════════════════════════════════════════════
elif "Security Intelligence" in page:
    page_header("Security Intelligence", "Live Password Threat Analysis  ·  Full-Spectrum Audit")

    st.markdown("""
    <div style='background:#11101A;border:1px solid #1C1B2E;border-left:3px solid #D4AF37;
         border-radius:0 10px 10px 0;padding:1.1rem 1.5rem;margin-bottom:1.8rem;'>
        <span style='color:#5A5450;font-size:0.84rem;line-height:1.9;font-family:Inter,sans-serif;'>
        Enter any password for a <b style='color:#D4AF37;'>full intelligence report</b> —
        entropy score, AI threat classification, estimated crack time, live hash generation,
        policy compliance audit, and character composition analysis.
        </span>
    </div>
    """, unsafe_allow_html=True)

    si_pwd = st.text_input("Enter password to analyse:", placeholder="Type any password...", type="password", key="si_pwd_input")
    show_plain = st.checkbox("Show password in plain text", value=False)
    if show_plain and si_pwd:
        st.markdown(f"<code style='color:#D4AF37;font-size:0.88rem;'>{si_pwd}</code>", unsafe_allow_html=True)

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

        if score>=80: threat_level,threat_color,threat_label="LOW","#4AAA7A","STRONG"
        elif score>=55: threat_level,threat_color,threat_label="MODERATE","#D4AF37","MODERATE"
        elif score>=30: threat_level,threat_color,threat_label="HIGH","#B87333","WEAK"
        else: threat_level,threat_color,threat_label="CRITICAL","#C05555","CRITICAL"

        # Threat panel
        st.markdown(f"""
        <div style='background:#11101A;border:1px solid {threat_color}20;border-radius:12px;
             padding:2.2rem;margin:1.2rem 0;
             box-shadow:0 0 40px {threat_color}10,0 8px 28px rgba(0,0,0,0.6);'>
            <div style='display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:1.5rem;'>
                <div>
                    <div style='color:#2A2840;font-size:0.54rem;font-weight:700;letter-spacing:0.22em;
                         font-family:Inter,sans-serif;margin-bottom:0.5rem;'>OVERALL THREAT LEVEL</div>
                    <div style='color:{threat_color};font-size:3.2rem;font-weight:400;
                         letter-spacing:0.04em;line-height:1;font-family:Playfair Display,Georgia,serif;
                         text-shadow:0 0 30px {threat_color}50;'>{threat_level}</div>
                    <div style='color:#4A4540;font-size:0.74rem;margin-top:0.6rem;font-family:Inter,sans-serif;'>
                        Classified as <b style='color:{threat_color};'>{threat_label}</b></div>
                </div>
                <div style='text-align:right;'>
                    <div style='color:#2A2840;font-size:0.54rem;font-weight:700;letter-spacing:0.22em;
                         font-family:Inter,sans-serif;margin-bottom:0.5rem;'>SECURITY SCORE</div>
                    <div style='color:{threat_color};font-size:4rem;font-weight:400;line-height:1;
                         font-family:Playfair Display,Georgia,serif;
                         text-shadow:0 0 30px {threat_color}50;'>{score}<span style='font-size:1.1rem;color:#2A2840;'>/100</span></div>
                </div>
            </div>
            <div style='margin-top:1.5rem;background:#1C1B2E;border-radius:4px;height:2px;overflow:hidden;'>
                <div style='width:{score}%;background:linear-gradient(90deg,{threat_color}80,{threat_color});
                     height:100%;border-radius:4px;
                     box-shadow:0 0 10px {threat_color}60;'></div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        si1, si2, si3, si4, si5 = st.columns(5)
        si1.metric("Length", len(si_pwd))
        si2.metric("Entropy", f"{ent:.2f} bits/char")
        si3.metric("AI Weak Prob.", f"{ai_prob:.1%}")
        si4.metric("Charset Size", charset_size)
        si5.metric("Combinations", f"{total_combinations:.2e}")

        st.markdown("<div style='height:0.5rem;'></div>", unsafe_allow_html=True)
        section("ESTIMATED CRACK TIME")
        c1, c2, c3 = st.columns(3)
        crack_data = [
            (c1, "DICTIONARY ATTACK", crack_dict, f"at {DICT_RATE:,} attempts/sec", "#C05555", "#1A1014"),
            (c2, "BRUTE-FORCE (GPU)", crack_brute, f"at {BRUTE_RATE/1e9:.0f}B attempts/sec", "#B87333", "#1A1510"),
            (c3, "WITH BCRYPT DEFENCE", crack_bcrypt, f"at only {BCRYPT_RATE} attempts/sec", "#4AAA7A", "#0E1A14"),
        ]
        for col, label, val, sub, color, bg in crack_data:
            with col:
                st.markdown(f"""
                <div style='background:{bg};border:1px solid {color}18;border-radius:10px;
                     padding:1.4rem;text-align:center;
                     box-shadow:0 0 24px {color}08,0 4px 16px rgba(0,0,0,0.5);'>
                    <div style='color:{color};font-size:0.54rem;font-weight:700;letter-spacing:0.18em;
                         font-family:Inter,sans-serif;margin-bottom:0.5rem;'>{label}</div>
                    <div style='color:#EDE9E0;font-size:1.6rem;font-weight:400;margin:0.5rem 0;
                         font-family:Playfair Display,Georgia,serif;'>{val}</div>
                    <div style='color:#4A4540;font-size:0.67rem;font-family:Inter,sans-serif;'>{sub}</div>
                </div>""", unsafe_allow_html=True)

        st.markdown("<div style='height:0.5rem;'></div>", unsafe_allow_html=True)
        t_hash, t_ai, t_policy, t_compose = st.tabs(["🔑  LIVE HASHES", "🤖  AI ANALYSIS", "🛡️  POLICY AUDIT", "📊  COMPOSITION"])

        with t_hash:
            section("ALL FOUR ALGORITHMS — LIVE OUTPUT")
            h_md5 = hash_md5(si_pwd); h_sha1 = hash_sha1(si_pwd)
            col_a, col_b = st.columns(2)
            with col_a:
                st.markdown("""<div style='background:#11101A;border:1px solid #C0555520;border-radius:9px;
                    padding:1.1rem;margin-bottom:0.9rem;'>
                    <div style='color:#C05555;font-size:0.58rem;font-weight:700;letter-spacing:0.14em;
                    margin-bottom:0.5rem;font-family:JetBrains Mono,monospace;'>⚠ MD5 — BROKEN</div>""", unsafe_allow_html=True)
                st.code(h_md5, language=None)
                st.markdown("<div style='color:#2E2840;font-size:0.67rem;font-family:Inter,sans-serif;margin-top:0.3rem;'>No salt · 128-bit · Crackable in milliseconds</div></div>", unsafe_allow_html=True)
                st.markdown("""<div style='background:#11101A;border:1px solid #B8733320;border-radius:9px;padding:1.1rem;'>
                    <div style='color:#B87333;font-size:0.58rem;font-weight:700;letter-spacing:0.14em;
                    margin-bottom:0.5rem;font-family:JetBrains Mono,monospace;'>⚠ SHA-1 — DEPRECATED</div>""", unsafe_allow_html=True)
                st.code(h_sha1, language=None)
                st.markdown("<div style='color:#2E2840;font-size:0.67rem;font-family:Inter,sans-serif;margin-top:0.3rem;'>No salt · 160-bit · Collision attacks known</div></div>", unsafe_allow_html=True)
            with col_b:
                if st.button("🔒 Generate bcrypt & Argon2 Hashes"):
                    with st.spinner("Computing secure hashes..."):
                        t0=time.perf_counter(); h_bcrypt=hash_bcrypt(si_pwd); bcrypt_ms=(time.perf_counter()-t0)*1000
                        t0=time.perf_counter(); h_argon2=hash_argon2(si_pwd); argon2_ms=(time.perf_counter()-t0)*1000
                    st.session_state["si_bcrypt"]=(h_bcrypt,bcrypt_ms)
                    st.session_state["si_argon2"]=(h_argon2,argon2_ms)
                if "si_bcrypt" in st.session_state:
                    h_b,ms_b=st.session_state["si_bcrypt"]
                    st.markdown(f"""<div style='background:#11101A;border:1px solid #4AAA7A20;border-radius:9px;
                        padding:1.1rem;margin-bottom:0.9rem;'>
                        <div style='color:#4AAA7A;font-size:0.58rem;font-weight:700;letter-spacing:0.14em;
                        margin-bottom:0.5rem;font-family:JetBrains Mono,monospace;'>✓ BCRYPT ({ms_b:.0f} ms)</div>""", unsafe_allow_html=True)
                    st.code(h_b, language=None)
                    st.markdown("<div style='color:#2E2840;font-size:0.67rem;font-family:Inter,sans-serif;margin-top:0.3rem;'>Built-in salt · Adaptive cost · Attacker-hostile</div></div>", unsafe_allow_html=True)
                if "si_argon2" in st.session_state:
                    h_a,ms_a=st.session_state["si_argon2"]
                    st.markdown(f"""<div style='background:#11101A;border:1px solid #D4AF3720;border-radius:9px;padding:1.1rem;'>
                        <div style='color:#D4AF37;font-size:0.58rem;font-weight:700;letter-spacing:0.14em;
                        margin-bottom:0.5rem;font-family:JetBrains Mono,monospace;'>✓ ARGON2 ({ms_a:.0f} ms)</div>""", unsafe_allow_html=True)
                    st.code(h_a, language=None)
                    st.markdown("<div style='color:#2E2840;font-size:0.67rem;font-family:Inter,sans-serif;margin-top:0.3rem;'>Memory-hard · PHC winner · GPU-resistant</div></div>", unsafe_allow_html=True)

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
            comp_color = "#4AAA7A" if compliance_pct>=75 else "#B87333" if compliance_pct>=50 else "#C05555"
            st.markdown(f"""
            <div style='background:#11101A;border:1px solid #1C1B2E;border-radius:9px;
                 padding:1rem 1.3rem;margin-bottom:1rem;
                 display:flex;justify-content:space-between;align-items:center;'>
                <span style='color:#5A5450;font-size:0.82rem;font-family:Inter,sans-serif;'>Compliance Score</span>
                <span style='color:{comp_color};font-size:1.3rem;font-weight:400;
                     font-family:Playfair Display,Georgia,serif;
                     text-shadow:0 0 20px {comp_color}40;'>
                    {passed_count}/{len(rules)}
                    <span style='font-size:0.78rem;color:#3A3850;'>({compliance_pct:.0f}%)</span>
                </span>
            </div>""", unsafe_allow_html=True)
            for rule, passed, detail in rules:
                col_r = "#4AAA7A" if passed else "#C05555"
                bg_r  = "#0E1A14" if passed else "#1A0E0E"
                bd_r  = "#1A3024" if passed else "#301A1A"
                st.markdown(f"""
                <div style='display:flex;align-items:center;justify-content:space-between;
                     padding:0.55rem 1.1rem;border-radius:7px;margin-bottom:0.3rem;
                     background:{bg_r};border:1px solid {bd_r};'>
                    <span style='color:{col_r};font-size:0.78rem;font-family:Inter,sans-serif;'>
                        {"✓" if passed else "✗"}&nbsp; {rule}
                    </span>
                    <span style='color:#2E2840;font-size:0.69rem;font-family:JetBrains Mono,monospace;'>{detail}</span>
                </div>""", unsafe_allow_html=True)

        with t_compose:
            section("CHARACTER COMPOSITION")
            digits  = sum(c.isdigit() for c in si_pwd)
            lowers  = sum(c.islower() for c in si_pwd)
            uppers  = sum(c.isupper() for c in si_pwd)
            specials= sum(c in _string.punctuation for c in si_pwd)
            total   = len(si_pwd)

            fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4))
            fig.patch.set_facecolor("#0C0B14")
            categories=["Lowercase","Uppercase","Digits","Special"]
            counts=[lowers,uppers,digits,specials]
            colors_bar=["#D4AF37","#7A5CC0","#B87333","#4AAA7A"]
            bars=ax1.bar(categories, counts, color=colors_bar, edgecolor='#1C1B2E', width=0.5)
            for bar,v in zip(bars,counts):
                if v>0: ax1.text(bar.get_x()+bar.get_width()/2, bar.get_height()+0.05, str(v), ha='center', color='#EDE9E0', fontsize=11)
            style_axes(ax1,"Character Type Count"); ax1.set_ylabel("Count",color="#3A3850")

            nonzero_vals=[v for v in counts if v>0]
            nonzero_labels=[f"{categories[i]}\n{counts[i]} ({counts[i]/total*100:.0f}%)" for i,v in enumerate(counts) if v>0]
            nonzero_colors=[colors_bar[i] for i,v in enumerate(counts) if v>0]
            if nonzero_vals:
                wedges,texts,_=ax2.pie(nonzero_vals,labels=nonzero_labels,colors=nonzero_colors,autopct='',startangle=90,wedgeprops={"edgecolor":"#0C0B14","linewidth":2})
                for t in texts: t.set_color("#555"); t.set_fontsize(8)
            ax2.set_facecolor("#0C0B14"); style_axes(ax2,"Composition Distribution")
            plt.tight_layout()
            st.image(make_chart(fig), use_container_width=True)

            sc1,sc2,sc3,sc4=st.columns(4)
            sc1.metric("Lowercase",f"{lowers} ({lowers/total*100:.0f}%)")
            sc2.metric("Uppercase",f"{uppers} ({uppers/total*100:.0f}%)")
            sc3.metric("Digits",f"{digits} ({digits/total*100:.0f}%)")
            sc4.metric("Special",f"{specials} ({specials/total*100:.0f}%)")
    else:
        st.markdown("""
        <div style='background:#11101A;border:1px dashed #1C1B2E;border-radius:12px;
             padding:4rem;text-align:center;margin-top:1rem;'>
            <div style='font-size:2.2rem;margin-bottom:1.2rem;opacity:0.6;'>🔍</div>
            <div style='color:#D4AF37;font-size:1rem;font-weight:400;
                 font-family:Playfair Display,Georgia,serif;font-style:italic;'>Awaiting Input</div>
            <div style='color:#2A2840;font-size:0.76rem;margin-top:0.5rem;font-family:Inter,sans-serif;'>
                Enter a password above to generate a full security intelligence report.
            </div>
        </div>
        """, unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════
# PAGE: ABOUT
# ══════════════════════════════════════════════════════════════
elif "About" in page:
    page_header("About", "Research Team  ·  Project Overview  ·  Academic Context")

    st.markdown("""
    <div style='background:#11101A;border:1px solid #1C1B2E;border-radius:12px;
         padding:3rem;margin-bottom:1.8rem;text-align:center;
         box-shadow:0 0 40px rgba(212,175,55,0.06),0 8px 28px rgba(0,0,0,0.6);
         position:relative;overflow:hidden;'>
        <div style='position:absolute;top:0;left:20%;right:20%;height:1px;
             background:linear-gradient(90deg,transparent,#D4AF37 50%,transparent);'></div>
        <div style='font-size:2rem;margin-bottom:0.9rem;'>🔐</div>
        <div style='color:#D4AF37;font-size:1.5rem;font-weight:400;font-style:italic;
             font-family:Playfair Display,Georgia,serif;
             text-shadow:0 0 30px rgba(212,175,55,0.35);'>CryptLab</div>
        <div style='color:#2A2840;font-size:0.56rem;letter-spacing:0.2em;margin-top:0.6rem;
             text-transform:uppercase;font-family:Inter,sans-serif;'>
            Cryptanalysis of Weak Password Hashing Systems and AI-Based Defence Mechanism
        </div>
        <div style='height:1px;background:linear-gradient(90deg,transparent,#1C1B2E 30%,#1C1B2E 70%,transparent);
             margin:1.6rem auto;max-width:300px;'></div>
        <div style='color:#4A4540;font-size:0.84rem;line-height:2.1;max-width:620px;margin:0 auto;
             font-family:Inter,sans-serif;'>
            A university-level research project investigating cryptographic vulnerabilities in legacy
            password hashing algorithms, performing systematic attack simulations, and designing
            an AI-augmented defence architecture using modern memory-hard hashing and machine learning.
        </div>
    </div>
    """, unsafe_allow_html=True)

    section("DEVELOPED BY")
    team = [
        ("👩‍💻", "Amina Noor",    "Full Stack Developer",    "Module I — Hash Lab & Attack Simulation",        "#B87333"),
        ("👩‍🎨", "Hamail Fatima", "UI/UX Designer",          "Module II — Cryptanalysis & AI Analysis",        "#7A5CC0"),
        ("👩‍🔬", "Hajra Sarwar",  "Full Stack AI Developer", "Module III — Defence Architecture & Validation", "#4AAA7A"),
    ]
    t1, t2, t3 = st.columns(3)
    for col, (icon, name, title, module, color) in zip([t1,t2,t3], team):
        with col:
            st.markdown(f"""
            <div style='background:#11101A;border:1px solid #1C1B2E;border-top:2px solid {color};
                 border-radius:10px;padding:1.9rem 1.6rem;text-align:center;height:100%;
                 box-shadow:0 0 24px {color}08,0 4px 16px rgba(0,0,0,0.5);'>
                <div style='font-size:2rem;margin-bottom:0.9rem;'>{icon}</div>
                <div style='color:#EDE9E0;font-size:1.05rem;font-weight:400;
                     font-family:Playfair Display,Georgia,serif;font-style:italic;'>{name}</div>
                <div style='color:{color};font-size:0.55rem;font-weight:700;letter-spacing:0.16em;
                     margin:0.55rem 0;text-transform:uppercase;font-family:Inter,sans-serif;'>{title}</div>
                <div style='height:1px;background:linear-gradient(90deg,transparent,{color}30 50%,transparent);
                     margin:0.9rem 0;'></div>
                <div style='color:#4A4540;font-size:0.72rem;line-height:1.9;font-family:Inter,sans-serif;'>{module}</div>
            </div>
            """, unsafe_allow_html=True)

    st.markdown("<div style='height:0.5rem;'></div>", unsafe_allow_html=True)
    section("PROJECT DETAILS")
    d1, d2 = st.columns(2)
    with d1:
        st.markdown("""
        <div style='background:#11101A;border:1px solid #1C1B2E;border-radius:10px;padding:1.6rem;height:100%;
             box-shadow:0 4px 16px rgba(0,0,0,0.4);'>
            <div style='color:#D4AF37;font-size:0.55rem;font-weight:700;letter-spacing:0.2em;
                 margin-bottom:1.1rem;text-transform:uppercase;font-family:Inter,sans-serif;'>SCOPE &amp; OBJECTIVES</div>
            <ul style='color:#4A4540;font-size:0.77rem;line-height:2.3;margin:0;
                 padding-left:1.1rem;font-family:Inter,sans-serif;'>
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
        <div style='background:#11101A;border:1px solid #1C1B2E;border-radius:10px;padding:1.6rem;height:100%;
             box-shadow:0 4px 16px rgba(0,0,0,0.4);'>
            <div style='color:#D4AF37;font-size:0.55rem;font-weight:700;letter-spacing:0.2em;
                 margin-bottom:1.1rem;text-transform:uppercase;font-family:Inter,sans-serif;'>TECHNOLOGY STACK</div>
            <table style='width:100%;border-collapse:collapse;font-size:0.76rem;font-family:Inter,sans-serif;'>
                <tr style='border-bottom:1px solid #161524;'><td style='color:#D4AF37;padding:0.5rem 0;font-family:JetBrains Mono,monospace;font-size:0.73rem;'>Python 3.12</td><td style='color:#4A4540;padding:0.5rem 0;'>Core language</td></tr>
                <tr style='border-bottom:1px solid #161524;'><td style='color:#D4AF37;padding:0.5rem 0;font-family:JetBrains Mono,monospace;font-size:0.73rem;'>hashlib</td><td style='color:#4A4540;padding:0.5rem 0;'>MD5 / SHA-1 primitives</td></tr>
                <tr style='border-bottom:1px solid #161524;'><td style='color:#D4AF37;padding:0.5rem 0;font-family:JetBrains Mono,monospace;font-size:0.73rem;'>bcrypt / Argon2</td><td style='color:#4A4540;padding:0.5rem 0;'>Memory-hard secure hashing</td></tr>
                <tr style='border-bottom:1px solid #161524;'><td style='color:#D4AF37;padding:0.5rem 0;font-family:JetBrains Mono,monospace;font-size:0.73rem;'>scikit-learn</td><td style='color:#4A4540;padding:0.5rem 0;'>Random Forest ML model</td></tr>
                <tr style='border-bottom:1px solid #161524;'><td style='color:#D4AF37;padding:0.5rem 0;font-family:JetBrains Mono,monospace;font-size:0.73rem;'>Streamlit</td><td style='color:#4A4540;padding:0.5rem 0;'>Interactive web interface</td></tr>
                <tr><td style='color:#D4AF37;padding:0.5rem 0;font-family:JetBrains Mono,monospace;font-size:0.73rem;'>ReportLab</td><td style='color:#4A4540;padding:0.5rem 0;'>PDF academic report export</td></tr>
            </table>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<div style='height:0.5rem;'></div>", unsafe_allow_html=True)
    st.markdown("""
    <div style='background:#11101A;border:1px solid #1C1B2E;border-radius:8px;
         padding:1rem 1.6rem;text-align:center;'>
        <span style='color:#2A2840;font-size:0.63rem;letter-spacing:0.16em;font-family:JetBrains Mono,monospace;'>
        CRYPTANALYSIS OF WEAK PASSWORD HASHING SYSTEMS AND AI-BASED DEFENCE MECHANISM &nbsp;·&nbsp; UNIVERSITY PROJECT &nbsp;·&nbsp; 2026–2027
        </span>
    </div>
    """, unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════
# FOOTER
# ══════════════════════════════════════════════════════════════
st.markdown("---")
st.markdown("""
<div style='text-align:center;padding:0.5rem;'>
    <span style='color:#1C1B2E;font-size:0.6rem;letter-spacing:0.16em;font-family:JetBrains Mono,monospace;'>
    CRYPTLAB &nbsp;·&nbsp; CRYPTANALYSIS OF WEAK PASSWORD HASHING SYSTEMS AND AI-BASED DEFENCE MECHANISM
    </span>
</div>
""", unsafe_allow_html=True)
