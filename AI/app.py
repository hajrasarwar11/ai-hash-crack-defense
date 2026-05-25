"""
app.py — PassGuard v3.0
All features: Analyze, Batch Audit, CSV Upload, Vault, AI Coach, Degradation, History, About
"""

import streamlit as st
import pandas as pd
from datetime import datetime
from backend import (
    predict_strength, calculate_entropy, estimate_crack_time,
    identify_attacks, check_breach, generate_password,
    generate_qr_code, get_tips, predict_degradation,
    audit_batch, audit_csv, check_multilingual_patterns,
    extract_features, coach_response,
    vault_encrypt, vault_decrypt, MODEL
)

# ─────────────────────────────────────────────────────────────
# PAGE CONFIG
# ─────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="PassGuard",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ─────────────────────────────────────────────────────────────
# CSS
# ─────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;900&family=JetBrains+Mono:wght@400;700&display=swap');

html, body, [class*="css"] { font-family: 'Inter', sans-serif !important; }
#MainMenu { visibility: visible; }
footer { visibility: visible; }
header { visibility: visible; }
[data-testid="collapsedControl"] { display: block !important; visibility: visible !important; }
button[kind="header"] { display: block !important; visibility: visible !important; }
.block-container { padding-top: 0 !important; }

/* ── DARK BACKGROUND FIX ── */
.stApp, .main, section.main, [data-testid="stAppViewContainer"] {
    background-color: #0d0d0d !important;
}
[data-testid="stAppViewBlockContainer"] {
    background-color: #0d0d0d !important;
}

/* ── GLOBAL TEXT COLOR FIX ── */
html, body, p, span, div, label, li,
[class*="css"], .stMarkdown, .stText {
    color: #e8e8e8 !important;
}

/* Sidebar */
section[data-testid="stSidebar"] {
    background: #0a0a0a !important;
    border-right: 2px solid #333 !important;
}
section[data-testid="stSidebar"] * { color: #ffffff !important; }

/* Buttons */
.stButton > button {
    background: #1a1a1a !important;
    color: #fff !important;
    border: 2px solid #555 !important;
    border-radius: 2px !important;
    font-weight: 700 !important;
    letter-spacing: 1px !important;
    text-transform: uppercase !important;
    font-size: 0.78rem !important;
    width: 100%;
    transition: all 0.15s !important;
}
.stButton > button:hover {
    background: #fff !important;
    color: #000 !important;
    border-color: #fff !important;
}

/* Inputs */
.stTextInput > div > div > input,
.stTextArea > div > div > textarea {
    background: #1a1a1a !important;
    color: #ffffff !important;
    border: 2px solid #444 !important;
    border-radius: 2px !important;
    font-family: 'JetBrains Mono', monospace !important;
}
.stTextInput > div > div > input::placeholder,
.stTextArea > div > div > textarea::placeholder {
    color: #666 !important;
}

/* Selectbox */
.stSelectbox > div > div {
    background: #1a1a1a !important;
    color: #fff !important;
    border: 2px solid #444 !important;
    border-radius: 2px !important;
}
.stSelectbox svg { fill: #fff !important; }

/* Metrics */
[data-testid="stMetric"] {
    background: #1a1a1a !important;
    border: 1px solid #333 !important;
    padding: 1rem;
    border-radius: 3px;
}
[data-testid="stMetric"] * { color: #fff !important; }
[data-testid="stMetricLabel"] {
    font-size: 0.62rem !important;
    letter-spacing: 2px !important;
    text-transform: uppercase !important;
    color: #aaa !important;
}
[data-testid="stMetricValue"] {
    font-size: 1.3rem !important;
    font-weight: 900 !important;
    font-family: 'JetBrains Mono', monospace !important;
    color: #fff !important;
}

/* Tabs */
.stTabs [data-baseweb="tab-list"] {
    border-bottom: 2px solid #444 !important;
    background: transparent !important;
    gap: 0;
}
.stTabs [data-baseweb="tab"] {
    font-weight: 700 !important;
    letter-spacing: 2px !important;
    font-size: 0.68rem !important;
    text-transform: uppercase !important;
    padding: 0.6rem 0.8rem !important;
    color: #aaa !important;
    background: transparent !important;
}
.stTabs [aria-selected="true"] {
    border-bottom: 3px solid #fff !important;
    color: #fff !important;
}

/* Progress */
.stProgress > div > div > div { background: #fff !important; }
.stProgress > div > div {
    background: #333 !important;
}

/* Code blocks */
code, .stCode {
    background: #1a1a1a !important;
    color: #7fff7f !important;
    font-family: 'JetBrains Mono', monospace !important;
    border: 1px solid #333 !important;
}

/* Dataframe */
[data-testid="stDataFrame"] {
    background: #1a1a1a !important;
    color: #fff !important;
}

/* Info / Success / Warning / Error boxes */
[data-testid="stAlert"] { border-radius: 3px !important; }

/* Chat messages */
[data-testid="stChatMessage"] {
    background: #1a1a1a !important;
    border: 1px solid #333 !important;
    border-radius: 3px !important;
    color: #fff !important;
}

/* Dividers */
hr { border-color: #333 !important; }

/* Expander */
[data-testid="stExpander"] {
    background: #1a1a1a !important;
    border: 1px solid #333 !important;
}
[data-testid="stExpander"] * { color: #e8e8e8 !important; }

/* File uploader */
[data-testid="stFileUploader"] {
    background: #1a1a1a !important;
    border: 2px dashed #444 !important;
    color: #aaa !important;
}

/* Download button */
[data-testid="stDownloadButton"] > button {
    background: #1a1a1a !important;
    color: #fff !important;
    border: 2px solid #555 !important;
}
</style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────
# SESSION STATE
# ─────────────────────────────────────────────────────────────
for key, default in {
    "history":       [],
    "generated_pwd": "",
    "show_qr":       False,
    "vault":         [],
    "chat":          [],
    "last_password": "",
}.items():
    if key not in st.session_state:
        st.session_state[key] = default

# ─────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────
def section_title(text):
    st.markdown(
        f'<div style="font-size:0.72rem;font-weight:700;letter-spacing:4px;'
        f'text-transform:uppercase;color:#000;border-bottom:2px solid #000;'
        f'padding-bottom:0.35rem;margin:1.2rem 0 0.8rem;">{text}</div>',
        unsafe_allow_html=True
    )

def render_tip(status, text):
    if status == "good": st.success(f"✓  {text}")
    elif status == "warn": st.warning(f"⚠  {text}")
    else: st.error(f"✗  {text}")

def render_progress(label, pct):
    st.markdown(f"**{label}** — {pct}%")
    st.progress(pct / 100)

# ─────────────────────────────────────────────────────────────
# HEADER
# ─────────────────────────────────────────────────────────────
st.markdown("""
<div style="background:#000;padding:2.2rem 2rem 1.6rem;text-align:center;margin-bottom:1.2rem;">
    <div style="color:#fff;font-size:2.8rem;font-weight:900;letter-spacing:8px;">🔐 PASSGUARD</div>
    <div style="color:#555;font-size:0.75rem;letter-spacing:3px;margin-top:0.4rem;text-transform:uppercase;">
        ML-Based Password Intelligence Platform
    </div>
</div>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────
# SIDEBAR
# ─────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("### 🔐 PASSGUARD")
    st.markdown("---")
    page = st.radio("", [
        "🔍  Analyze",
        "📦  Batch Audit",
        "📊  CSV Audit",
        "🔒  Password Vault",
        "🤖  AI Coach",
        "📉  Degradation",
        "📋  History",
        "ℹ️   About",
    ], label_visibility="collapsed")
    st.markdown("---")
    st.markdown("**Model Status**")
    if MODEL is not None:
        st.success("✓ ML Model Active")
    else:
        st.warning("⚠ Rule-Based Mode\nAdd model.pkl to /models/")
    st.markdown("---")
    st.caption("PassGuard v3.0")


# ═════════════════════════════════════════════════════════════
# PAGE 1 — ANALYZE
# ═════════════════════════════════════════════════════════════
if "Analyze" in page:

    ci, cl, cb = st.columns([4, 1, 1])
    with ci:
        password = st.text_input("", placeholder="Enter password to analyze...",
                                  type="password", label_visibility="collapsed")
    with cl:
        gen_len = st.selectbox("", [12, 16, 20, 24, 32], index=1,
                                label_visibility="collapsed")
    with cb:
        if st.button("⚡ Generate"):
            st.session_state.generated_pwd = generate_password(gen_len)
            st.session_state.show_qr       = False

    # Generated password display
    if st.session_state.generated_pwd:
        gp = st.session_state.generated_pwd
        gc1, gc2, gc3 = st.columns([4, 1, 1])
        with gc1:
            st.code(gp)
        with gc2:
            st.info("Copy above")
        with gc3:
            if st.button("🔲 QR Code"):
                st.session_state.show_qr = not st.session_state.show_qr

        if st.session_state.show_qr:
            qr_bytes = generate_qr_code(gp)
            if qr_bytes:
                qc1, qc2, qc3 = st.columns([1, 2, 1])
                with qc2:
                    section_title("QR Code — Scan to Transfer")
                    st.image(qr_bytes, width=200)
                    st.caption("Scan with phone camera to transfer password securely.")
            else:
                st.info("Run:  pip install qrcode[pil]  to enable QR codes.")

    if password:
        st.session_state.last_password = password
        pred, proba                    = predict_strength(password)
        strength_label                 = ["WEAK", "MEDIUM", "STRONG"][pred]
        crack_time, attack_type, secs  = estimate_crack_time(password)
        entropy                        = calculate_entropy(password)
        feats                          = extract_features(password)

        st.session_state.history.append({
            "Time":     datetime.now().strftime("%H:%M:%S"),
            "Masked":   "*" * len(password),
            "Strength": strength_label,
            "Entropy":  f"{entropy}b",
            "Crack":    crack_time,
            "Attack":   attack_type,
        })

        st.markdown("---")
        section_title("Security Overview")

        k1, k2, k3, k4, k5 = st.columns(5)
        k1.metric("Strength",       strength_label)
        k2.metric("Crack Time",     crack_time)
        k3.metric("Entropy (bits)", entropy)
        k4.metric("Length",         feats["length"])
        k5.metric("Unique Chars",   feats["unique_chars"])

        st.markdown("<br>", unsafe_allow_html=True)

        tab1, tab2, tab3, tab4, tab5 = st.tabs([
            "ML CONFIDENCE", "CHAR BREAKDOWN", "ATTACK SIMULATION", "BREACH CHECK", "TIPS"
        ])

        with tab1:
            section_title("Model Confidence Scores")
            for i, lbl in enumerate(["Weak", "Medium", "Strong"]):
                render_progress(lbl, int(proba[i] * 100))
            st.markdown("---")
            section_title("Multilingual Weak Pattern Scan")
            found = check_multilingual_patterns(password)
            if found:
                for lang, pat in found:
                    st.error(f"✗  [{lang}] Weak pattern: `{pat}`")
            else:
                st.success("✓  No weak patterns (English, Pakistani, Arabic, Hindi, PIN).")

        with tab2:
            section_title("Character Composition")
            cb1, cb2, cb3, cb4, cb5, cb6 = st.columns(6)
            cb1.metric("Total",     feats["length"])
            cb2.metric("Uppercase", feats["num_upper"])
            cb3.metric("Lowercase", feats["num_lower"])
            cb4.metric("Digits",    feats["num_digits"])
            cb5.metric("Special",   feats["num_special"])
            cb6.metric("Unique",    feats["unique_chars"])
            st.markdown("---")
            section_title("Character Ratios")
            render_progress("Digit Ratio",   int(feats["digit_ratio"] * 100))
            render_progress("Special Ratio", int(feats["special_ratio"] * 100))
            render_progress("Char Variety",  int(feats["char_variety_ratio"] * 100))
            st.markdown("---")
            section_title("Pattern Flags")
            flags = [
                ("Sequential Numbers", feats["sequential_nums"]),
                ("Repeated Characters (3+)", feats["repeated_chars"]),
                ("Common Weak Pattern", feats["common_weak_pattern"]),
                ("Only Letters", feats["only_letters"]),
                ("Only Digits",  feats["only_digits"]),
            ]
            f1, f2 = st.columns(2)
            for i, (lbl, val) in enumerate(flags):
                with (f1 if i % 2 == 0 else f2):
                    if val: st.error(f"✗  {lbl}: DETECTED")
                    else:   st.success(f"✓  {lbl}: Clear")

        with tab3:
            section_title("Attack Type Simulation")
            st.caption("Simulates which attack methods would most likely crack this password.")
            for atk, desc in identify_attacks(password):
                with st.expander(f"⚠  {atk}"):
                    st.write(desc)
            st.markdown("---")
            section_title("Primary Attack Vector")
            st.error(f"**{attack_type}** — Estimated crack time: **{crack_time}**")

        with tab4:
            section_title("HaveIBeenPwned Breach Check")
            st.caption("Password never transmitted. Only partial SHA-1 hash used (k-anonymity).")
            with st.spinner("Checking 12+ billion breached passwords..."):
                breached, count = check_breach(password)
            if breached is None:
                st.warning("⚠  Breach API unavailable — check internet connection.")
            elif breached:
                st.error(f"🚨  **BREACHED** — Found {count:,} times in known databases. Change immediately.")
            else:
                st.success("✅  Not found in any known breach database.")

        with tab5:
            section_title("Improvement Recommendations")
            tips = get_tips(password)
            t1, t2 = st.columns(2)
            for i, (status, tip) in enumerate(tips):
                with (t1 if i % 2 == 0 else t2):
                    render_tip(status, tip)

    else:
        st.markdown("<br>", unsafe_allow_html=True)
        st.info("Enter a password above to begin analysis.")


# ═════════════════════════════════════════════════════════════
# PAGE 2 — BATCH AUDIT (text input)
# ═════════════════════════════════════════════════════════════
elif "Batch" in page:
    section_title("Batch Password Audit")
    st.write("Paste multiple passwords (one per line). All passwords are masked in the output.")

    batch_text = st.text_area("Passwords (one per line)", height=180,
                               placeholder="password123\nHajra@2026!\nAbc1\nX9#mP2$kL8!wQ5@")

    if st.button("Run Audit") and batch_text.strip():
        pwds = [p.strip() for p in batch_text.strip().splitlines() if p.strip()]
        with st.spinner(f"Auditing {len(pwds)} passwords..."):
            rows = audit_batch(pwds)
        df = pd.DataFrame(rows)
        st.dataframe(df, use_container_width=True)

        st.markdown("---")
        section_title("Audit Summary")
        sc = df["Strength"].value_counts()
        s1, s2, s3, s4 = st.columns(4)
        s1.metric("Total",  len(pwds))
        s2.metric("Weak",   sc.get("Weak",   0))
        s3.metric("Medium", sc.get("Medium", 0))
        s4.metric("Strong", sc.get("Strong", 0))

        risk_pct = int((sc.get("Weak", 0) / len(pwds)) * 100)
        render_progress("At-Risk Passwords", risk_pct)
        if risk_pct >= 50: st.error("🚨  HIGH RISK — Enforce a strong password policy immediately.")
        elif risk_pct > 0: st.warning("⚠  MODERATE RISK — Some weak passwords found.")
        else:              st.success("✅  LOW RISK — No weak passwords detected.")


# ═════════════════════════════════════════════════════════════
# PAGE 3 — CSV AUDIT (file upload)
# ═════════════════════════════════════════════════════════════
elif "CSV" in page:
    section_title("CSV Organization Password Audit")
    st.write("Upload a CSV file with a **'password'** column to audit your entire organization's passwords.")
    st.caption("Example CSV format:  password  (one column, one password per row)")

    uploaded = st.file_uploader("Upload CSV", type=["csv"])

    if uploaded:
        try:
            df_in = pd.read_csv(uploaded)
            st.write(f"Loaded **{len(df_in)}** rows.")
            st.dataframe(df_in.head(5), use_container_width=True)

            if st.button("Run Full Audit"):
                with st.spinner("Auditing all passwords..."):
                    df_result = audit_csv(df_in)

                st.dataframe(df_result, use_container_width=True)

                section_title("Organization Risk Summary")
                sc = df_result["Strength"].value_counts()
                total = len(df_result)
                c1, c2, c3, c4 = st.columns(4)
                c1.metric("Total",  total)
                c2.metric("Weak",   sc.get("Weak",   0))
                c3.metric("Medium", sc.get("Medium", 0))
                c4.metric("Strong", sc.get("Strong", 0))

                risk_pct = int((sc.get("Weak", 0) / total) * 100)
                render_progress("At-Risk %", risk_pct)

                # Download results
                csv_out = df_result.to_csv(index=False).encode("utf-8")
                st.download_button(
                    label="⬇ Download Audit Report (CSV)",
                    data=csv_out,
                    file_name="passguard_audit_report.csv",
                    mime="text/csv"
                )

                if risk_pct >= 50:
                    st.error("🚨  HIGH RISK — Majority of passwords are weak.")
                elif risk_pct > 0:
                    st.warning("⚠  MODERATE RISK — Some passwords need attention.")
                else:
                    st.success("✅  LOW RISK — All passwords passed.")

        except Exception as e:
            st.error(f"Error reading CSV: {e}")
            st.info("Make sure your CSV has a column named exactly 'password'.")


# ═════════════════════════════════════════════════════════════
# PAGE 4 — PASSWORD VAULT
# ═════════════════════════════════════════════════════════════
elif "Vault" in page:
    section_title("Encrypted Password Vault")
    st.write(
        "Save generated passwords encrypted with a master key. "
        "Nothing is sent to any server — everything stays in your browser session."
    )
    st.warning("⚠  Session only: Vault clears when you close this tab. Copy passwords you want to keep.")

    master = st.text_input("Master Key (your secret password to lock the vault):",
                            type="password", placeholder="Enter master key...")

    v1, v2 = st.columns(2)

    with v1:
        section_title("Save a Password")
        label   = st.text_input("Label (e.g. 'Gmail', 'GitHub'):", placeholder="Account name...")
        to_save = st.text_input("Password to save:", type="password", placeholder="Password...")

        if st.button("🔒 Encrypt & Save"):
            if not master:
                st.error("Enter a master key first.")
            elif not label or not to_save:
                st.error("Enter both a label and a password.")
            else:
                encrypted = vault_encrypt(to_save, master)
                if encrypted:
                    st.session_state.vault.append({
                        "label":     label,
                        "encrypted": encrypted,
                        "saved_at":  datetime.now().strftime("%H:%M:%S")
                    })
                    st.success(f"✅  '{label}' saved to vault.")
                else:
                    st.error("Install cryptography library: pip install cryptography")

    with v2:
        section_title("Retrieve a Password")
        if st.session_state.vault:
            labels     = [v["label"] for v in st.session_state.vault]
            selected   = st.selectbox("Select saved entry:", labels)
            entry      = next(v for v in st.session_state.vault if v["label"] == selected)

            if st.button("🔓 Decrypt & Show"):
                if not master:
                    st.error("Enter the master key to decrypt.")
                else:
                    decrypted = vault_decrypt(entry["encrypted"], master)
                    if decrypted:
                        st.success("Decrypted successfully:")
                        st.code(decrypted)
                    else:
                        st.error("Wrong master key or corrupted entry.")
        else:
            st.info("No passwords saved yet. Save one on the left.")

    if st.session_state.vault:
        st.markdown("---")
        section_title("Vault Contents")
        for v in st.session_state.vault:
            st.write(f"🔐  **{v['label']}** — saved at {v['saved_at']} — encrypted")

        if st.button("🗑 Clear Vault"):
            st.session_state.vault = []
            st.rerun()


# ═════════════════════════════════════════════════════════════
# PAGE 5 — AI PASSWORD COACH (ChatBot)
# ═════════════════════════════════════════════════════════════
elif "Coach" in page:
    section_title("AI Password Coach")
    st.write("Ask me anything about your password security. I'll guide you step by step.")

    current_pwd = st.session_state.get("last_password", "")
    if current_pwd:
        st.info(f"Coaching based on your last analyzed password: {'*' * len(current_pwd)}")
    else:
        st.caption("Tip: Analyze a password first, then come here for personalized coaching.")

    # Display chat history
    for msg in st.session_state.chat:
        with st.chat_message(msg["role"]):
            st.write(msg["content"])

    # Chat input
    user_input = st.chat_input("Ask your question... (e.g. 'why is my password weak?' or 'fix it')")

    if user_input:
        st.session_state.chat.append({"role": "user", "content": user_input})
        with st.chat_message("user"):
            st.write(user_input)

        response = coach_response(user_input, current_pwd)
        st.session_state.chat.append({"role": "assistant", "content": response})
        with st.chat_message("assistant"):
            st.write(response)

    if st.button("Clear Chat"):
        st.session_state.chat = []
        st.rerun()


# ═════════════════════════════════════════════════════════════
# PAGE 6 — DEGRADATION
# ═════════════════════════════════════════════════════════════
elif "Degradation" in page:
    section_title("Password Strength Degradation Predictor")
    st.write("GPU cracking speeds double every ~2 years. See when your password becomes vulnerable.")

    deg_pwd = st.text_input("Enter password:", type="password", placeholder="Your password...")

    if deg_pwd:
        rows = predict_degradation(deg_pwd)

        section_title("Future Crack Time Projection (2026 → 2046)")
        h1, h2, h3, h4 = st.columns([1, 1, 1, 1])
        h1.markdown("**Year**")
        h2.markdown("**GPU Speed**")
        h3.markdown("**Crack Time**")
        h4.markdown("**Status**")
        st.markdown("---")

        for row in rows:
            r1, r2, r3, r4 = st.columns([1, 1, 1, 1])
            r1.write(str(row["Year"]))
            r2.write(row["GPU Speed"])
            r3.write(row["Crack Time"])
            if row["Status"] == "Safe":
                r4.success("✓ Safe")
            else:
                r4.error("✗ Crackable")

        st.markdown("---")
        safe_count = sum(1 for r in rows if r["Status"] == "Safe")
        if safe_count == len(rows):
            st.success("✅  Future-proof — stays safe through 2046.")
        elif safe_count > 0:
            st.warning(f"⚠  Becomes crackable around **{rows[safe_count]['Year']}**.")
        else:
            st.error("🚨  Already at risk — replace this password immediately.")


# ═════════════════════════════════════════════════════════════
# PAGE 7 — HISTORY
# ═════════════════════════════════════════════════════════════
elif "History" in page:
    section_title("Analysis History")
    st.caption("Passwords are masked. History clears when you close this tab.")

    if st.session_state.history:
        df_hist = pd.DataFrame(st.session_state.history[::-1])
        st.dataframe(df_hist, use_container_width=True)

        hc1, hc2 = st.columns(2)
        counts = df_hist["Strength"].value_counts()
        hc1.metric("Total Analyzed",  len(df_hist))
        hc2.metric("Strong Passwords", counts.get("STRONG", 0))

        if st.button("Clear History"):
            st.session_state.history = []
            st.rerun()
    else:
        st.info("No passwords analyzed yet. Go to Analyze to start.")


# ═════════════════════════════════════════════════════════════
# PAGE 8 — ABOUT
# ═════════════════════════════════════════════════════════════
elif "About" in page:
    section_title("About PassGuard")

    a1, a2 = st.columns(2)
    with a1:
        section_title("ML Model")
        for line in [
            "**Algorithm:** Random Forest Classifier",
            "**Dataset:** 670,000+ real-world passwords",
            "**Features:** 20 engineered features",
            "**Classes:** Weak / Medium / Strong",
            "**Accuracy:** ~95%",
            "**Tuning:** GridSearchCV (5-fold CV)",
        ]:
            st.write(line)

    with a2:
        section_title("All Features")
        for f in [
            "ML strength classification",
            "Entropy score (information theory)",
            "GPU-based crack time estimator",
            "HaveIBeenPwned breach check (k-anonymity)",
            "Attack type simulation",
            "Strong password generator",
            "QR code for password transfer",
            "Multilingual weak pattern detection",
            "Batch text password audit",
            "CSV organization audit + download report",
            "Encrypted password vault (AES-256)",
            "AI Password Coach (chatbot)",
            "Strength degradation predictor",
            "Password history tracker",
        ]:
            st.write(f"✓  {f}")

    st.markdown("---")
    section_title("Crack Time Assumption")
    st.write(
        "Assumes a modern GPU at **1 billion guesses/second** brute-force. "
        "Degradation projections assume speed doubles every 2 years (Moore's Law)."
    )

    st.markdown("---")
    st.markdown("""
    <div style="background:#000;color:#fff;padding:1rem 1.5rem;border-radius:3px;font-size:0.9rem;">
        <strong>Developer:</strong> Hajra Sarwar
    </div>
    """, unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────
# FOOTER
# ─────────────────────────────────────────────────────────────
st.markdown("""
<div style="background:#000;color:#444;text-align:center;padding:1rem;
            margin-top:2.5rem;font-size:0.7rem;letter-spacing:2px;text-transform:uppercase;">
    PassGuard v3.0 &nbsp;|&nbsp; Hajra Sarwar &nbsp;|&nbsp; ML Project 2026
</div>
""", unsafe_allow_html=True)
