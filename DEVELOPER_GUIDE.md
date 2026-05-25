# DEVELOPER GUIDE
## Cryptanalysis of Weak Password Hashing Systems and AI-Based Defence Mechanism

---

## Table of Contents

1. [Project Structure](#1-project-structure)
2. [How to Run the App](#2-how-to-run-the-app)
3. [Main App File — app.py](#3-main-app-file--apppy)
   - [Page Navigation (Sidebar)](#31-page-navigation-sidebar)
   - [Page 1 — Overview](#32-page-1--overview)
   - [Page 2 — Member 1: Hash Lab](#33-page-2--member-1-hash-lab)
   - [Page 3 — Member 1: Attack Lab](#34-page-3--member-1-attack-lab)
   - [Page 4 — Member 2: Cryptanalysis](#35-page-4--member-2-cryptanalysis)
   - [Page 5 — Member 3: Defence System](#36-page-5--member-3-defence-system)
   - [Page 6 — Validation Metrics](#37-page-6--validation-metrics)
   - [Page 7 — Generate PDF Report](#38-page-7--generate-pdf-report)
4. [PDF Report File — report_generator.py](#4-pdf-report-file--report_generatorpy)
   - [How to Change Colors](#41-how-to-change-colors)
   - [How to Add / Remove a Section](#42-how-to-add--remove-a-section)
   - [How to Change Tables](#43-how-to-change-tables)
   - [How to Change Charts](#44-how-to-change-charts)
5. [Source Modules — src/ folder](#5-source-modules--src-folder)
6. [How to Change Project / Member Names](#6-how-to-change-project--member-names)
7. [How to Add a New Page](#7-how-to-add-a-new-page)
8. [Common Editing Tasks (Quick Reference)](#8-common-editing-tasks-quick-reference)

---

## 1. Project Structure

```
workspace/
│
├── app.py                  ← Main Streamlit frontend (ALL 7 pages live here)
├── report_generator.py     ← PDF report builder (10-page A4 PDF)
├── requirements.txt        ← Python package list
├── DEVELOPER_GUIDE.md      ← This file
│
├── src/                    ← All core logic modules
│   ├── hasher.py               → MD5 / SHA-1 hashing functions
│   ├── secure_hasher.py        → bcrypt / Argon2 hashing functions
│   ├── password_generator.py   → Password dataset generator
│   ├── dictionary_attack.py    → Dictionary attack logic
│   ├── brute_force_attack.py   → Brute-force attack logic
│   ├── analysis.py             → Entropy & pattern analysis
│   ├── ai_weak_detector.py     → AI model (RandomForest) for weak detection
│   ├── password_policy.py      → Password policy enforcement rules
│   ├── validation_metrics.py   → Speed/performance benchmarks
│   ├── metrics.py              → Attack report formatter
│   └── visualizer.py           → Chart helper functions
│
├── AI/
│   └── models/
│       ├── model.pkl           ← Trained RandomForest model (do not delete)
│       └── scaler.pkl          ← Feature scaler (do not delete)
│
└── data/                   ← Auto-generated during app use
    ├── passwords.txt
    ├── dictionary.txt
    ├── hashes_md5.txt
    └── hashes_sha1.txt
```

---

## 2. How to Run the App

The app runs automatically via the configured workflow. If you need to restart it manually:

```bash
streamlit run app.py --server.port 5000 --server.address 0.0.0.0 --server.headless true
```

The app opens at **port 5000** in the Replit preview pane.

---

## 3. Main App File — `app.py`

`app.py` has **1167 lines**. Here is the structure at a glance:

| Line Range | What it does |
|------------|--------------|
| 1 – 35     | Imports (libraries + src modules) |
| 36 – 162   | CSS styling (colors, cards, fonts) |
| 163 – 202  | Helper functions (page_header, section, make_chart) |
| 203 – 1156 | All 7 page functions (one big if/elif block) |
| 1157 – 1167 | Sidebar navigation + page router |

---

### 3.1 Page Navigation (Sidebar)

Location: **lines 1157 – 1167** in `app.py`

```python
PAGES = [
    "🏠 Overview",
    "⚙️ Member 1 — Hash Lab",
    "⚔️ Member 1 — Attack Lab",
    "📊 Member 2 — Cryptanalysis",
    "🛡️ Member 3 — Defence System",
    "📈 Validation Metrics",
    "📄 Generate PDF Report",
]
```

**To rename a page:** Just change the string inside the list. The emoji at the start is optional but helps with visual layout.

**To add a page:** Add a new string to `PAGES`, then add a new `elif page == "Your New Page":` block before line 1167.

**To remove a page:** Delete the string from `PAGES` and delete its `elif` block.

---

### 3.2 Page 1 — Overview

**Where it is:** Search for `if page == "🏠 Overview":` in `app.py` (around line 210).

**What you can change:**

- **Project title / subtitle** — look for `page_header("🔐 Cryptanalysis Lab", "WEAK PASSWORD HASHING SYSTEMS & AI-BASED DEFENCE")`
- **Introduction paragraph** — the `st.markdown(...)` block just below it
- **Member cards** (3 columns) — find `col1, col2, col3 = st.columns(3)` and edit the text inside each `with col1:` / `with col2:` / `with col3:` block
- **Member names / roles** — look for text like `"MEMBER 1"`, `"Vulnerability Assessment"` and replace with your actual names

Example — changing the member card title:
```python
# BEFORE:
st.markdown("<div class='member-card'>...<b>Vulnerability Assessment</b>...")

# AFTER — add your name:
st.markdown("<div class='member-card'>...<b>Ali Hassan</b><br>Vulnerability Assessment...")
```

---

### 3.3 Page 2 — Member 1: Hash Lab

**Where it is:** Search for `elif page == "⚙️ Member 1 — Hash Lab":` (around line 315).

**What you can change:**

- **Number of passwords generated** — find `generate_weak_passwords(extra_count=25)` and change `25`
- **Sample table row count** — find `.head(10)` and change `10` to show more/fewer rows
- **Warning message** — find `st.info("MD5 and SHA-1 are **cryptographically broken**...")`
- **Interactive hash demo** — the password input + algorithm selector at the bottom of the page

---

### 3.4 Page 3 — Member 1: Attack Lab

**Where it is:** Search for `elif page == "⚔️ Member 1 — Attack Lab":` (around line 440).

**What you can change:**

- **Dictionary attack target list** — find `dict_targets = passwords[:5]` and change the slice
- **Max password length for brute-force** — find `max_length=4` and increase it (warning: longer = slower)
- **Character set for brute-force** — find `charset="abcdefghijklmnopqrstuvwxyz0123456789"` and edit
- **Result table** — displayed automatically from attack results

---

### 3.5 Page 4 — Member 2: Cryptanalysis

**Where it is:** Search for `elif page == "📊 Member 2 — Cryptanalysis":` (around line 605).

**What you can change:**

- **Entropy chart** — find `fig, axes = plt.subplots(1, 3, ...)` to change chart layout
- **Feature list for ML prediction** — controlled by `src/analysis.py:password_features()`
- **Hash timing chart** — find `measure_hash_time(hash_md5, ...)` etc. to change benchmark iterations

---

### 3.6 Page 5 — Member 3: Defence System

**Where it is:** Search for `elif page == "🛡️ Member 3 — Defence System":` (around line 755).

**What you can change:**

- **Test passwords for AI detector** — find `test_passwords = [...]` and edit the list
- **Policy check passwords** — find `policy_passwords = [...]` and edit the list
- **Policy rules explanation** — inside `st.expander("📋 Password Policy Rules")`

---

### 3.7 Page 6 — Validation Metrics

**Where it is:** Search for `elif page == "📈 Validation Metrics":` (around line 920).

**What you can change:**

- **Comparison table rows** — find the `rows = [...]` list with MD5/SHA1/bcrypt/Argon2 entries
- **Chart colors** — find `colors = ["#ef4444", "#f97316", "#22c55e", "#3b82f6"]`
- **Key findings text** — find `st.markdown("**Key Findings:**")` block

---

### 3.8 Page 7 — Generate PDF Report

**Where it is:** Search for `elif page == "📄 Generate PDF Report":` (around line 1050).

**What you can change:**

- **Download filename** — find `file_name="cryptanalysis_report.pdf"` and change it
- **Button label** — find `"📄 Generate Full PDF Report"` and change the text
- **What to include** — the actual report content is inside `report_generator.py` (see Section 4)

---

## 4. PDF Report File — `report_generator.py`

`report_generator.py` has **1053 lines**. The main function is:

```python
def generate_report(progress_cb=None) -> bytes:
    ...
```

It returns the PDF as raw bytes which Streamlit downloads.

### Report Page Structure

| Variable / Comment | What it produces |
|--------------------|------------------|
| `story.append(title_page_elements)` | Page 1 — Title Page |
| `# Section 1: Introduction` | Page 2 — Introduction |
| `# Section 2: Member 1 — Hash Lab` | Page 3 — Hash implementations |
| `# Section 3: Member 1 — Attacks` | Page 4 — Attack results |
| `# Section 4: Member 2 — Cryptanalysis` | Pages 5-7 — Entropy, ML, timing |
| `# Section 5: Validation` | Pages 8-10 — Defence, AI, conclusions |

---

### 4.1 How to Change Colors

All PDF colors are defined at the top of `report_generator.py` around **line 41**:

```python
# ── Colors ──────────────────────────────────────────────────
C_DARK    = HexColor("#0f172a")   # Very dark navy — background of title page
C_ACCENT  = HexColor("#3b82f6")   # Blue — headings, dividers
C_GREEN   = HexColor("#22c55e")   # Green — secure items
C_RED     = HexColor("#ef4444")   # Red — weak/broken items
C_ORANGE  = HexColor("#f97316")   # Orange — medium risk
C_YELLOW  = HexColor("#facc15")   # Yellow — warnings
C_LIGHT   = HexColor("#f8fafc")   # Off-white — card backgrounds
C_MUTED   = HexColor("#64748b")   # Grey — secondary text
```

Change the hex codes to change the color scheme throughout the PDF.

---

### 4.2 How to Add / Remove a Section

**To add a new text section inside the PDF:**

Find the location in `report_generator.py` where you want to insert it (use the section comments like `# Section 2:`), then add:

```python
story.append(Paragraph("Your Section Title", styles["h2"]))
story.append(Paragraph(
    "Your paragraph text goes here. This is the body content.",
    styles["body"]
))
story.append(Spacer(1, 12))  # 12pt gap after paragraph
```

**To add a page break:**

```python
story.append(PageBreak())
```

**To remove a section:** Find the block between two `progress_cb(...)` calls and delete the `story.append(...)` lines.

---

### 4.3 How to Change Tables

Tables in the PDF are built using ReportLab's `Table` class. Here is a simple example of how they work:

```python
# A table with a header row + data rows:
data = [
    ["Column 1", "Column 2", "Column 3"],   # Header row
    ["Row 1 A",  "Row 1 B",  "Row 1 C"],   # Data row
    ["Row 2 A",  "Row 2 B",  "Row 2 C"],   # Data row
]

tbl = Table(data, colWidths=[5*cm, 5*cm, 5*cm])
tbl.setStyle(TableStyle([
    ("BACKGROUND",  (0, 0), (-1, 0),  C_ACCENT),     # Header background
    ("TEXTCOLOR",   (0, 0), (-1, 0),  colors.white),  # Header text color
    ("FONTNAME",    (0, 0), (-1, 0),  "Helvetica-Bold"),
    ("FONTSIZE",    (0, 0), (-1, -1), 9),
    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_LIGHT, colors.white]),
    ("GRID",        (0, 0), (-1, -1), 0.5, C_MUTED),
]))
story.append(tbl)
```

**To edit an existing table:** search for the header text (e.g., `"Algorithm"`) in `report_generator.py` to find the right table, then change the data rows.

---

### 4.4 How to Change Charts

Charts are built with **matplotlib** and converted to images embedded in the PDF. Here is the pattern:

```python
fig, ax = plt.subplots(figsize=(6, 3))
ax.bar(["MD5", "SHA-1", "bcrypt"], [0.001, 0.002, 0.30], color=["#ef4444", "#f97316", "#22c55e"])
ax.set_title("Hash Speed Comparison")
ax.set_ylabel("Time (seconds)")
story.append(chart_to_image(fig))   # Converts fig to PDF image
plt.close(fig)
```

**To change chart type** (e.g., bar → line): replace `ax.bar(...)` with `ax.plot(...)`.

**To change colors:** edit the `color=[...]` list.

**To change labels:** edit the first argument list (the category names).

---

## 5. Source Modules — `src/` folder

These are the core logic files. You generally do not need to edit these unless you want to change the underlying algorithms.

| File | Key Functions | What it does |
|------|---------------|--------------|
| `src/hasher.py` | `hash_md5(pwd)`, `hash_sha1(pwd)`, `hash_password(pwd, algo)` | Computes MD5 / SHA-1 hashes |
| `src/secure_hasher.py` | `hash_bcrypt(pwd)`, `hash_argon2(pwd)`, `verify_bcrypt(pwd, hash)` | Secure hashing with salt |
| `src/password_generator.py` | `generate_weak_passwords(extra_count=25)`, `build_dictionary()` | Creates test password dataset |
| `src/dictionary_attack.py` | `dictionary_attack(hashes, dictionary, algo)` | Runs dictionary attack |
| `src/brute_force_attack.py` | `brute_force_attack(hashes, max_length, charset, algo)` | Runs brute-force attack |
| `src/analysis.py` | `shannon_entropy(pwd)`, `password_features(pwd)`, `analyze_patterns(pwds)` | Entropy & pattern analysis |
| `src/ai_weak_detector.py` | `predict_weak_password(pwd)`, `extract_features(pwd)` | AI model prediction |
| `src/password_policy.py` | `check_password_policy(pwd)`, `password_policy_feedback(pwd)` | Policy enforcement |
| `src/validation_metrics.py` | `measure_hash_time(fn, pwd, iterations)`, `validate_improvements(pwds)` | Performance benchmarks |
| `src/metrics.py` | `format_attack_report(results)` | Formats attack result text |

### Example — changing which passwords are generated

Open `src/password_generator.py` and find the `generate_weak_passwords` function. The base list is inside a `WEAK_PASSWORDS` variable — add or remove entries there.

### Example — changing password policy rules

Open `src/password_policy.py` and find `check_password_policy`. The rules are simple `if` checks:

```python
def check_password_policy(password: str) -> bool:
    if len(password) < 8:        # Change 8 to require longer passwords
        return False
    if not any(c.isupper() for c in password):
        return False
    if not any(c.isdigit() for c in password):
        return False
    ...
```

---

## 6. How to Change Project / Member Names

These names appear in both the app sidebar and the PDF title page.

### In `app.py` (sidebar info box):

Search for this block (around line 310):

```python
st.markdown("""
<div class="info-box">
<b>PROJECT</b><br>
Cryptanalysis of Weak Password Hashing Systems and AI-Based Defence Mechanism
</div>
""", unsafe_allow_html=True)
```

Change the project name there.

### In `report_generator.py` (PDF title page):

Search for the title page section (around line 250). You will find:

```python
story.append(Paragraph("CRYPTANALYSIS OF WEAK PASSWORD", title_style))
story.append(Paragraph("HASHING SYSTEMS", title_style))
story.append(Paragraph("& AI-BASED DEFENCE MECHANISM", title_style))
```

And the member/submission info:

```python
story.append(Paragraph("Member 1 — Vulnerability Assessment & Hash Cracking", info_style))
story.append(Paragraph("Member 2 — Cryptanalysis & AI Analysis", info_style))
story.append(Paragraph("Member 3 — Defence System & Validation", info_style))
```

Replace `Member 1`, `Member 2`, `Member 3` with the actual names of your team members.

Also update the institution / date line:

```python
story.append(Paragraph("Academic Research Project  ·  2025", date_style))
```

---

## 7. How to Add a New Page

Here is a step-by-step example of adding a page called "References":

### Step 1 — Add to navigation list

In `app.py`, find `PAGES = [...]` (near line 1157) and add:

```python
PAGES = [
    "🏠 Overview",
    ...
    "📄 Generate PDF Report",
    "📚 References",          # ← add this
]
```

### Step 2 — Add the page function / block

Just before the last line of `app.py` (the `st.sidebar` section), add:

```python
elif page == "📚 References":
    page_header("📚 References", "SOURCES AND FURTHER READING")
    section("Academic References")
    st.markdown("""
    1. Kelsey, J. et al. (2006). *Cryptanalytic Attacks on Pseudorandom Number Generators.*
    2. Provos, N. & Mazieres, D. (1999). *A Future-Adaptable Password Scheme.* USENIX.
    3. Biham, E. & Shamir, A. (1993). *Differential Cryptanalysis of the Data Encryption Standard.*
    """)
```

### Step 3 — Save and refresh

The app will reload automatically. Your new page appears in the sidebar.

---

## 8. Common Editing Tasks (Quick Reference)

| What you want to change | Where to look |
|-------------------------|---------------|
| Project title in browser tab | `app.py` line ~39 — `st.set_page_config(page_title=...)` |
| Sidebar project title "CRYPTLAB" | `app.py` CSS section — find `CRYPTLAB` text |
| App background / card colors | `app.py` lines 50–162 inside `<style>` block |
| Number of test passwords | `app.py` — find `generate_weak_passwords(extra_count=25)` |
| Brute-force max length | `app.py` — find `max_length=4` |
| Dictionary attack targets | `app.py` — find `dict_targets = passwords[:5]` |
| PDF title page member names | `report_generator.py` — search `Member 1` |
| PDF color scheme | `report_generator.py` lines 41–50 — `C_DARK`, `C_ACCENT`, etc. |
| PDF download file name | `app.py` — find `file_name="cryptanalysis_report.pdf"` |
| Password policy minimum length | `src/password_policy.py` — find `len(password) < 8` |
| AI model files | `AI/models/model.pkl` and `AI/models/scaler.pkl` (do not rename) |
| Port number | Workflow command: `--server.port 5000` |

---

*This guide covers the full project as of May 2025. All page line numbers are approximate — use your editor's search (Ctrl+F) to find exact locations.*
