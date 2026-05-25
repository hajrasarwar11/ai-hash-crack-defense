# Hash Vulnerability Assessment & Cracking Lab

Educational Python project demonstrating **weak passwords**, **MD5/SHA1 hashing**, **dictionary attacks**, **brute-force attacks**, timing metrics, success rates, and **matplotlib** charts.

> **Ethics:** Use only on systems and data you own or have permission to test. This lab is for learning — not for attacking real accounts.

## Project structure

```
hash-vuln-assessment/
├── main.py                 # Run the full lab workflow
├── requirements.txt        # matplotlib
├── README.md
├── data/                   # Generated passwords, dictionary, hash files
├── src/
│   ├── password_generator.py
│   ├── hasher.py
│   ├── storage.py
│   ├── dictionary_attack.py
│   ├── brute_force_attack.py
│   ├── metrics.py
│   └── visualizer.py
├── output/
│   ├── results/            # Text reports
│   └── graphs/             # PNG charts
└── examples/
    └── OUTPUT_EXAMPLES.md  # Sample output for every file
```

## Requirements

- Python 3.10 or newer
- pip

## Setup

```bash
cd C:\Users\Lenovo\Projects\hash-vuln-assessment
python -m pip install -r requirements.txt
```

(If you use a virtual environment: `python -m venv venv`, then activate it before installing.)

## Run the lab

```bash
python main.py
```

## What each step does

| Step | Module | Description |
|------|--------|-------------|
| 1 | `password_generator.py` | Creates weak passwords and saves `data/passwords.txt` |
| 2 | `hasher.py` + `storage.py` | MD5/SHA1 hashes saved to `data/hashes_*.txt` |
| 3 | `dictionary_attack.py` | Tries every dictionary word against targets |
| 4 | `brute_force_attack.py` | Tries character combinations (limited for demo speed) |
| 5 | `metrics.py` | Reports time, attempts, and success rate |
| 6 | `visualizer.py` | Bar charts in `output/graphs/` |

## Sample console output

```
============================================================
  Hash Vulnerability Assessment & Cracking Lab
============================================================

[1] Generating weak password dataset...
    30 passwords -> ...\data\passwords.txt

[4-7] Running attacks (measuring time and success rate)...
Running dictionary attack (md5)...
  Cracked: 30 | Time: 0.0021s | Success: 100.0%
```

See `examples/OUTPUT_EXAMPLES.md` for full sample contents of every output file.
