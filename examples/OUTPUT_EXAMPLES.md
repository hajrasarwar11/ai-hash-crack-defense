# Output Examples for Each File

This document shows **example contents** after running `python main.py`. Your exact hashes and times may vary slightly by machine.

---

## `data/passwords.txt`

One weak password per line:

```
123456
password
12345678
qwerty
abc123
111111
12345
dragon
master
hello
admin
letmein
welcome
monkey
login
pass
test
guest
root
toor
1000
1001
...
```

---

## `data/dictionary.txt`

Weak passwords plus extra dictionary words:

```
123456
password
...
sunshine
princess
football
shadow
superman
```

---

## `data/hashes_md5.txt`

Format: `hash:plaintext` (plaintext kept for lab verification only)

```
e10adc3949ba59abbe56e057f20f883e:123456
5f4dcc3b5aa765d61d8327deb882cf99:password
25d55ad283aa400af464c76d713c07ad:12345678
d8578edf8458ce06fbc5bb76a58c5ca4:qwerty
...
```

---

## `data/hashes_sha1.txt`

Format: `hash:plaintext`

```
7c4a8d09ca3762af61e59520943dc26494f8941b:123456
5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8:password
7c222fb2927d828a93a335852730a9491575ecab:12345678
b1b3774a2a054f6e4e2720c999578343b683b6ec:qwerty
...
```

---

## `output/results/attack_results.txt`

```
HASH CRACKING LAB — RESULTS REPORT
==================================================

Attack type: dictionary
Algorithm: MD5
Targets: 30
Cracked: 30
Success rate: 100.00%
Attempts: 35
Time (seconds): 0.0018

Recovered passwords:
  e10adc3949ba... -> 123456
  5f4dcc3b5aa7... -> password
  ...
--------------------------------------------------

Attack type: brute_force
Algorithm: MD5
Targets: 5
Cracked: 5
Success rate: 100.00%
Attempts: ~1,700,000
Time (seconds): 2.95

Note: Brute-force runs only on passwords with length <= 4 (e.g. pass, test, root)
so the demo finishes in a few seconds. Long passwords like "123456" need
billions of attempts.
...
--------------------------------------------------

OVERALL SUMMARY
Average success rate: 87.50%
Total cracking time: 0.0823 seconds
```

---

## `output/graphs/success_rate_comparison.png`

Bar chart comparing success rate (%) for:

- Dictionary + MD5
- Brute-force + MD5
- Dictionary + SHA1
- Brute-force + SHA1

---

## `output/graphs/cracking_time_comparison.png`

Bar chart of elapsed seconds per attack run.

---

## `output/graphs/attempts_comparison.png`

Bar chart of hash computation attempts (log scale).

---

## Console output (`main.py`)

```
============================================================
  Hash Vulnerability Assessment & Cracking Lab
============================================================

[1] Generating weak password dataset...
    30 passwords -> C:\...\data\passwords.txt

[2] Building dictionary wordlist...
    Dictionary -> C:\...\data\dictionary.txt

[3] Creating MD5 and SHA1 hashes...
Saved 30 MD5 hashes -> C:\...\data\hashes_md5.txt
Saved 30 SHA1 hashes -> C:\...\data\hashes_sha1.txt

[4-7] Running attacks (measuring time and success rate)...

--- Targets loaded (MD5): 30 hashes ---
Running dictionary attack (md5)...
  Cracked: 30 | Time: 0.0018s | Success: 100.0%
Running brute-force attack (md5) on 5 short-password hashes...
  Cracked: 5 | Time: 2.9537s | Success: 100.0%

[8] Results report saved -> ...\output\results\attack_results.txt

[9] Generating matplotlib graphs...
    Graph -> ...\output\graphs\success_rate_comparison.png
    Graph -> ...\output\graphs\cracking_time_comparison.png
    Graph -> ...\output\graphs\attempts_comparison.png

============================================================
  Done! Check the 'data/', 'output/results/', and 'output/graphs/' folders.
============================================================
```

---

## Source modules (no generated output — behavior summary)

| File | Role |
|------|------|
| `src/password_generator.py` | Builds and saves weak password lists |
| `src/hasher.py` | `hash_md5()`, `hash_sha1()` |
| `src/storage.py` | Read/write `hash:password` lines |
| `src/dictionary_attack.py` | Returns `cracked`, `attempts`, `elapsed_seconds`, `success_rate` |
| `src/brute_force_attack.py` | Same result dict; limited charset/length for speed |
| `src/metrics.py` | Formats and saves `attack_results.txt` |
| `src/visualizer.py` | Saves three PNG charts |
