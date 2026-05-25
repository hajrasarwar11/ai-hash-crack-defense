"""
Hash Vulnerability Assessment Lab — main entry point.

Run this script to:
  1. Generate weak passwords
  2. Create MD5 and SHA1 hashes
  3. Save hashes to text files
  4. Run dictionary and brute-force attacks
  5. Measure time and success rate
  6. Save reports and matplotlib graphs

Usage (from project folder):
    python main.py
"""

from pathlib import Path

from src.brute_force_attack import brute_force_attack
from src.dictionary_attack import dictionary_attack
from src.hasher import hash_md5, hash_password, hash_sha1
from src.metrics import save_results_report
from src.password_generator import (
    build_dictionary,
    generate_weak_passwords,
    save_passwords,
)
from src.storage import save_hashes

from src.visualizer import plot_attack_comparison
# Member 3 imports
from src.secure_hasher import hash_bcrypt, hash_argon2
from src.password_policy import check_password_policy, password_policy_feedback
from src.ai_weak_detector import predict_weak_password
from src.validation_metrics import validate_improvements

# Project paths (main.py lives at project root)
PROJECT_ROOT = Path(__file__).resolve().parent
DATA_DIR = PROJECT_ROOT / "data"
OUTPUT_DIR = PROJECT_ROOT / "output"
GRAPHS_DIR = OUTPUT_DIR / "graphs"
RESULTS_DIR = OUTPUT_DIR / "results"


def create_hash_files(passwords: list[str]) -> dict[str, Path]:
    """
    Hash all passwords with MD5 and SHA1 and write to data/*.txt files.

    Returns:
        Dict mapping algorithm name to file path.
    """
    md5_entries = [(hash_md5(pwd), pwd) for pwd in passwords]
    sha1_entries = [(hash_sha1(pwd), pwd) for pwd in passwords]

    md5_path = DATA_DIR / "hashes_md5.txt"
    sha1_path = DATA_DIR / "hashes_sha1.txt"

    save_hashes(md5_entries, md5_path)
    save_hashes(sha1_entries, sha1_path)

    print(f"Saved {len(md5_entries)} MD5 hashes -> {md5_path}")
    print(f"Saved {len(sha1_entries)} SHA1 hashes -> {sha1_path}")

    return {"md5": md5_path, "sha1": sha1_path}


def load_target_hashes(hash_file: Path) -> list[str]:
    """Read only hash values from a hash file (attacker view)."""
    hashes = []
    with open(hash_file, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()
            if ":" in line:
                hash_part, _ = line.split(":", 1)
                hashes.append(hash_part.strip())
    return hashes


def run_all_attacks(
    hash_files: dict[str, Path],
    dictionary_path: Path,
    passwords: list[str],
) -> list[dict]:
    """Run dictionary and brute-force attacks for each algorithm."""
    all_results = []

    for algorithm, hash_path in hash_files.items():
        targets = load_target_hashes(hash_path)
        print(f"\n--- Targets loaded ({algorithm.upper()}): {len(targets)} hashes ---")

        # Dictionary attack (usually fastest for weak passwords)
        print(f"Running dictionary attack ({algorithm})...")
        dict_result = dictionary_attack(targets, dictionary_path, algorithm)
        all_results.append(dict_result)
        print(f"  Cracked: {len(dict_result['cracked'])} | "
              f"Time: {dict_result['elapsed_seconds']:.4f}s | "
              f"Success: {dict_result['success_rate']:.1f}%")

        # Brute-force only on SHORT passwords (<= 4 chars) so the demo can finish
        # and still show a successful crack. Long passwords need huge search space.
        short_passwords = [pwd for pwd in passwords if len(pwd) <= 4]
        short_hashes = [
            hash_password(pwd, algorithm) for pwd in short_passwords[:5]
        ]
        brute_targets = short_hashes
        print(
            f"Running brute-force attack ({algorithm}) on "
            f"{len(brute_targets)} short-password hashes..."
        )
        brute_result = brute_force_attack(
            brute_targets,
            algorithm,
            charset="abcdefghijklmnopqrstuvwxyz0123456789",
            min_length=1,
            max_length=4,
            max_attempts=2_000_000,
        )
        all_results.append(brute_result)
        print(f"  Cracked: {len(brute_result['cracked'])} | "
              f"Time: {brute_result['elapsed_seconds']:.4f}s | "
              f"Success: {brute_result['success_rate']:.1f}%")

    return all_results



def main() -> None:
    """Orchestrate the full vulnerability assessment workflow, including defense system and validation."""
    print("=" * 60)
    print("  Hash Vulnerability Assessment & Cracking Lab")
    print("=" * 60)

    # Step 1: Generate weak password dataset
    print("\n[1] Generating weak password dataset...")
    passwords = generate_weak_passwords(extra_count=10)
    passwords_path = DATA_DIR / "passwords.txt"
    save_passwords(passwords, passwords_path)
    print(f"    {len(passwords)} passwords -> {passwords_path}")

    # Step 2: Build dictionary for attacks
    print("\n[2] Building dictionary wordlist...")
    dictionary_path = DATA_DIR / "dictionary.txt"
    build_dictionary(passwords, dictionary_path)
    print(f"    Dictionary -> {dictionary_path}")

    # Step 3: Hash and store in text files
    print("\n[3] Creating MD5 and SHA1 hashes...")
    hash_files = create_hash_files(passwords)

    # Step 4–7: Attacks, timing, success rate
    print("\n[4-7] Running attacks (measuring time and success rate)...")
    results = run_all_attacks(hash_files, dictionary_path, passwords)

    # Save text report
    report_path = RESULTS_DIR / "attack_results.txt"
    save_results_report(results, report_path)
    print(f"\n[8] Results report saved -> {report_path}")

    # Generate graphs
    print("\n[9] Generating matplotlib graphs...")
    graph_paths = plot_attack_comparison(results, GRAPHS_DIR)
    for path in graph_paths:
        print(f"    Graph -> {path}")

    # --- Member 3: Defense System & Validation ---
    print("\n[10] Defense System: Secure Hashing, Policy, AI Detection, Validation")
    # Example: Securely hash all passwords with bcrypt and argon2
    bcrypt_hashes = [hash_bcrypt(p) for p in passwords]
    argon2_hashes = [hash_argon2(p) for p in passwords]
    print(f"    {len(bcrypt_hashes)} passwords hashed with bcrypt.")
    print(f"    {len(argon2_hashes)} passwords hashed with argon2.")

    # Example: Password policy enforcement
    print("\n    Password Policy Compliance:")
    for p in passwords[:5]:
        compliant = check_password_policy(p)
        feedback = password_policy_feedback(p)
        print(f"      '{p}': {'OK' if compliant else 'FAIL'}; Feedback: {', '.join(feedback) if feedback else 'All good!'}")

    # Example: AI-based weak password detection
    print("\n    AI Weak Password Detection (probability):")
    for p in passwords[:5]:
        prob = predict_weak_password(p)
        print(f"      '{p}': Weak probability = {prob:.2f}")

    # Validation metrics
    print("\n    Validation Metrics (old vs new):")
    metrics = validate_improvements(passwords)
    print(f"      MD5 avg hash time:    {metrics['md5_time']:.6f} sec")
    print(f"      SHA1 avg hash time:   {metrics['sha1_time']:.6f} sec")
    print(f"      bcrypt avg hash time: {metrics['bcrypt_time']:.6f} sec")
    print(f"      argon2 avg hash time: {metrics['argon2_time']:.6f} sec")
    print(f"      Avg weak prob (AI):   {metrics['avg_weak_prob']:.2f}")
    print(f"      Policy compliance:    {metrics['policy_compliance_rate']*100:.1f}%")

    print("\n" + "=" * 60)
    print("  Done! Check the 'data/', 'output/results/', and 'output/graphs/' folders.")
    print("  See 'examples/OUTPUT_EXAMPLES.md' for sample file contents.")
    print("=" * 60)


if __name__ == "__main__":
    main()
