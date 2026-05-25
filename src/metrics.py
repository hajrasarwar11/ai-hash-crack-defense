"""
Collect and report attack metrics: time, success rate, and summary text.
"""

from pathlib import Path


def format_attack_report(result: dict) -> str:
    """Turn one attack result dict into a human-readable report block."""
    lines = [
        f"Attack type: {result.get('attack_type', 'unknown')}",
        f"Algorithm: {result.get('algorithm', 'unknown').upper()}",
        f"Targets: {result.get('total_targets', 0)}",
        f"Cracked: {len(result.get('cracked', {}))}",
        f"Success rate: {result.get('success_rate', 0):.2f}%",
        f"Attempts: {result.get('attempts', 0):,}",
        f"Time (seconds): {result.get('elapsed_seconds', 0):.4f}",
        "",
        "Recovered passwords:",
    ]

    cracked = result.get("cracked", {})
    if not cracked:
        lines.append("  (none)")
    else:
        for hash_value, password in cracked.items():
            short_hash = hash_value[:12] + "..."
            lines.append(f"  {short_hash} -> {password}")

    return "\n".join(lines)


def save_results_report(results: list[dict], filepath: Path) -> None:
    """Write all attack results to a single text report file."""
    filepath.parent.mkdir(parents=True, exist_ok=True)

    with open(filepath, "w", encoding="utf-8") as file:
        file.write("HASH CRACKING LAB — RESULTS REPORT\n")
        file.write("=" * 50 + "\n\n")

        for result in results:
            file.write(format_attack_report(result))
            file.write("\n" + "-" * 50 + "\n\n")

        # Overall summary across all runs
        if results:
            avg_success = sum(r["success_rate"] for r in results) / len(results)
            total_time = sum(r["elapsed_seconds"] for r in results)
            file.write("OVERALL SUMMARY\n")
            file.write(f"Average success rate: {avg_success:.2f}%\n")
            file.write(f"Total cracking time: {total_time:.4f} seconds\n")


def compute_overall_success(cracked_count: int, total_targets: int) -> float:
    """Return success rate as a percentage (0–100)."""
    if total_targets == 0:
        return 0.0
    return cracked_count / total_targets * 100
