"""
Generate matplotlib charts comparing attack performance.
"""

from pathlib import Path

import matplotlib.pyplot as plt


def plot_attack_comparison(results: list[dict], output_dir: Path) -> list[Path]:
    """
    Create bar charts for success rate and cracking time.

    Args:
        results: List of attack result dictionaries.
        output_dir: Folder where PNG files are saved.

    Returns:
        List of paths to saved image files.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    saved_files = []

    # Build labels like "Dictionary-MD5" for each run
    labels = []
    for r in results:
        attack = r.get("attack_type", "attack").replace("_", " ").title()
        algo = r.get("algorithm", "").upper()
        labels.append(f"{attack}\n{algo}")

    success_rates = [r.get("success_rate", 0) for r in results]
    elapsed_times = [r.get("elapsed_seconds", 0) for r in results]
    attempts = [r.get("attempts", 0) for r in results]

    # --- Chart 1: Success rate ---
    fig1, ax1 = plt.subplots(figsize=(10, 5))
    bars1 = ax1.bar(labels, success_rates, color="#4CAF50", edgecolor="black")
    ax1.set_ylabel("Success Rate (%)")
    ax1.set_title("Hash Cracking Success Rate by Attack Method")
    ax1.set_ylim(0, 105)
    for bar, value in zip(bars1, success_rates):
        ax1.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1,
                 f"{value:.1f}%", ha="center", fontsize=9)
    plt.xticks(rotation=15, ha="right")
    plt.tight_layout()
    path1 = output_dir / "success_rate_comparison.png"
    fig1.savefig(path1, dpi=150)
    plt.close(fig1)
    saved_files.append(path1)

    # --- Chart 2: Cracking time ---
    fig2, ax2 = plt.subplots(figsize=(10, 5))
    bars2 = ax2.bar(labels, elapsed_times, color="#2196F3", edgecolor="black")
    ax2.set_ylabel("Time (seconds)")
    ax2.set_title("Hash Cracking Time by Attack Method")
    for bar, value in zip(bars2, elapsed_times):
        ax2.text(bar.get_x() + bar.get_width() / 2, bar.get_height(),
                 f"{value:.3f}s", ha="center", va="bottom", fontsize=9)
    plt.xticks(rotation=15, ha="right")
    plt.tight_layout()
    path2 = output_dir / "cracking_time_comparison.png"
    fig2.savefig(path2, dpi=150)
    plt.close(fig2)
    saved_files.append(path2)

    # --- Chart 3: Attempts (log scale helps when counts differ a lot) ---
    fig3, ax3 = plt.subplots(figsize=(10, 5))
    ax3.bar(labels, attempts, color="#FF9800", edgecolor="black")
    ax3.set_ylabel("Hash Attempts")
    ax3.set_title("Number of Hash Computations per Attack")
    ax3.set_yscale("log")
    plt.xticks(rotation=15, ha="right")
    plt.tight_layout()
    path3 = output_dir / "attempts_comparison.png"
    fig3.savefig(path3, dpi=150)
    plt.close(fig3)
    saved_files.append(path3)

    return saved_files
