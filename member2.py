"""Runner script to execute Member 2 tasks.

Usage:
    python member2.py
"""
from pathlib import Path

from src.analysis import run_member2


def main():
    project_root = Path(__file__).resolve().parent
    out = run_member2({"project_root": project_root})
    print("Member 2 tasks finished. Summary file:")
    print(out.get("summary_file"))


if __name__ == "__main__":
    main()
