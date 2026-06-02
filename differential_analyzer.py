"""
differential_analyzer.py
-------------------------
Compares CAPE Sandbox JSON reports across two analysis runs to detect
evasion-triggered behavioral differences in API calls and signatures.

Author  : Ziad Hany Mohamed Salem
Project : Sandbox Evasion Technique Classifier
Dept.   : Cybersecurity
Date    : May 2026

Usage:
    python3 differential_analyzer.py <task_id_1> <task_id_2>

Example:
    python3 differential_analyzer.py 18 19

Note: Update CAPE_REPORTS_PATH below to match your CAPE installation path.
"""

import json
import sys
import os

# ── Configuration ─────────────────────────────────────────────────────────────
CAPE_REPORTS_PATH = "/home/user/CAPEv2/storage/analyses"


# ── Report Loading ─────────────────────────────────────────────────────────────
def load_report(task_id):
    """Load and return a CAPE JSON report for the given task ID."""
    path = os.path.join(CAPE_REPORTS_PATH, str(task_id), "reports", "report.json")
    if not os.path.exists(path):
        print(f"[!] Report not found: {path}")
        return None
    with open(path) as f:
        return json.load(f)


# ── Feature Extraction ─────────────────────────────────────────────────────────
def extract_api_calls(report):
    """Extract all API call names from a CAPE report's behavioral analysis."""
    calls = []
    try:
        for process in report["behavior"]["processes"]:
            for call in process["calls"]:
                calls.append(call["api"])
    except (KeyError, TypeError):
        pass
    return calls


def extract_signatures(report):
    """Extract all CAPE signature names triggered in a report."""
    sigs = []
    try:
        for sig in report["signatures"]:
            sigs.append(sig["name"])
    except (KeyError, TypeError):
        pass
    return sigs


# ── Differential Analysis ──────────────────────────────────────────────────────
def compare_reports(task1, task2):
    """Compare two CAPE reports and print behavioral differences."""
    r1 = load_report(task1)
    r2 = load_report(task2)

    if not r1 or not r2:
        print("[!] Cannot compare — one or both reports missing.")
        return

    apis1 = set(extract_api_calls(r1))
    apis2 = set(extract_api_calls(r2))
    sigs1 = set(extract_signatures(r1))
    sigs2 = set(extract_signatures(r2))

    print(f"\n{'='*60}")
    print(f"  Differential Analysis: Task {task1} vs Task {task2}")
    print(f"{'='*60}")

    print(f"\n[+] API calls unique to Task {task1}:")
    print(f"    {apis1 - apis2 or 'None'}")

    print(f"\n[+] API calls unique to Task {task2}:")
    print(f"    {apis2 - apis1 or 'None'}")

    print(f"\n[+] Common API calls:")
    print(f"    {apis1 & apis2 or 'None'}")

    print(f"\n[+] Signatures in Task {task1}:")
    print(f"    {sigs1 or 'None'}")

    print(f"\n[+] Signatures in Task {task2}:")
    print(f"    {sigs2 or 'None'}")

    print(f"\n{'='*60}")
    if sigs1 != sigs2 or apis1 != apis2:
        print("  Evasion detected: YES — behavioral difference confirmed")
    else:
        print("  Evasion detected: NO — identical behavior across runs")
    print(f"{'='*60}\n")


# ── Entry Point ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 differential_analyzer.py <task_id_1> <task_id_2>")
        sys.exit(1)

    compare_reports(sys.argv[1], sys.argv[2])
