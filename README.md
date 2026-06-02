
# Sandbox Evasion Technique Classifier

> Multi-environment malware analysis framework using CAPE Sandbox to detect and classify anti-VM, anti-debug, and anti-sandbox evasion techniques through differential execution analysis.

**Author:** Ziad Hany Mohamed Salem  
**Department:** AI & Cybersecurity  
**Date:** May 2026  

---

## Overview

This project builds a dynamic malware analysis lab that proves how real-world malware detects sandbox environments and changes its behavior — or refuses to run entirely. Three malware families were executed across seven analysis runs with deliberately varied hardware configurations (CPU count, RAM size, MAC address, AV state). A custom Python tool then compares CAPE JSON reports across runs to surface evasion-triggered behavioral differences.

**Result:** 18 distinct evasion techniques identified, classified, and mapped to academic taxonomy.

---

## Key Findings

| Malware | Evasion Style | Signatures Detected | Notable Technique |
|---------|--------------|-------------------|-------------------|
| Rombertik | Hardware fingerprinting | 2 | Refuses execution on 1 CPU, changed MAC, or 2GB RAM |
| Emotet | Multi-technique | 20 | Timing attacks, language checks, process injection, mouse detection |
| AgentTesla | AV-aware packing | 27 (Defender OFF) | 0 API calls with Defender ON → 110+ with Defender OFF |

---

## Lab Architecture

```
Host (Windows 10 + VirtualBox 7.0)
│
├── Ubuntu 24.04 VM (192.168.56.102)
│   ├── CAPE Sandbox v2.5
│   ├── MongoDB 7.0  (report storage)
│   └── Python 3.12  (differential_analyzer.py)
│
└── Windows 10 VM (192.168.56.103)
    └── CAPE Agent v0.20 (guest monitor)
```

**Network:** Host-Only Adapter (VM-to-VM) + NAT

---

## Malware Samples

All samples sourced from the [theZoo](https://github.com/ytisf/theZoo) repository for educational and research purposes only.

| Sample | Family | Known For |
|--------|--------|-----------|
| `yfoye_dump.exe` | Rombertik | Anti-analysis, self-destruction on sandbox detection |
| `29D6161522C7F7F21B35401907C702BDDB05ED47.bin` | Emotet | Advanced evasion, process injection |
| `Win32.AgentTesla.exe` | AgentTesla | AV-aware packing, infostealer |

---

## Core Tool — `differential_analyzer.py`

The custom Python script compares CAPE JSON reports across different sandbox configurations to detect evasion-triggered behavioral differences.

```python
import json, sys, os

def load_report(task_id):
    path = "/home/user/CAPEv2/storage/analyses/" + str(task_id) + "/reports/report.json"
    if not os.path.exists(path):
        print("Report not found for task " + str(task_id))
        return None
    with open(path) as f:
        return json.load(f)

def extract_api_calls(report):
    calls = []
    try:
        for process in report["behavior"]["processes"]:
            for call in process["calls"]:
                calls.append(call["api"])
    except:
        pass
    return calls

def extract_signatures(report):
    sigs = []
    try:
        for sig in report["signatures"]:
            sigs.append(sig["name"])
    except:
        pass
    return sigs

def compare_reports(task1, task2):
    r1 = load_report(task1)
    r2 = load_report(task2)
    if not r1 or not r2:
        return

    apis1 = set(extract_api_calls(r1))
    apis2 = set(extract_api_calls(r2))
    sigs1 = set(extract_signatures(r1))
    sigs2 = set(extract_signatures(r2))

    print("=== Differential Analysis: Task " + str(task1) + " vs Task " + str(task2) + " ===")
    print("API calls only in Task " + str(task1) + ": " + str(apis1 - apis2))
    print("API calls only in Task " + str(task2) + ": " + str(apis2 - apis1))
    print("Signatures in Task " + str(task1) + ": " + str(sigs1))
    print("Signatures in Task " + str(task2) + ": " + str(sigs2))

    if sigs1 != sigs2 or apis1 != apis2:
        print("Evasion detected: YES")
    else:
        print("Evasion detected: NO")

compare_reports(sys.argv[1], sys.argv[2])
```

**Usage:**
```bash
# Clone the repo
git clone https://github.com/ZiadHany99/sandbox-evasion-classifier.git
cd sandbox-evasion-classifier

# Run a comparison between two CAPE task IDs
python3 differential_analyzer.py 18 19
```

---

## Experimental Runs

| Run | Task | Malware | Config Change | Result | Key Finding |
|-----|------|---------|--------------|--------|-------------|
| 1 | 18 | Rombertik | Baseline (2 CPU, 4GB, original MAC) | Evasion YES — Crashed | Detected sandbox via `NtQuerySystemInformation`, self-terminated |
| 2 | 19 | Rombertik | CPU = 1 | Evasion YES — Silent | 0 API calls — refused to run |
| 3 | 20 | Rombertik | MAC changed | Evasion YES — Silent | 0 API calls — non-standard MAC detected |
| 4 | 21 | Rombertik | RAM = 2GB | Evasion YES — Silent | 0 API calls — low RAM flagged as sandbox |
| 5 | 22 | Emotet | Defender OFF | Evasion YES — Active | 20 signatures: `stealth_timeout`, `injection_rwx`, `language_check_registry` |
| 6 | 23 | AgentTesla | Defender ON | Blocked by AV | 0 API calls — Defender killed process before execution |
| 7 | 24 | AgentTesla | Defender OFF | Evasion YES — Active | 27 signatures: `disables_uac`, `antisandbox_restart`, `amsi_enumeration` |

---

## Evasion Technique Taxonomy

18 distinct techniques classified across 6 categories, mapped to academic references:

| Technique | Malware | Category | Academic Reference |
|-----------|---------|----------|--------------------|
| CPU Count Check | Rombertik | Anti-VM | Sandprint [1] |
| MAC Address Check | Rombertik | Anti-VM | Sandprint [1] |
| RAM Size Check | Rombertik | Anti-VM | Sandprint [1] |
| VM Fingerprinting (`NtQuerySystemInformation`) | Rombertik | Anti-VM | Egele et al. [2] |
| Memory Availability Check | AgentTesla | Anti-VM | Egele et al. [2] |
| Screen Resolution Check (`GetSystemMetrics`) | Emotet | Anti-VM | Sandprint [1] |
| Self-Termination (`exec_crash`) | Rombertik | Anti-Analysis | Egele et al. [2] |
| Debugger Check (`IsDebuggerPresent`) | Emotet, AgentTesla | Anti-Debug | Egele et al. [2] |
| Exception Handler (`SetUnhandledExceptionFilter`) | Rombertik, AgentTesla | Anti-Debug | Egele et al. [2] |
| Timing Attack (`NtDelayExecution`) | Emotet, AgentTesla | Anti-Sandbox | Sandprint [1] |
| Human Interaction Check (`GetCursorPos`) | Emotet | Anti-Sandbox | Sandprint [1] |
| Language Check (`GetKeyboardLayout`) | Emotet, AgentTesla | Anti-Sandbox | Sandprint [1] |
| AMSI Enumeration | AgentTesla | Anti-AV | Egele et al. [2] |
| Packer High Entropy | AgentTesla | Anti-AV | Egele et al. [2] |
| Sandbox Restart Detection | AgentTesla | Anti-Sandbox | Sandprint [1] |
| Process Injection (`injection_rwx`) | Emotet, AgentTesla | Stealth | Egele et al. [2] |
| UAC Bypass (`disables_uac`) | AgentTesla | Privilege Escalation | Egele et al. [2] |
| WMI Abuse (`WbemLocator`) | AgentTesla | Stealth | Egele et al. [2] |

---

## Tools & Stack

| Tool | Purpose |
|------|---------|
| CAPE Sandbox v2.5 | Dynamic malware analysis and API call monitoring |
| Python 3.12 | Differential analyzer script |
| MongoDB 7.0 | CAPE report storage backend |
| VirtualBox 7.0 | Hypervisor for multi-VM lab setup |
| Windows 10 (guest) | Malware execution environment |
| Ubuntu 24.04 (host) | CAPE server OS |

---

## References

[1] Yokoyama, A. et al. (2016). *Sandprint: Fingerprinting Malware Sandboxes to Provide Intelligence for Sandbox Evasion.* RAID 2016. Springer.  
[2] Egele, M. et al. (2012). *A Survey on Automated Dynamic Malware-Analysis Techniques and Tools.* ACM Computing Surveys, 44(2).

---

## Disclaimer

This project was conducted in a fully isolated lab environment for academic and educational research purposes only. All malware samples were handled in air-gapped virtual machines. No malicious code was deployed against any real system or network. This work is intended to improve defensive security understanding.
