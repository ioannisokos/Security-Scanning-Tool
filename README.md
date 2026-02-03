# Security-Scanning-Tool
# Mini Security Scanner (Context-Based)

## Purpose

This project is a **learning-focused security scanning tool** designed to demonstrate
**basic network exposure analysis and risk thinking**, not vulnerability exploitation.

Its goal is to help understand:
- What services are exposed
- Why certain exposures may matter
- How to think like a security analyst, not a vulnerability scanner

---

## What it does

- Performs a TCP port scan (configurable range)
- Identifies basic services by port
- Attempts simple banner grabbing
- Performs a basic HTTP header check
- Classifies findings using **simple risk context**, such as:
  - Remote access services exposed (SSH / RDP)
  - HTTP services with minimal headers
  - Unknown services with banners
- Outputs results as:
  - JSON (machine-readable)
  - HTML report (human-readable)

Risk levels are **contextual**, not technical severity.

---

## How it works
python scanner.py --target < IP > --output report.html

---

## Disclaimer

⚠️ **Lab and educational use only**

This tool is intended to be used:
- On systems you own
- In controlled lab environments
- With explicit authorization

Running network scans against systems without permission
may be illegal and unethical.

The author takes **no responsibility** for misuse of this software.

Use responsibly.

