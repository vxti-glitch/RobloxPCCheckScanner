# RobloxPCCheckScanner

A forensic-grade PowerShell tool for scanning a Windows PC for Roblox cheat traces. Built for investigators and server staff who need a thorough, evidence-based report.

---

## What It Scans

- Windows Registry (cheat-related keys and residual entries)
- Prefetch files (execution history)
- Amcache & ShimCache (program execution artifacts)
- Installed programs
- Kernel drivers (signed and unsigned)
- And more...

---

## Usage

1. Open PowerShell **as Administrator**
2. Run:
```powershell
iex (iwr 'https://raw.githubusercontent.com/vxti-glitch/RobloxPCCheckScanner/refs/heads/main/PCCheckScanner.ps1').Content
```
3. Review the output for flagged entries

---

## Requirements

- Windows 10 / 11
- PowerShell 5.1+
- Administrator privileges

---

## Notes

- This tool is **read-only** — it does not modify or delete anything
- False positives are possible; always review results manually
- Intended for use by server staff and investigators only

---

## Author

Made by **vxti** — [Discord](https://discord.com/users/660631234736554006)
