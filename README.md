# RobloxPCCheckScanner

A forensic PC scanner built for Roblox competitive league administrators to investigate players for evidence of cheating software. Not an anti-cheat — a forensic audit tool. Built by **vxti**.

---

## Download

Go to the [Releases](../../releases) page and download the latest `PCCheckScanner.exe`.

No installation required. Single `.exe`, no dependencies.

---

## Requirements

- Windows 10 or Windows 11 (64-bit)
- Must be run as **Administrator**
- Internet connection on first run (downloads forensic tools automatically)

---

## How To Use

1. Download `PCCheckScanner.exe` from [Releases](../../releases)
2. Right-click → **Run as administrator**
3. Click **START SCAN**
4. Wait for all 14 phases to complete
5. Review findings in the **Overview** tab

---

## What It Scans

| Phase | What It Checks |
|-------|----------------|
| 01 | Environment setup, tool download |
| 02 | Windows Defender status, exclusions, threat history |
| 03 | Critical Windows service status |
| 04 | USN Journal integrity |
| 05 | Virtual machine / Hyper-V detection |
| 06 | Amcache execution hash records |
| 07 | Registry execution logs (BAM, MuiCache, ShellBags, RunMRU) |
| 08 | Prefetch file analysis |
| 09 | Running processes, loaded DLLs, USB history, PowerShell history |
| 10 | UserAssist GUI execution history |
| 11 | Installed programs blacklist check |
| 12 | Kernel driver audit |
| 13 | SHA256 hash scan against known cheat file database |
| 14 | Deleted file recovery via MFT, LNK files, Jump Lists |

---

## Cheat Database

Detects the following by SHA256 hash — flags evidence even if the files have been deleted:

- Matcha (Usermode, Kernel, updater, login loader, auth)
- Severe (main, updater, auth)
- Matrix (newui / oldui)

---

## Findings

| Badge | Meaning |
|-------|---------|
| 🔴 CONFIRMED | Direct hash match or blacklisted artifact found |
| 🟠 SUSPECTED | Possible match — requires manual review |
| 🟡 WARNING | Suspicious configuration (e.g. Defender exclusions) |
| 🟢 CLEAN | Check passed |

---

## First Run

On first run the scanner will automatically download Eric Zimmerman's forensic tools to `%USERPROFILE%\Downloads\EZTools`. These are free, open source forensic utilities used by professional investigators. An internet connection is required for this step. Subsequent runs use the cached tools and do not need internet access.

---

## Cheat Submissions

Got a cheat loader, executor, or injector you want added to the detection database? DM me on Discord and I'll add support for it in the next update.

**Discord:** vxti

---

## Disclaimer

This tool is intended for use by server administrators and league staff with explicit permission from the player being scanned. Do not use on systems you do not have authorization to access.

---

Made by **vxti**
