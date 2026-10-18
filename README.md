# Case Study 3: Investigating Memory Evidence (SBT-DF204)

[![Course](https://img.shields.io/badge/Course-SBT--DF204-blue.svg)](https://elearning.icdfa.org)
[![Forensics](https://img.shields.io/badge/Domain-Memory%20Forensics-orange.svg)](https://github.com/volatilityfoundation/volatility)
[![Tool](https://img.shields.io/badge/Framework-Volatility%202.6-green.svg)](https://www.volatilityfoundation.org)

An individual digital forensics case study examining a Windows memory dump (`memdumpWin7.mem`) to reconstruct an evidence-based account of a suspected unauthorized file transfer using Volatility 2 plugins across processes, network connections, registry hives, command history, removable media, and File Explorer ShellBags.

---

## Repository Structure

```text
memdump-forensics-investigation/
├── volatility_commands.sh     # Shell script containing Volatility 2 execution commands and output logs
├── timeline_memory.csv        # Exported chronological event timeline in UTC
├── report/
│   ├── SBTDF204_CaseStudy3_Memory_Forensics_Report.docx
│   └── SBTDF204_CaseStudy3_Evidence_Log_and_Appendices.md
└── README.md                  # Project documentation and investigation summary
```

## Executive Summary

The investigation analyzed a Windows memory image (`memdumpWin7.mem`) to determine whether browser activity, command prompt executions, removable storage devices, and user profiles form a defensible sequence of an unauthorized file transfer.

**Key forensic findings include:**

- **Profile & Image Integrity:** The memory image was validated against candidate profile `Win7SP1x64` using `imageinfo` and corroborated across process and network plugins.

- **Process & Network Correlation:** Analysis via `pslist`/`psscan` and `netscan` isolated process execution trees (such as web browsers or command shells) and associated socket connections to evaluate potential external file-sharing endpoints.

- **Command History & Removable Media:** Command prompt executions recovered via `cmdscan/consoles` were correlated with USB storage artifacts (`USBSTOR`, `DeviceClasses`, `MountedDevices`, and `MountPoints2`) to analyze drive-letter mappings and copy attempts.

- **ShellBags Explorer Traces:** File Explorer access patterns and folder-view timestamps were extracted via `shellbags` to reconstruct folder browsing interactions without confusing folder preferences with file modification events.

## Evidence Acquisition & Preservation Baseline

**To maintain strict chain of custody and forensic integrity:**

- Image Source: Supplied laboratory memory dump (`memdumpWin7.mem`).

- Original File Permissions: Locked to read-only (`chmod 444 memdumpWin7.mem`) prior to processing.

- Working Copy: Working copy (`memdumpWin7_working.mem`) verified via SHA-256 cryptographic hashing to match the original image.

- Analysis Tool: Volatility 2 (`python2 vol.py`) in an isolated Kali Linux virtual machine environment.




























