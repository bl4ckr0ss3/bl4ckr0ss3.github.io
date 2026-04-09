---
title: "Malware Family — Short Description of Campaign"
date: {{ .Date }}
draft: true

# ── Core metadata ──────────────────────────────────────
malware_family: "FamilyName / PE32"   # e.g. "RedLine / Win32"
platform: "Windows 10 x64"
severity: "high"                       # critical | high | medium | low
weight: 1                              # report number (001, 002, ...) — lower = newer on list

# ── Tags (used for colored badges) ────────────────────
# Available: stealer, rat, ransomware, loader, dropper, rootkit, backdoor, worm
tags:
  - stealer
  - loader

# ── Sample hashes ──────────────────────────────────────
sha256: "aabbccdd..."
md5:    "11223344..."

# ── Defanged IOCs (shown in the IOC summary box) ───────
iocs:
  - type: "C2"
    value: "185.220.101[.]47:80"
  - type: "URL"
    value: "hxxp://example[.]com/gate.php"
  - type: "Mutex"
    value: "MUTEX_NAME_HERE"
  - type: "Domain"
    value: "evil[.]example[.]com"

# ── MITRE ATT&CK ───────────────────────────────────────
mitre:
  - id: "T1059.003"
    name: "Windows Command Shell"
  - id: "T1055"
    name: "Process Injection"
  - id: "T1082"
    name: "System Information Discovery"
---

## Executive Summary

Brief 2-3 sentence overview of what this malware is, how it was distributed, and what it does. Write this for someone who may not read the full report.

## Sample Information

| Field       | Value                     |
|-------------|---------------------------|
| File Name   | `sample.exe`              |
| File Type   | PE32 executable           |
| Size        | 512 KB                    |
| Compiler    | MSVC / .NET / AutoIt      |
| Packer      | UPX / None                |
| First Seen  | 2025-01-01 (VirusTotal)   |

## Static Analysis

What did you find by looking at the file without running it? Imports, strings, packer detection, PE header anomalies.

```
; Example: interesting strings found
http://185.220.101[.]47/gate.php
SOFTWARE\Microsoft\Windows\CurrentVersion\Run
SELECT * FROM Win32_ComputerSystem
```

## Dynamic Analysis

What happened when you ran it in a sandbox or VM? File system changes, registry keys, network connections, process spawning.

### Filesystem Activity

- Created: `%APPDATA%\malware\config.bin`
- Deleted: original executable after execution

### Registry Activity

- Added: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` → persistence

### Network Activity

Describe C2 communication, beacon intervals, protocols used.

## Code Analysis / Reverse Engineering

Interesting functions, algorithms, obfuscation techniques. Include Ghidra/x64dbg screenshots if you have them (add to `static/img/`).

## YARA Rule

```yara
rule MalwareFamily_Campaign {
    meta:
        description = "Detects MalwareFamily used in [campaign]"
        author      = "Your Name"
        date        = "2025-01-01"
        severity    = "high"

    strings:
        $s1 = "MUTEX_NAME_HERE" ascii
        $s2 = { 4D 5A 90 00 }  // MZ header after unpack

    condition:
        uint16(0) == 0x5A4D and all of them
}
```

## Conclusion

Wrap up: what's significant about this sample, who might be targeted, any links to known threat actors or campaigns.

## References

- [VirusTotal Report](https://www.virustotal.com/gui/file/HASH)
- [Any.run Sandbox](https://any.run/report/HASH)
- [MITRE ATT&CK](https://attack.mitre.org/)
