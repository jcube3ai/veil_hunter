# VeilHunter

<p align="center">
  <img src="https://img.shields.io/badge/platform-Windows-blue?style=flat-square" />
  <img src="https://img.shields.io/badge/PowerShell-5.1%2B-blue?style=flat-square&logo=powershell" />
  <img src="https://img.shields.io/badge/MITRE%20ATT%26CK-mapped-red?style=flat-square" />
  <img src="https://img.shields.io/badge/license-Apache%202.0-green?style=flat-square" />
</p>

**Windows Threat Hunting Library — MITRE ATT&CK Mapped**

VeilHunter is a PowerShell-based threat hunting toolkit for detecting adversary persistence, lateral movement, defense evasion, credential theft, C2 communication, ransomware staging, and LOLBin abuse on Windows hosts.

All findings are printed directly to the PowerShell console with colour-coded severity, structured field-by-field output, and MITRE ATT&CK technique IDs on every line. A narrow GUI launcher sits alongside your console so you can select hunt modules without losing your output window.

---

## Library Overview

| Script | Category | Hunt Modules |
|--------|----------|-------------|
| `VH_Master_Launcher.ps1` | **Launcher** | Opens all hunters from a single menu |
| `Veil_Hunter_v2.ps1` | Persistence | Scheduled tasks, services, WMI, BITS, run keys, IFEO, DLL hijacks, startup folders, Winlogon, LSA |
| `Task_Hunter_v2.ps1` | Persistence | Scheduled tasks, AT jobs, task XML LOLBin scan |
| `service_installs_v2.ps1` | Persistence | Service installs, start type changes, unsigned service binaries |
| `malvertising_payload_hunter_v2.ps1` | Initial Access | Internet-sourced files (Zone.ID), RMM tool footprints, task LOLBin refs |
| `VH_Credential_Hunter.ps1` | Credential Access | LSASS access, SAM dumps, DPAPI, browser creds, Kerberoasting |
| `VH_Lateral_Hunter.ps1` | Lateral Movement | SMB admin shares, WMI lateral, RDP, Pass-the-Hash, PSExec |
| `VH_Defense_Evasion_Hunter.ps1` | Defense Evasion | AMSI bypass, Defender tampering, log clearing, masquerading, timestomping |
| `VH_C2_Exfil_Hunter.ps1` | C2 + Exfiltration | Suspicious connections, BITS abuse, named pipe C2, DNS beaconing, cloud exfil staging |
| `VH_PreRansom_Hunter.ps1` | Impact | Shadow copy deletion, backup tampering, ransom note drops, ransomware extensions, bcdedit |
| `VH_LOLBin_Hunter.ps1` | Execution | 24 LOLBins with chain analysis, encoded command decoding, unsigned staging binaries |

---

## Prerequisites

| Requirement | Detail |
|-------------|--------|
| OS | Windows 10 / Windows Server 2016 or later |
| PowerShell | 5.1 or higher |
| Privileges | Some hunts require an elevated (Administrator) prompt — run as Admin for full coverage |
| Execution Policy | Set before running any script |

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
Get-ChildItem . -Recurse | Unblock-File
```

---

## Quick Start

### Option 1 — Master Launcher (Recommended)

Drop all scripts into the same folder, then run the launcher. It detects which hunters are present and lets you select and launch them from a single menu.

```powershell
.\VH_Master_Launcher.ps1
```

The launcher opens a small panel in the top-right corner of your screen. Check the boxes for the hunters you want and click **Launch Selected Hunters**. Output from each hunter prints to the console behind the panel.

To run every available hunter headless and save all results to CSV automatically:

1. Open the launcher
2. Click **Run All (Headless)**
3. Results are saved to a timestamped folder next to the scripts

### Option 2 — Run Individual Scripts

Each script can be run standalone. Every script supports a GUI launcher mode (default) and a headless CLI mode (`-Headless`).

```powershell
# GUI launcher (select modules from the panel, output to console)
.\Veil_Hunter_v2.ps1

# Headless — run all modules, print to console
.\Veil_Hunter_v2.ps1 -Headless -All

# Headless — specific modules only
.\Veil_Hunter_v2.ps1 -Headless -RunWMI -RunRegistry

# Headless — export results to CSV
.\Veil_Hunter_v2.ps1 -Headless -All -OutputPath C:\Hunts\results.csv
```

---

## Console Output Format

All findings print to the console using a consistent, readable format. Each finding occupies multiple lines — one field per line — so nothing gets cut off. Colour coding is applied by severity.

```
[HIGH] [T1053.005] Scheduled Task
       Artifact : SIGIL_Test_Task
       Path: \SIGIL_Test\ | Author: DESKTOP\JohnC | RunAs: SYSTEM
       RunLevel: Highest | Action: powershell.exe -EncodedCommand dGVzdA==
       Path     : C:\Windows\System32\Tasks\SIGIL_Test\SIGIL_Test_Task

[MED]  [T1543.003] Service Registry
       Artifact : Service: MySuspiciousService
       Type: OwnProcess(16) | Start: Auto(2) | Signature: NotSigned
       Reasons: Auto-start unsigned binary
       Path     : C:\Users\JohnC\AppData\Local\Temp\svc.exe
```

**Severity colours:**

| Colour | Level | Meaning |
|--------|-------|---------|
| 🔴 Red | `[HIGH]` | Confirmed malicious pattern or strong indicator |
| 🟡 Yellow | `[MED]` | Suspicious — investigate further |
| ⚫ Gray | `[INFO]` | Notable but likely benign — context dependent |

---

## Script Reference

---

### VH_Master_Launcher.ps1

The entry point for the entire library. Scans the current directory for all VeilHunter scripts, shows which are present, and provides two run modes.

**GUI launcher mode:** Select hunters by checkbox and click Launch. Each hunter opens its own GUI panel alongside the shared console.

**Headless mode:** Click "Run All (Headless)" to execute every available hunter sequentially and save CSV results to a timestamped output folder.

```powershell
.\VH_Master_Launcher.ps1
```

---

### Veil_Hunter_v2.ps1 — Core Persistence Hunter

The main multi-module persistence scanner. Covers 8 technique categories in a single script.

**Hunt modules:**

| Module | MITRE ID | What It Hunts |
|--------|----------|---------------|
| Scheduled Tasks | T1053.005 | Event log (EID 106/140/141/200/201) + live task enumeration with corrected whitelist |
| Service Tampering | T1543.003 | Event log (EID 7045/7040/7036/7034/7031) + registry scan for suspicious ImagePath |
| WMI Subscriptions | T1546.003 | Event log (EID 5858-5861) + live `root\subscription` namespace query |
| BITS Jobs | T1197 | Event log + `Get-BitsTransfer` for active transfers to non-Microsoft URLs |
| Run Keys + IFEO | T1547.001 / T1546.012 | 7 Run key paths + IFEO Debugger + GlobalFlag silent exit monitoring |
| DLL Hijack + AppInit | T1574.001 / T1546.010 | COM InprocServer32 paths + AppInit_DLLs with signature checking |
| Startup Folders | T1547.009 | All user/system startup paths with signature validation |
| Winlogon + LSA | T1547.004 / T1547.002 | Userinit/Shell value tampering, Notify DLLs, LSA auth packages |

**Usage:**

```powershell
# GUI launcher (default)
.\Veil_Hunter_v2.ps1

# Headless — all modules
.\Veil_Hunter_v2.ps1 -Headless -All

# Headless — specific modules
.\Veil_Hunter_v2.ps1 -Headless -RunWMI -RunRegistry -RunDLL

# Export to CSV
.\Veil_Hunter_v2.ps1 -Headless -All -OutputPath C:\Hunts\core.csv
```

**Parameters:**

```
-Headless        Run without GUI — all output to console
-All             Run all 8 hunt modules
-RunTasks        Scheduled tasks only
-RunServices     Service tampering only
-RunWMI          WMI subscriptions only
-RunBITS         BITS jobs only
-RunRegistry     Run keys + IFEO only
-RunDLL          DLL hijack + AppInit only
-RunStartup      Startup folders only
-RunWinlogon     Winlogon + LSA only
-OutputPath      CSV export path
```

---

### Task_Hunter_v2.ps1 — Scheduled Task Deep Dive

Focused scheduled task and AT job hunter with an adjustable lookback window and raw task XML scanning.

**Hunt modules:**

| Module | MITRE ID | What It Hunts |
|--------|----------|---------------|
| Scheduled Tasks | T1053.005 | Event log EID 106/140/141/200/201 + live `Get-ScheduledTask` with corrected whitelist filtering |
| AT Jobs | T1053.002 | Legacy `Win32_ScheduledJob` WMI class |
| Task XML LOLBin Scan | T1053.005 | Raw XML task files modified recently, flagging LOLBin executable references |

**Usage:**

```powershell
# GUI launcher
.\Task_Hunter_v2.ps1

# Headless — 72 hour lookback
.\Task_Hunter_v2.ps1 -Headless -LookbackHours 72

# Headless — 1 week lookback with CSV export
.\Task_Hunter_v2.ps1 -Headless -LookbackHours 168 -OutputPath C:\Hunts\tasks.csv
```

**Parameters:**

```
-Headless          Run without GUI
-LookbackHours     How far back to check event logs (default: 72)
-OutputPath        CSV export path
```

---

### service_installs_v2.ps1 — Service Installation Hunter

Hunts malicious service installations and configuration changes across both the event log and the services registry.

**What It Hunts:**

| Event ID | Description | Severity |
|----------|-------------|----------|
| 7045 | New service installed | HIGH |
| 7040 | Service start type changed (elevated to HIGH if changing to auto-start) | MED |
| 7036 | Service state changed | INFO |
| 7034 | Service crashed unexpectedly | MED |
| 7031 | Service terminated unexpectedly | MED |

Registry scan additionally checks for: suspicious ImagePath locations (Temp, AppData, ProgramData), unsigned or missing binaries, kernel/filesystem drivers outside standard Windows paths, and auto-start services with unsigned executables.

**Usage:**

```powershell
# Run immediately (no GUI — outputs directly to console)
.\service_installs_v2.ps1

# Custom lookback and CSV export
.\service_installs_v2.ps1 -LookbackHours 168 -OutputPath C:\Hunts\services.csv
```

**Parameters:**

```
-LookbackHours    How far back to check event logs (default: 72)
-OutputPath       CSV export path
```

---

### malvertising_payload_hunter_v2.ps1 — Malvertising + RMM Hunter

Detects files delivered via malvertising or drive-by attacks, RMM tool footprints, and recently modified task files referencing LOLBins.

**What It Hunts:**

- **Internet-sourced files** — Scans 11 common drop locations for files with `Zone.Identifier` ADS `ZoneId=3` (internet zone). Each hit is SHA256 hashed for IOC lookup and Authenticode checked. Covers 30 file extensions.
- **RMM tool footprints** — Checks service registry and installed software for 30+ RMM tools (AnyDesk, ScreenConnect, Atera, NinjaRMM, ConnectWise, Bomgar, LogMeIn, Kaseya, MeshCentral, Action1, and more).
- **Task XML LOLBin references** — Scans `%WINDIR%\System32\Tasks` for recently modified task XML files that reference LOLBin executables.

**Usage:**

```powershell
# Default 7-day lookback
.\malvertising_payload_hunter_v2.ps1

# 14-day lookback with additional paths and CSV export
.\malvertising_payload_hunter_v2.ps1 -LookbackDays 14 -ScanPaths "D:\Shared","C:\Staging" -OutputPath C:\Hunts\malad.csv
```

**Parameters:**

```
-LookbackDays    Days back to check file modification times (default: 7)
-OutputPath      CSV export path
-ScanPaths       Additional directories to include in the file scan
```

---

### VH_Credential_Hunter.ps1 — Credential Theft Hunter

Hunts credential access techniques across the event log, filesystem, and registry.

**Hunt modules:**

| Module | MITRE ID | What It Hunts |
|--------|----------|---------------|
| LSASS Access | T1003.001 | Security EID 4656/4663 matching lsass.exe + known dumper tool binaries on disk (mimikatz, procdump, nanodump, etc.) |
| SAM/Hive Dumps | T1003.002 | Security EID 4656/4663 on SAM/SECURITY/SYSTEM hives + `.hive` dump files on disk |
| DPAPI + Browser Creds | T1555 | DPAPI master key path enumeration, Chrome/Edge/Firefox credential DB locations, Windows Credential Manager vault entries |
| Credential Files | T1552.001 | Files matching credential naming patterns (password, creds, id_rsa, .pfx, .kdbx, .pem, .ppk) in common user paths |
| Kerberos Abuse | T1558 | EID 4769 with RC4 encryption (Kerberoasting signal) + EID 4768 with pre-auth disabled (AS-REP roasting) |

**Usage:**

```powershell
# GUI launcher
.\VH_Credential_Hunter.ps1

# Headless — all modules
.\VH_Credential_Hunter.ps1 -Headless -All

# Headless — specific modules with CSV export
.\VH_Credential_Hunter.ps1 -Headless -LookbackHours 48 -OutputPath C:\Hunts\creds.csv
```

**Parameters:**

```
-Headless          Run without GUI
-All               Run all 5 hunt modules
-LookbackHours     Event log lookback window (default: 72)
-OutputPath        CSV export path
```

---

### VH_Lateral_Hunter.ps1 — Lateral Movement Hunter

Detects adversary movement between systems using common lateral movement techniques.

**Hunt modules:**

| Module | MITRE ID | What It Hunts |
|--------|----------|---------------|
| SMB / Admin Shares | T1021.002 | EID 5140/5145 (admin share access: C$, ADMIN$, IPC$) + EID 4648 (explicit credential use) |
| WMI Lateral Movement | T1047 | WMI-Activity log for Win32_Process/Win32_Service operations + EID 4688 chains showing wmiprvse.exe spawning cmd/powershell |
| RDP Anomalies | T1021.001 | RDP connection log EID 1149/4625 + registry check for RDP enabled state |
| Pass-the-Hash | T1550.002 | EID 4624 Type-3 NTLM network logons from non-machine accounts with a remote source IP |
| PSExec / Remote Exec | T1569.002 | PSEXESVC/paexec/remcom service registry keys + EID 7045 for PSExec-style service installs |

**Usage:**

```powershell
# GUI launcher
.\VH_Lateral_Hunter.ps1

# Headless — all modules
.\VH_Lateral_Hunter.ps1 -Headless -All -OutputPath C:\Hunts\lateral.csv
```

**Parameters:**

```
-Headless          Run without GUI
-All               Run all 5 hunt modules
-LookbackHours     Event log lookback window (default: 72)
-OutputPath        CSV export path
```

---

### VH_Defense_Evasion_Hunter.ps1 — Defense Evasion Hunter

Detects techniques adversaries use to avoid detection and disable security tooling.

**Hunt modules:**

| Module | MITRE ID | What It Hunts |
|--------|----------|---------------|
| AMSI Bypass | T1562.001 | AMSI provider registry tampering + ScriptBlock logging disabled + Module logging disabled |
| Defender Tampering | T1562.001 | DisableAntiSpyware, DisableRealtimeMonitoring, and Defender exclusion paths pointing to staging locations |
| Event Log Tampering | T1070.001 | EID 1102 (Security log cleared), EID 104 (System log cleared), EID 1100 (EventLog service shutdown) |
| Masquerading | T1036 | Windows process names (svchost, lsass, csrss, etc.) in non-system paths + lookalike system directories |
| Process Injection | T1055 | AppInit_DLLs populated + unsigned DLLs recently written to System32 |
| Timestomping | T1070.006 | PE compile timestamp vs filesystem mtime discrepancy greater than 365 days |

**Usage:**

```powershell
# GUI launcher
.\VH_Defense_Evasion_Hunter.ps1

# Headless — all modules
.\VH_Defense_Evasion_Hunter.ps1 -Headless -All -OutputPath C:\Hunts\evasion.csv
```

**Parameters:**

```
-Headless          Run without GUI
-All               Run all 6 hunt modules
-LookbackHours     Event log lookback window (default: 72)
-OutputPath        CSV export path
```

---

### VH_C2_Exfil_Hunter.ps1 — C2 and Exfiltration Hunter

Hunts active command-and-control communication and data exfiltration staging.

**Hunt modules:**

| Module | MITRE ID | What It Hunts |
|--------|----------|---------------|
| Suspicious Connections | T1071 | Active TCP connections from suspicious processes (powershell, mshta, rundll32, etc.) or on unusual ports (4444, 5555, 1337, 31337, 9001, etc.) |
| BITS Abuse | T1197 | BITS client event log for transfers to non-Microsoft URLs + active `Get-BitsTransfer` jobs |
| Named Pipe C2 | T1572 | Named pipe enumeration against known C2 framework patterns (Cobalt Strike msagent_, mojo., Meterpreter, Sliver, Empire, Havoc) |
| DNS Beaconing | T1071.004 | DNS client cache for low-TTL entries to suspicious TLDs (.ru, .cn, .tk, .xyz, .pw, etc.) + DNS over HTTPS enabled check |
| Cloud Exfil Staging | T1048 | Archive and database files (zip, rar, 7z, db, pst, kdbx) recently written to OneDrive, Dropbox, Google Drive, Box, iCloud sync folders |

**Usage:**

```powershell
# GUI launcher
.\VH_C2_Exfil_Hunter.ps1

# Headless — all modules
.\VH_C2_Exfil_Hunter.ps1 -Headless -All -OutputPath C:\Hunts\c2.csv
```

**Parameters:**

```
-Headless          Run without GUI
-All               Run all 5 hunt modules
-LookbackHours     Event log lookback window (default: 72)
-OutputPath        CSV export path
```

---

### VH_PreRansom_Hunter.ps1 — Pre-Ransomware Indicators Hunter

Detects the preparation steps adversaries take before deploying ransomware. Running this immediately after an alert gives you early warning before encryption begins.

**Hunt modules:**

| Module | MITRE ID | What It Hunts |
|--------|----------|---------------|
| Shadow Copy Deletion | T1490 | EID 4688 for vssadmin delete / wmic shadowcopy delete / bcdedit recoveryenabled commands + Win32_ShadowCopy absence |
| Backup Tampering | T1490 | VSS/wbengine/SDRSVC service disabled + Windows Backup scheduled task disabled |
| Ransom Note Drops | T1486 | Files matching ransom note naming patterns (README, HOW_TO_DECRYPT, RESTORE, YOUR_FILES, etc.) in user directories |
| Ransomware File Extensions | T1486 | Files with known ransomware encrypted extensions (.wncry, .locked, .locky, .cerber, .zepto, .ctbl, etc.) |
| Inhibit Recovery | T1490 | Live `bcdedit` output checked for `recoveryenabled No` and `bootstatuspolicy IgnoreAllFailures` |

**Usage:**

```powershell
# GUI launcher (Run button is red — indicates high-risk hunt)
.\VH_PreRansom_Hunter.ps1

# Headless — all modules
.\VH_PreRansom_Hunter.ps1 -Headless -All -OutputPath C:\Hunts\preransom.csv
```

**Parameters:**

```
-Headless          Run without GUI
-All               Run all 5 hunt modules
-LookbackHours     Event log lookback window (default: 72)
-OutputPath        CSV export path
```

---

### VH_LOLBin_Hunter.ps1 — LOLBin Deep Dive Hunter

Comprehensive living-off-the-land binary hunting. Covers 24 LOLBins with parent/child execution chain analysis from the Security event log.

**Covered LOLBins:**

`mshta`, `wscript`, `cscript`, `rundll32`, `regsvr32`, `certutil`, `bitsadmin`, `msiexec`, `installutil`, `regasm`, `regsvcs`, `odbcconf`, `pcalua`, `forfiles`, `msconfig`, `esentutl`, `expand`, `extrac32`, `makecab`, `wmic`, `netsh`, `schtasks`, `at`, `reg`, `sc`

**Hunt modules:**

| Module | MITRE ID | What It Hunts |
|--------|----------|---------------|
| LOLBin Execution Chains | T1218 | EID 4688 process creation events analysed for all 24 LOLBins — flags suspicious arguments, execution from staging paths, and Office/browser parent processes spawning LOLBins |
| Encoded Command Detection | T1027.010 | EID 4688 events containing `-EncodedCommand` with live base64 decoding of the payload |
| Unsigned Binaries in Staging Paths | T1218 | PE files recently written to Temp, Downloads, ProgramData, Public with invalid or missing Authenticode signatures |

**Usage:**

```powershell
# GUI launcher
.\VH_LOLBin_Hunter.ps1

# Headless — all modules
.\VH_LOLBin_Hunter.ps1 -Headless -All -OutputPath C:\Hunts\lolbins.csv

# Headless — custom lookback
.\VH_LOLBin_Hunter.ps1 -Headless -LookbackHours 168 -OutputPath C:\Hunts\lolbins_week.csv
```

**Parameters:**

```
-Headless          Run without GUI
-All               Run all 3 hunt modules
-LookbackHours     Event log lookback window (default: 72)
-OutputPath        CSV export path
```

---

## Exporting Results

Every script supports CSV export. The exported file includes these fields for every finding:

```
Timestamp, Severity, TechniqueID, Technique, Artifact, Detail, Path
```

```powershell
# Export from any individual script
.\VH_LOLBin_Hunter.ps1 -Headless -All -OutputPath "C:\Hunts\lolbins_$(Get-Date -f yyyyMMdd).csv"

# Export from the master launcher (saves all hunters to a timestamped folder)
# Click "Run All (Headless)" in the launcher GUI
```

---

## Detection Coverage

Hunt findings map to the following MITRE ATT&CK techniques across the library:

| MITRE ID | Technique | Script |
|----------|-----------|--------|
| T1003.001 | LSASS Memory | VH_Credential_Hunter |
| T1003.002 | SAM/Security Hive | VH_Credential_Hunter |
| T1021.001 | Remote Desktop | VH_Lateral_Hunter |
| T1021.002 | SMB/Admin Shares | VH_Lateral_Hunter |
| T1027.010 | Encoded PowerShell | VH_LOLBin_Hunter |
| T1036 | Masquerading | VH_Defense_Evasion_Hunter |
| T1047 | WMI Execution | Veil_Hunter_v2 + VH_Lateral_Hunter |
| T1048 | Exfil via Cloud | VH_C2_Exfil_Hunter |
| T1053.002 | AT Jobs | Task_Hunter_v2 |
| T1053.005 | Scheduled Tasks | Veil_Hunter_v2 + Task_Hunter_v2 |
| T1055 | Process Injection | VH_Defense_Evasion_Hunter |
| T1070.001 | Event Log Cleared | Veil_Hunter_v2 + VH_Defense_Evasion_Hunter |
| T1070.006 | Timestomping | VH_Defense_Evasion_Hunter |
| T1071 | App Layer Protocol C2 | VH_C2_Exfil_Hunter |
| T1071.004 | DNS Beaconing | VH_C2_Exfil_Hunter |
| T1105 | Internet-Sourced Files | malvertising_payload_hunter_v2 |
| T1197 | BITS Jobs | Veil_Hunter_v2 + VH_C2_Exfil_Hunter |
| T1218 | LOLBin Execution | VH_LOLBin_Hunter |
| T1219 | RMM Tools | malvertising_payload_hunter_v2 |
| T1486 | Data Encrypted / Ransom Notes | VH_PreRansom_Hunter |
| T1490 | Inhibit System Recovery | VH_PreRansom_Hunter |
| T1543.003 | Windows Services | Veil_Hunter_v2 + service_installs_v2 |
| T1546.003 | WMI Subscriptions | Veil_Hunter_v2 |
| T1546.010 | AppInit_DLLs | Veil_Hunter_v2 |
| T1546.012 | IFEO | Veil_Hunter_v2 |
| T1547.001 | Run Keys | Veil_Hunter_v2 |
| T1547.002 | LSA Auth Packages | Veil_Hunter_v2 |
| T1547.004 | Winlogon Helper | Veil_Hunter_v2 |
| T1547.009 | Startup Folders | Veil_Hunter_v2 |
| T1550.002 | Pass-the-Hash | VH_Lateral_Hunter |
| T1552.001 | Credential Files | VH_Credential_Hunter |
| T1555 | Credentials from Password Stores | VH_Credential_Hunter |
| T1558.003 | Kerberoasting | VH_Credential_Hunter |
| T1558.004 | AS-REP Roasting | VH_Credential_Hunter |
| T1562.001 | Impair Defenses | VH_Defense_Evasion_Hunter |
| T1569.002 | PSExec | VH_Lateral_Hunter |
| T1572 | Named Pipe C2 | VH_C2_Exfil_Hunter |
| T1574.001 | DLL Hijack | Veil_Hunter_v2 |

---

## Recommended Hunting Workflow

```
1. Run VH_Master_Launcher.ps1
2. Start with the full library in Headless mode to get a baseline
3. Review HIGH findings first — these are confirmed malicious patterns
4. Work down to MED findings with context from your environment
5. Export findings to CSV for ticketing or SIEM correlation
6. Re-run specific hunters after remediation to confirm cleanup
```

For incident response, prioritise in this order:

1. `VH_PreRansom_Hunter.ps1` — check for imminent encryption indicators
2. `VH_Credential_Hunter.ps1` — determine if credentials are compromised
3. `VH_Lateral_Hunter.ps1` — assess scope of movement across the environment
4. `VH_C2_Exfil_Hunter.ps1` — identify active C2 channels
5. `Veil_Hunter_v2.ps1` — find persistence mechanisms keeping the attacker in

---

## Requirements for Full Coverage

Some hunt modules need specific Windows features to be enabled for maximum coverage. Without these, scripts fall back to registry/filesystem scanning automatically.

| Feature | Required By | How to Enable |
|---------|-------------|---------------|
| Process Creation Auditing (EID 4688) | LOLBin Hunter, Lateral Hunter | `auditpol /set /subcategory:"Process Creation" /success:enable` |
| Command Line Logging in EID 4688 | LOLBin Hunter | Group Policy: Administrative Templates > System > Audit Process Creation > Include command line |
| Security log size (recommended 1GB+) | All event log hunts | `wevtutil sl Security /ms:1073741824` |
| Sysmon (optional, enhances coverage) | All hunters | Deploy Sysmon with a community config (SwiftOnSecurity/sysmon-config) |

---

## Contributing

Contributions, issues, and feature requests are welcome. To add a new hunt module:

1. Follow the existing `Add-Finding` / `Print-Finding` / `Print-AllFindings` pattern from the shared helpers block at the top of each script
2. Tag every finding with a MITRE ATT&CK technique ID
3. Keep output field-per-line — no raw event message dumps
4. Include a `-Headless` compatible path and `-OutputPath` CSV export
5. Fork the repo and submit a pull request

---

## License

Apache 2.0 — see [LICENSE](LICENSE) for details.
