VeilHunter

Purple Team Simulation & Hunting Tool for Windows Persistence Detection

Overview

VeilHunter is a PowerShell–based purple‑team simulator and hunter designed to emulate and detect realistic adversary persistence techniques against Windows hosts in a completely lab‑safe environment. Each module represents a different persistence mechanism mapped to MITRE ATT&CK, with both simulation (artifact creation) and cleanup options, so you can practice detection, response, and forensic analysis without risking real infections.

Repository Contents

File

Description

VeilHunter.ps1

CLI scanner: hunts across a Windows host for persistence artifacts with verbose reporting.

VeilHunterUI.ps1

GUI launcher: select specific techniques to hunt or clean up via checkboxes.

WindowsPersistenceFullSim.ps1

Simulation harness: plants & cleans up exotic Windows persistence artifacts.

LICENSE

Apache 2.0 License details.

README.md

This document.

Prerequisites

OS: Windows 10 or later / Windows Server 2016+

PowerShell: Version 5.1 or later (PS 7+ supported)

Execution Policy: Ensure scripts can run:

Set-ExecutionPolicy Bypass -Scope Process -Force

Usage

CLI Scanner

.\VeilHunter.ps1 -Verbose

Runs all hunts sequentially, reporting any found artifacts.

GUI Launcher

.\VeilHunterUI.ps1

Launches a window to check/uncheck persistence sub‑techniques, then Run Selected to hunt or Cleanup to remove simulation artifacts.

Simulation Harness

Create test artifacts:

.\WindowsPersistenceFullSim.ps1

Cleanup test artifacts:

.\WindowsPersistenceFullSim.ps1 -Cleanup

MITRE ATT&CK Mapping

VeilHunter covers these Windows persistence techniques:

Technique ID

Name

T1053.001

Scheduled Task

T1053.002

AT Job (legacy)

T1053.005

COM+ Timer via TaskScheduler

T1053.006

Windows Service

T1547.001

Registry Run Key & Startup Folder shortcut

T1547.004

Image File Execution Options (IFEO)

T1546.002

Shortcut Modification (Startup & Desktop)

T1546.004

COM Hijacking (InprocServer32)

T1546.005

WMI permanent event subscription

Contributing

Contributions, suggestions, and bug reports are welcome! Please open an issue or pull request.

License

This project is licensed under the Apache 2.0 License — see LICENSE.

