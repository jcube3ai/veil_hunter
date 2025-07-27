# VeilHunter

**Hunting Tool for Windows Persistence Detection**

---

## Overview

VeilHunter is a PowerShell-based threat hunting tool designed to detect stealthy Windows persistence techniques by scanning hosts for artifacts adversaries use to maintain footholds. It provides both GUI and CLI interfaces, verbose output, and cleanup capabilities for lab testing.

---

## Repository Contents

| File              | Description                                                                                        |
| ----------------- | -------------------------------------------------------------------------------------------------- |
| `Veil_Hunter.ps1` | Main CLI scanner that runs all persistence hunts (scheduled tasks, services, registry, WMI, etc.). |
| `Task_Hunter.ps1` | Focused module to enumerate and report suspicious Scheduled Tasks and AT jobs.                     |
| `README.md`       | This documentation.                                                                                |

---

## Prerequisites

* **OS**: Windows 10 / Server 2016 or later
* **PowerShell**: Version 5.1 or later (compatible with PS 7+)
* **Execution Policy**: Ensure scripts are unblocked:

  ```powershell
  Set-ExecutionPolicy Bypass -Scope Process -Force
  Get-ChildItem . -Recurse | Unblock-File
  ```

---

## Usage

### CLI Mode

Run all hunts:

```powershell
.\Veil_Hunter.ps1 -Verbose
```

Run only Scheduled Task hunts:

```powershell
.\Task_Hunter.ps1 -Verbose
```

### GUI Mode

Launch the GUI to select specific hunts (if implemented):

```powershell
.\Veil_HunterUI.ps1
```

*(Note: GUI script not included by default.)*

---

## Detection Modules

| Technique                               | Module         |
| --------------------------------------- | -------------- |
| Scheduled Task creation/modification    | Scheduled Task |
| AT Job (legacy scheduling)              | Task Hunter    |
| Windows Service installation            | Service Hunt   |
| Registry Run/Login keys & IFEO          | Registry Hunt  |
| Startup Folder & Shortcut modifications | Shortcut Hunt  |
| COM Hijacking (InprocServer32)          | COM Hunt       |
| WMI Permanent Event Subscriptions       | WMI Hunt       |

---

## Contributing

Contributions, issues, and feature requests are welcome! Please fork the repo and submit a pull request.

---

## License

This project is licensed under the Apache 2.0 License — see [LICENSE](LICENSE) for details.

