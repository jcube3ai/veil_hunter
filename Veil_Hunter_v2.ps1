#Requires -Version 5.1
<#
.SYNOPSIS
    VeilHunter v2 -- Windows Persistence Hunter (GUI + CLI)

.DESCRIPTION
    Hunts for adversary persistence artifacts across Scheduled Tasks,
    Services, WMI Subscriptions, BITS Jobs, Registry Run Keys, IFEO,
    DLL Hijacks, Startup Folders, Winlogon Helpers, and AppInit DLLs.

    Supports both GUI (interactive) and CLI (headless) modes.
    All findings carry a Severity rating (HIGH / MED / INFO) and MITRE
    ATT&CK technique ID. Results can be exported to CSV.

.PARAMETER Headless
    Run in CLI mode (no GUI). All selected hunts run automatically.

.PARAMETER OutputPath
    Optional path to export findings as CSV.
    Example: -OutputPath "C:\Hunts\veilhunter_$(Get-Date -f yyyyMMdd).csv"

.PARAMETER All
    (Headless mode) Run all hunt modules.

.EXAMPLE
    # GUI mode
    .\Veil_Hunter_v2.ps1

    # CLI mode - all hunts, export to CSV
    .\Veil_Hunter_v2.ps1 -Headless -All -OutputPath C:\Hunts\results.csv

    # CLI mode - specific hunts
    .\Veil_Hunter_v2.ps1 -Headless -RunWMI -RunRegistry
#>

[CmdletBinding()]
param(
    [switch]$Headless,
    [switch]$All,
    [switch]$RunTasks,
    [switch]$RunServices,
    [switch]$RunWMI,
    [switch]$RunBITS,
    [switch]$RunRegistry,
    [switch]$RunDLL,
    [switch]$RunStartup,
    [switch]$RunWinlogon,
    [string]$OutputPath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"

# ---------------------------------------------------------------
# SHARED FINDING STORE
# ---------------------------------------------------------------
$script:Findings = [System.Collections.Generic.List[pscustomobject]]::new()

function Add-Finding {
    param(
        [ValidateSet("HIGH","MED","INFO")]
        [string]$Severity,
        [string]$TechniqueID,
        [string]$Technique,
        [string]$Artifact,
        [string]$Detail,
        [string]$Path = ""
    )
    $f = [pscustomobject]@{
        Timestamp   = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        Severity    = $Severity
        TechniqueID = $TechniqueID
        Technique   = $Technique
        Artifact    = $Artifact
        Detail      = $Detail
        Path        = $Path
    }
    $script:Findings.Add($f)
    return $f
}

function Format-Finding([pscustomobject]$f) {
    $sev = switch ($f.Severity) {
        "HIGH" { "[HIGH]" }
        "MED"  { "[MED] " }
        default { "[INFO]" }
    }
    $lines = @()
    $lines += "$sev [$($f.TechniqueID)] $($f.Technique) -- $($f.Artifact)"
    if ($f.Detail) { $lines += "       Detail : $($f.Detail)" }
    if ($f.Path)   { $lines += "       Path   : $($f.Path)"   }
    $lines += ""   # blank line between findings
    return $lines -join "`n"
}

# ---------------------------------------------------------------
# HKCR DRIVE MAPPING (fixes silent failure bug in v1)
# ---------------------------------------------------------------
function Ensure-HKCRDrive {
    if (-not (Get-PSDrive -Name HKCR -ErrorAction SilentlyContinue)) {
        New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
    }
}

# ---------------------------------------------------------------
# SIGNATURE HELPER
# ---------------------------------------------------------------
function Get-SignatureStatus([string]$FilePath) {
    if (-not $FilePath -or -not (Test-Path $FilePath -ErrorAction SilentlyContinue)) {
        return "FILE_NOT_FOUND"
    }
    try {
        $sig = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction Stop
        return $sig.Status.ToString()
    } catch {
        return "UNKNOWN"
    }
}

# ---------------------------------------------------------------
# HUNT 1 -- Scheduled Tasks (T1053.005)
# Event IDs: 106 (registered), 140 (updated), 141 (deleted),
#            200 (action launched), 201 (action completed)
# ---------------------------------------------------------------
function Hunt-ScheduledTasks {
    Write-Verbose "Running Scheduled Task hunt (T1053.005)"

    # -- Event log path --
    $logName = "Microsoft-Windows-TaskScheduler/Operational"
    if (Get-WinEvent -ListLog $logName -ErrorAction SilentlyContinue) {
        $events = Get-WinEvent -LogName $logName -MaxEvents 200 -ErrorAction SilentlyContinue |
            Where-Object { $_.Id -in 106, 140, 141, 200, 201 }
        foreach ($e in $events) {
            $sev = if ($e.Id -in 141, 200) { "HIGH" } else { "MED" }
            $evtDesc = switch ($e.Id) {
                106 { "Task registered" }
                140 { "Task updated" }
                141 { "Task deleted -- possible covering tracks" }
                200 { "Task action launched" }
                201 { "Task action completed" }
            }
            # Parse task name from message - first non-empty line is usually the task path
            $taskName = ""
            $instance = ""
            if ($e.Message -match 'Task\s+(.+?)\s+(was|is)\s') { $taskName = $Matches[1].Trim() }
            if ($e.Message -match 'instance\s+(.+?)\s+of') { $instance = $Matches[1].Trim() }
            if (-not $taskName) {
                $taskName = ($e.Message -split '\r?\n' | Where-Object { $_.Trim() } | Select-Object -First 1).Trim()
            }
            $detail = "Time: $($e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')) | $evtDesc"
            if ($taskName) { $detail += " | Task: $taskName" }
            if ($instance) { $detail += " | Instance: $instance" }
            Add-Finding -Severity $sev -TechniqueID "T1053.005" -Technique "Scheduled Task" `
                -Artifact "EventID $($e.Id)" -Detail $detail | Out-Null
        }
    }

    # -- Folder scan fallback + live task analysis --
    $suspiciousPatterns = '-EncodedCommand|\\Users\\|\\AppData\\|\\Temp\\|\\ProgramData\\|mshta|wscript|cscript|rundll32|regsvr32|certutil'
    Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
        $_.TaskPath -notlike '\Microsoft\Windows\*'
    } | ForEach-Object {
        $task    = $_
        $actions = $task.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }
        $actionStr = ($actions -join "; ").Trim()
        if ($actionStr -match $suspiciousPatterns -or $task.Principal.UserId -match 'SYSTEM') {
            $sev = if ($actionStr -match '-EncodedCommand|mshta|wscript|cscript|rundll32') { "HIGH" } else { "MED" }
            Add-Finding -Severity $sev -TechniqueID "T1053.005" -Technique "Scheduled Task" `
                -Artifact $task.TaskName `
                -Detail "Author: $($task.Author) | Action: $actionStr | State: $($task.State)" `
                -Path "$env:WINDIR\System32\Tasks$($task.TaskPath)$($task.TaskName)" | Out-Null
        }
    }
}

# ---------------------------------------------------------------
# HUNT 2 -- Service Path Tampering (T1543.003)
# Event IDs: 7045 (new service), 7040 (start type changed), 7036 (state change)
# ---------------------------------------------------------------
function Hunt-ServiceTampering {
    Write-Verbose "Running Service Tampering hunt (T1543.003)"

    # -- Event log --
    if (Get-WinEvent -ListLog "System" -ErrorAction SilentlyContinue) {
        $evtIds = @(
            @{ Id = 7045; Desc = "New service installed"; Sev = "HIGH" },
            @{ Id = 7040; Desc = "Service start type changed"; Sev = "MED" },
            @{ Id = 7036; Desc = "Service state changed"; Sev = "INFO" }
        )
        foreach ($e in $evtIds) {
            Get-WinEvent -LogName System `
                -FilterXPath "*[System[(EventID=$($e.Id))]]" `
                -MaxEvents 100 -ErrorAction SilentlyContinue | ForEach-Object {
                # Extract service name and image path from message - skip raw message dump
                $svcName = ""
                $imgPath = ""
                if ($_.Message -match "service name:\s*(.+?)[\r\n]")  { $svcName = $Matches[1].Trim() }
                if ($_.Message -match "service file name:\s*(.+?)[\r\n]") { $imgPath = $Matches[1].Trim() }
                # Fallback: grab first meaningful line only
                if (-not $svcName) {
                    $svcName = ($_.Message -split '\r?\n' | Where-Object { $_.Trim() -ne "" } | Select-Object -First 1).Trim()
                }
                $detail = "Time: $($_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')) | $($e.Desc)"
                if ($svcName) { $detail += " | Service: $svcName" }
                if ($imgPath) { $detail += " | Path: $imgPath" }
                Add-Finding -Severity $e.Sev -TechniqueID "T1543.003" -Technique "Service Tampering" `
                    -Artifact "EventID $($e.Id)" -Detail $detail | Out-Null
            }
        }
    }

    # -- Registry scan: suspicious ImagePath locations --
    $suspPaths = '\\Users\\|\\AppData\\|\\Temp\\|\\ProgramData\\|\\Downloads\\'
    Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\*' `
        -Name ImagePath, Start -ErrorAction SilentlyContinue |
        Where-Object { $_.ImagePath -match $suspPaths } |
        ForEach-Object {
            $imgPath = ($_.ImagePath -split '"' | Where-Object { $_ -match '\.exe' } | Select-Object -First 1).Trim()
            $sig = Get-SignatureStatus $imgPath
            $sev = if ($sig -ne "Valid") { "HIGH" } else { "MED" }
            Add-Finding -Severity $sev -TechniqueID "T1543.003" -Technique "Service Tampering" `
                -Artifact $_.PSChildName `
                -Detail "ImagePath in suspicious location | Signature: $sig | Start: $($_.Start)" `
                -Path $_.ImagePath | Out-Null
        }
}

# ---------------------------------------------------------------
# HUNT 3 -- WMI Event Subscriptions (T1546.003)
# Event IDs: 5858, 5859, 5860, 5861
# ---------------------------------------------------------------
function Hunt-WmiSubscriptions {
    Write-Verbose "Running WMI Subscription hunt (T1546.003)"

    # Helper: pull a named field out of a WMI event message
    function Parse-WmiField([string]$msg, [string]$field) {
        if ($msg -match "$field\s*=\s*([^;`r`n]+)") { return $Matches[1].Trim() }
        return ""
    }

    $wmiLog = "Microsoft-Windows-WMI-Activity/Operational"
    if (Get-WinEvent -ListLog $wmiLog -ErrorAction SilentlyContinue) {
        $events = Get-WinEvent -LogName $wmiLog -MaxEvents 200 -ErrorAction SilentlyContinue |
            Where-Object { $_.Id -in 5858, 5859, 5860, 5861 }

        foreach ($e in $events) {
            $sev = if ($e.Id -in 5859, 5861) { "HIGH" } else { "MED" }
            $evtDesc = switch ($e.Id) {
                5858 { "WMI query error" }
                5859 { "WMI temporary subscription created" }
                5860 { "WMI consumer activity" }
                5861 { "WMI permanent subscription created" }
            }

            # Extract only the useful fields - skip the noise
            $msg       = $e.Message
            $user      = Parse-WmiField $msg "User"
            $operation = Parse-WmiField $msg "Operation"
            $result    = Parse-WmiField $msg "ResultCode"
            $cause     = Parse-WmiField $msg "PossibleCause"

            # Skip 5858 errors that are routine OS/scheduler noise
            if ($e.Id -eq 5858) {
                $op = $operation.ToLower()
                if ($op -match 'msft_scheduledtask|taskscheduler|lenovo_gamezone|win32_processor|win32_computersystem') {
                    continue
                }
            }

            $detail = "Time: $($e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))"
            if ($user)      { $detail += " | User: $user" }
            if ($operation) { $detail += " | Op: $($operation.Substring(0, [Math]::Min(80, $operation.Length)))" }
            if ($result)    { $detail += " | Result: $result" }
            if ($cause -and $cause -ne "Unknown") { $detail += " | Cause: $cause" }

            Add-Finding -Severity $sev -TechniqueID "T1546.003" -Technique "WMI Subscription" `
                -Artifact "EventID $($e.Id) -- $evtDesc" -Detail $detail | Out-Null
        }
    }

    # -- Live WMI namespace query (always runs, most reliable) --
    Get-WmiObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue |
        ForEach-Object {
            Add-Finding -Severity "HIGH" -TechniqueID "T1546.003" -Technique "WMI Subscription" `
                -Artifact "EventFilter: $($_.Name)" `
                -Detail "Namespace: $($_.EventNamespace) | Query: $($_.Query)" | Out-Null
        }

    Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -ErrorAction SilentlyContinue |
        ForEach-Object {
            Add-Finding -Severity "HIGH" -TechniqueID "T1546.003" -Technique "WMI Subscription" `
                -Artifact "CommandLineConsumer: $($_.Name)" `
                -Detail "Command: $($_.CommandLineTemplate)" | Out-Null
        }

    Get-WmiObject -Namespace root\subscription -Class ActiveScriptEventConsumer -ErrorAction SilentlyContinue |
        ForEach-Object {
            Add-Finding -Severity "HIGH" -TechniqueID "T1546.003" -Technique "WMI Subscription" `
                -Artifact "ScriptConsumer: $($_.Name)" `
                -Detail "Script: $($_.ScriptText -replace '\r?\n',' ' | Select-Object -First 120)" | Out-Null
        }

    Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue |
        ForEach-Object {
            Add-Finding -Severity "HIGH" -TechniqueID "T1546.003" -Technique "WMI Subscription" `
                -Artifact "Binding active" `
                -Detail "Filter -> Consumer binding is live on this host" | Out-Null
        }
}

# ---------------------------------------------------------------
# HUNT 4 -- BITS Jobs (T1197)
# ---------------------------------------------------------------
function Hunt-BitsJobs {
    Write-Verbose "Running BITS Jobs hunt (T1197)"

    $bitsLog = "Microsoft-Windows-Bits-Client/Operational"
    if (Get-WinEvent -ListLog $bitsLog -ErrorAction SilentlyContinue) {
        Get-WinEvent -LogName $bitsLog -MaxEvents 100 -ErrorAction SilentlyContinue |
            ForEach-Object {
                $sev = if ($_.Id -in 3, 59, 60) { "HIGH" } else { "INFO" }
                Add-Finding -Severity $sev -TechniqueID "T1197" -Technique "BITS Job" `
                    -Artifact "EventID $($_.Id)" `
                    -Detail "[$($_.TimeCreated)] $($_.Message -replace '\r?\n',' ')" | Out-Null
            }
    }

    # -- Live BITS transfer check --
    Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue | ForEach-Object {
        $sev = if ($_.JobState -in "Transferring","Connecting") { "HIGH" } else { "MED" }
        Add-Finding -Severity $sev -TechniqueID "T1197" -Technique "BITS Job" `
            -Artifact "Job: $($_.DisplayName)" `
            -Detail "State: $($_.JobState) | Remote: $($_.RemoteName) | Owner: $($_.OwnerAccount)" `
            -Path $_.LocalName | Out-Null
    }
}

# ---------------------------------------------------------------
# HUNT 5 -- Registry Run Keys & IFEO (T1547.001 / T1546.012)
# ---------------------------------------------------------------
function Hunt-RegistryPersistence {
    Write-Verbose "Running Registry Persistence hunt (T1547.001 / T1546.012)"

    $runPaths = @(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunServices',
        'HKLM:\System\CurrentControlSet\Control\Session Manager\BootExecute'
    )

    $suspValuePatterns = '-EncodedCommand|mshta|wscript|cscript|rundll32|regsvr32|\\Temp\\|\\AppData\\|\\Users\\Public\\|powershell|cmd\.exe'

    foreach ($p in $runPaths) {
        if (-not (Test-Path $p -ErrorAction SilentlyContinue)) { continue }
        Get-ItemProperty -LiteralPath $p -ErrorAction SilentlyContinue |
            ForEach-Object {
                $item = $_
                $item.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } |
                    ForEach-Object {
                        $val = [string]$_.Value
                        $sev = if ($val -match $suspValuePatterns) { "HIGH" } else { "MED" }
                        Add-Finding -Severity $sev -TechniqueID "T1547.001" -Technique "Registry Run Key" `
                            -Artifact $_.Name -Detail "Value: $val" -Path "$p\$($_.Name)" | Out-Null
                    }
            }
    }

    # -- IFEO Debugger hijacks --
    $ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    Get-ChildItem -LiteralPath $ifeo -ErrorAction SilentlyContinue | ForEach-Object {
        $dbg = (Get-ItemProperty -LiteralPath $_.PSPath -Name Debugger -ErrorAction SilentlyContinue).Debugger
        if ($dbg) {
            Add-Finding -Severity "HIGH" -TechniqueID "T1546.012" -Technique "IFEO Debugger Hijack" `
                -Artifact $_.PSChildName -Detail "Debugger: $dbg" -Path $_.PSPath | Out-Null
        }
        # GlobalFlag for silent exit monitoring
        $gf = (Get-ItemProperty -LiteralPath $_.PSPath -Name GlobalFlag -ErrorAction SilentlyContinue).GlobalFlag
        if ($gf -eq 512) {
            Add-Finding -Severity "HIGH" -TechniqueID "T1546.012" -Technique "IFEO GlobalFlag (Silent Exit Monitor)" `
                -Artifact $_.PSChildName -Detail "GlobalFlag=512 -- may redirect exit to SilentProcessExit handler" `
                -Path $_.PSPath | Out-Null
        }
    }
}

# ---------------------------------------------------------------
# HUNT 6 -- DLL Hijacks via COM InprocServer32 (T1574.001)
# Fixed: HKCR drive mapped, existence check, signature check
# ---------------------------------------------------------------
function Hunt-DllHijacks {
    Write-Verbose "Running DLL Hijack hunt (T1574.001)"
    Ensure-HKCRDrive

    # Suspicious COM paths: outside System32/SysWOW64/WinSxS/WindowsApps
    $suspComPattern = '\\Users\\|\\AppData\\|\\Temp\\|\\ProgramData\\|\\Downloads\\'

    Get-ChildItem 'HKCR:\CLSID' -ErrorAction SilentlyContinue | ForEach-Object {
        $clsid = $_
        $inproc = Join-Path $clsid.PSPath "InprocServer32"
        if (Test-Path $inproc -ErrorAction SilentlyContinue) {
            $val = (Get-ItemProperty -LiteralPath $inproc -Name '(default)' -ErrorAction SilentlyContinue).'(default)'
            if ($val -and ($val -match $suspComPattern -or -not (Test-Path $val -ErrorAction SilentlyContinue))) {
                $exists = Test-Path $val -ErrorAction SilentlyContinue
                $sig    = if ($exists) { Get-SignatureStatus $val } else { "FILE_MISSING" }
                $sev    = if (-not $exists -or $sig -ne "Valid") { "HIGH" } else { "MED" }
                Add-Finding -Severity $sev -TechniqueID "T1574.001" -Technique "COM DLL Hijack" `
                    -Artifact $clsid.PSChildName `
                    -Detail "InprocServer32: $val | Exists: $exists | Signature: $sig" `
                    -Path $val | Out-Null
            }
        }
    }

    # AppInit_DLLs -- T1546.010
    $appinit = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'
    $dllVal  = (Get-ItemProperty -LiteralPath $appinit -Name AppInit_DLLs -ErrorAction SilentlyContinue).AppInit_DLLs
    if ($dllVal -and $dllVal.Trim()) {
        Add-Finding -Severity "HIGH" -TechniqueID "T1546.010" -Technique "AppInit_DLLs" `
            -Artifact "AppInit_DLLs" -Detail "Value: $dllVal" -Path $appinit | Out-Null
    }
    $loadAppinit = (Get-ItemProperty -LiteralPath $appinit -Name LoadAppInit_DLLs -ErrorAction SilentlyContinue).LoadAppInit_DLLs
    if ($loadAppinit -eq 1) {
        Add-Finding -Severity "HIGH" -TechniqueID "T1546.010" -Technique "AppInit_DLLs Enabled" `
            -Artifact "LoadAppInit_DLLs=1" -Detail "AppInit DLL loading is enabled on this host." -Path $appinit | Out-Null
    }
}

# ---------------------------------------------------------------
# HUNT 7 -- Startup Folder Persistence (T1547.009)
# ---------------------------------------------------------------
function Hunt-StartupFolders {
    Write-Verbose "Running Startup Folder hunt (T1547.009)"

    $startupPaths = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",
        "C:\Users\Public\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
    )

    $suspExts = '\.vbs$|\.js$|\.hta$|\.bat$|\.cmd$|\.ps1$|\.exe$|\.dll$'

    foreach ($folder in $startupPaths) {
        if (-not (Test-Path $folder -ErrorAction SilentlyContinue)) { continue }
        Get-ChildItem -Path $folder -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            $sev = if ($_.Extension -match $suspExts) { "HIGH" } else { "MED" }
            $sig = Get-SignatureStatus $_.FullName
            $sev = if ($sig -ne "Valid" -and $sig -ne "FILE_NOT_FOUND") { "HIGH" } else { $sev }
            Add-Finding -Severity $sev -TechniqueID "T1547.009" -Technique "Startup Folder" `
                -Artifact $_.Name `
                -Detail "Modified: $($_.LastWriteTime) | Signature: $sig" `
                -Path $_.FullName | Out-Null
        }
    }
}

# ---------------------------------------------------------------
# HUNT 8 -- Winlogon Helper DLLs (T1547.004)
# ---------------------------------------------------------------
function Hunt-WinlogonHelpers {
    Write-Verbose "Running Winlogon Helper hunt (T1547.004)"

    $winlogonKey  = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $knownHelpers = @{
        Userinit  = 'C:\Windows\system32\userinit.exe,'
        Shell     = 'explorer.exe'
    }

    foreach ($name in $knownHelpers.Keys) {
        $val = (Get-ItemProperty -LiteralPath $winlogonKey -Name $name -ErrorAction SilentlyContinue).$name
        if ($val -and $val.Trim() -ne $knownHelpers[$name]) {
            Add-Finding -Severity "HIGH" -TechniqueID "T1547.004" -Technique "Winlogon Helper" `
                -Artifact "$name" `
                -Detail "Expected: '$($knownHelpers[$name])' | Found: '$val'" `
                -Path "$winlogonKey\$name" | Out-Null
        }
    }

    # Check for extra Notify packages
    $notifyKey = Join-Path $winlogonKey "Notify"
    if (Test-Path $notifyKey -ErrorAction SilentlyContinue) {
        Get-ChildItem -LiteralPath $notifyKey -ErrorAction SilentlyContinue | ForEach-Object {
            $dll = (Get-ItemProperty -LiteralPath $_.PSPath -Name DllName -ErrorAction SilentlyContinue).DllName
            if ($dll) {
                $sig = Get-SignatureStatus $dll
                $sev = if ($sig -ne "Valid") { "HIGH" } else { "MED" }
                Add-Finding -Severity $sev -TechniqueID "T1547.004" -Technique "Winlogon Notify DLL" `
                    -Artifact $_.PSChildName -Detail "DllName: $dll | Signature: $sig" -Path $dll | Out-Null
            }
        }
    }

    # LSA authentication packages
    $lsaKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $authPkgs = (Get-ItemProperty -LiteralPath $lsaKey -Name 'Authentication Packages' -ErrorAction SilentlyContinue).'Authentication Packages'
    if ($authPkgs) {
        $expected = @('msv1_0')
        $extras = $authPkgs | Where-Object { $_ -notin $expected -and $_ -ne '' }
        foreach ($pkg in $extras) {
            Add-Finding -Severity "HIGH" -TechniqueID "T1547.002" -Technique "LSA Authentication Package" `
                -Artifact $pkg -Detail "Non-standard LSA auth package registered." -Path $lsaKey | Out-Null
        }
    }
}

# ---------------------------------------------------------------
# EXPORT
# ---------------------------------------------------------------
function Export-Findings([string]$Path) {
    if ($script:Findings.Count -eq 0) {
        Write-Host "No findings to export." -ForegroundColor Yellow
        return
    }
    try {
        $script:Findings | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8 -Force
        Write-Host "[+] Findings exported to: $Path ($($script:Findings.Count) records)" -ForegroundColor Green
    } catch {
        Write-Host "[X] Export failed: $_" -ForegroundColor Red
    }
}

# ---------------------------------------------------------------
# HEADLESS (CLI) MODE
# ---------------------------------------------------------------
if ($Headless) {
    $script:Findings.Clear()

    if ($All -or $RunTasks)    { Hunt-ScheduledTasks    }
    if ($All -or $RunServices) { Hunt-ServiceTampering  }
    if ($All -or $RunWMI)      { Hunt-WmiSubscriptions  }
    if ($All -or $RunBITS)     { Hunt-BitsJobs          }
    if ($All -or $RunRegistry) { Hunt-RegistryPersistence }
    if ($All -or $RunDLL)      { Hunt-DllHijacks        }
    if ($All -or $RunStartup)  { Hunt-StartupFolders    }
    if ($All -or $RunWinlogon) { Hunt-WinlogonHelpers   }

    Write-Host "`n===== VeilHunter v2 Results ($($script:Findings.Count) findings) =====" -ForegroundColor Cyan

    $grouped = $script:Findings | Group-Object Severity | Sort-Object {
        switch ($_.Name) { "HIGH" { 0 } "MED" { 1 } default { 2 } }
    }
    foreach ($grp in $grouped) {
        $color = switch ($grp.Name) { "HIGH" { "Red" } "MED" { "Yellow" } default { "Gray" } }
        Write-Host "`n-- $($grp.Name) ($($grp.Count)) --" -ForegroundColor $color
        foreach ($f in $grp.Group) {
            $sev = switch ($f.Severity) { "HIGH" { "[HIGH]" } "MED" { "[MED] " } default { "[INFO]" } }
            Write-Host "$sev [$($f.TechniqueID)] $($f.Technique)" -ForegroundColor $color
            Write-Host "       Artifact : $($f.Artifact)"         -ForegroundColor $color
            if ($f.Detail) {
                $f.Detail -split '\|' | ForEach-Object {
                    Write-Host "       $($_.Trim())" -ForegroundColor $color
                }
            }
            if ($f.Path) { Write-Host "       Path     : $($f.Path)" -ForegroundColor DarkGray }
            Write-Host ""
        }
    }

    if ($OutputPath) { Export-Findings $OutputPath }
    exit 0
}

# ---------------------------------------------------------------
# GUI MODE  (launcher panel only -- all results go to the console)
# ---------------------------------------------------------------
Add-Type -AssemblyName System.Windows.Forms, System.Drawing

# Console output helpers -- Write-Host with colour, no TextBox involved
function Con-Log {
    param(
        [string]$Message,
        [string]$Severity = "INFO"
    )
    $color = switch ($Severity) {
        "HIGH"  { "Red"     }
        "MED"   { "Yellow"  }
        "CLEAN" { "Green"   }
        default { "Gray"    }
    }
    Write-Host $Message -ForegroundColor $color
}

function Con-Banner([string]$Text) {
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
}

function Con-Section([string]$Text) {
    Write-Host ""
    Write-Host "-- $Text --" -ForegroundColor DarkCyan
}

# Hunt module registry
$huntModules = [ordered]@{
    "Scheduled Tasks (T1053.005)"      = "Hunt-ScheduledTasks"
    "Service Tampering (T1543.003)"    = "Hunt-ServiceTampering"
    "WMI Subscriptions (T1546.003)"    = "Hunt-WmiSubscriptions"
    "BITS Jobs (T1197)"                = "Hunt-BitsJobs"
    "Run Keys + IFEO (T1547.001)"      = "Hunt-RegistryPersistence"
    "DLL Hijack + AppInit (T1574.001)" = "Hunt-DllHijacks"
    "Startup Folders (T1547.009)"      = "Hunt-StartupFolders"
    "Winlogon + LSA (T1547.004)"       = "Hunt-WinlogonHelpers"
}

# ---- Form layout ----
$FORM_W  = 280    # narrow launcher panel -- results go to console
$CB_X    = 12
$CB_Y0   = 12
$CB_STEP = 28
$BTN_W   = 120
$BTN_H   = 32
$MARGIN  = 10

$form = New-Object System.Windows.Forms.Form
$form.Text            = "VeilHunter v2"
$form.StartPosition   = "Manual"
$form.FormBorderStyle = "FixedToolWindow"
$form.MaximizeBox     = $false
$form.MinimizeBox     = $false
$form.TopMost         = $true   # stays visible while console output scrolls

# Position form top-right so it doesn't block the console
$screen = [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea
$form.Location = New-Object System.Drawing.Point(($screen.Right - $FORM_W - 10), $screen.Top + 10)

# -- Checkboxes --
$cbY = $CB_Y0
$checkboxes = @{}
foreach ($label in $huntModules.Keys) {
    $cb          = New-Object System.Windows.Forms.CheckBox
    $cb.Text     = $label
    $cb.AutoSize = $true
    $cb.Location = New-Object System.Drawing.Point($CB_X, $cbY)
    $form.Controls.Add($cb)
    $checkboxes[$label] = $cb
    $cbY += $CB_STEP
}

# -- Select All --
$cbY += 4
$cbAll = New-Object System.Windows.Forms.CheckBox
$cbAll.Text     = "Select All"
$cbAll.Font     = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$cbAll.AutoSize = $true
$cbAll.Location = New-Object System.Drawing.Point($CB_X, $cbY)
$cbAll.Add_CheckedChanged({
    foreach ($cb in $checkboxes.Values) { $cb.Checked = $cbAll.Checked }
})
$form.Controls.Add($cbAll)
$cbY += $CB_STEP + 8

# -- Separator line --
$sep = New-Object System.Windows.Forms.Label
$sep.BorderStyle = "Fixed3D"
$sep.Size        = New-Object System.Drawing.Size(($FORM_W - $CB_X * 2), 2)
$sep.Location    = New-Object System.Drawing.Point($CB_X, $cbY)
$form.Controls.Add($sep)
$cbY += 10

# -- Run button --
$btnRun = New-Object System.Windows.Forms.Button
$btnRun.Text     = "Run Hunt"
$btnRun.Size     = New-Object System.Drawing.Size($BTN_W, $BTN_H)
$btnRun.Location = New-Object System.Drawing.Point($CB_X, $cbY)
$btnRun.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 215)
$btnRun.ForeColor = [System.Drawing.Color]::White
$btnRun.FlatStyle = "Flat"
$form.Controls.Add($btnRun)

# -- Export CSV button --
$btnExport = New-Object System.Windows.Forms.Button
$btnExport.Text     = "Export CSV"
$btnExport.Size     = New-Object System.Drawing.Size($BTN_W, $BTN_H)
$btnExport.Location = New-Object System.Drawing.Point(($CB_X + $BTN_W + $MARGIN), $cbY)
$btnExport.FlatStyle = "Flat"
$form.Controls.Add($btnExport)
$cbY += $BTN_H + $MARGIN

# -- Status label --
$lblStatus = New-Object System.Windows.Forms.Label
$lblStatus.Text      = "Ready."
$lblStatus.AutoSize  = $false
$lblStatus.Size      = New-Object System.Drawing.Size(($FORM_W - $CB_X * 2), 18)
$lblStatus.Font      = New-Object System.Drawing.Font("Segoe UI", 8)
$lblStatus.ForeColor = [System.Drawing.Color]::DarkGray
$lblStatus.Location  = New-Object System.Drawing.Point($CB_X, $cbY)
$form.Controls.Add($lblStatus)
$cbY += 24

$form.ClientSize = New-Object System.Drawing.Size($FORM_W, $cbY)

# ---- Run button handler ----
$btnRun.Add_Click({
    $selected = $checkboxes.Keys | Where-Object { $checkboxes[$_].Checked }
    if (-not $selected) {
        [System.Windows.Forms.MessageBox]::Show(
            "Select at least one hunt module.", "Nothing Selected",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning) | Out-Null
        return
    }

    $btnRun.Enabled    = $false
    $btnExport.Enabled = $false
    $script:Findings.Clear()

    Con-Banner "VeilHunter v2 -- Hunt started $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"

    foreach ($label in $selected) {
        $lblStatus.Text = "Running: $label"
        [System.Windows.Forms.Application]::DoEvents()

        Con-Section $label
        & $huntModules[$label]
        [System.Windows.Forms.Application]::DoEvents()
    }

    # Print findings sorted by severity
    Con-Banner "RESULTS  ($($script:Findings.Count) total findings)"

    $grouped = $script:Findings | Group-Object Severity | Sort-Object {
        switch ($_.Name) { "HIGH" { 0 } "MED" { 1 } default { 2 } }
    }

    foreach ($grp in $grouped) {
        $color = switch ($grp.Name) { "HIGH" { "Red" } "MED" { "Yellow" } default { "Gray" } }
        Con-Section "$($grp.Name) -- $($grp.Count) finding(s)"
        foreach ($f in $grp.Group) {
            # Print each field on its own line with consistent indentation
            $sev = switch ($f.Severity) { "HIGH" { "[HIGH]" } "MED" { "[MED] " } default { "[INFO]" } }
            Write-Host "$sev [$($f.TechniqueID)] $($f.Technique)" -ForegroundColor $color
            Write-Host "       Artifact : $($f.Artifact)"         -ForegroundColor $color
            if ($f.Detail) {
                # Wrap long detail lines at 100 chars
                $f.Detail -split '\|' | ForEach-Object {
                    Write-Host "       $($_.Trim())" -ForegroundColor $color
                }
            }
            if ($f.Path)   { Write-Host "       Path     : $($f.Path)" -ForegroundColor DarkGray }
            Write-Host ""
        }
    }

    $high = ($script:Findings | Where-Object Severity -eq "HIGH").Count
    $med  = ($script:Findings | Where-Object Severity -eq "MED").Count
    $info = ($script:Findings | Where-Object Severity -eq "INFO").Count

    Write-Host ""
    Write-Host "Hunt complete -- HIGH: $high  |  MED: $med  |  INFO: $info  |  Total: $($script:Findings.Count)" -ForegroundColor Cyan
    Write-Host ""

    $lblStatus.Text    = "Done -- HIGH: $high  MED: $med  INFO: $info"
    $btnRun.Enabled    = $true
    $btnExport.Enabled = $true
})

# ---- Export button handler ----
$btnExport.Add_Click({
    if ($script:Findings.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show(
            "Run a hunt first.", "No Findings",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
        return
    }
    $dlg = New-Object System.Windows.Forms.SaveFileDialog
    $dlg.Filter   = "CSV Files (*.csv)|*.csv|All Files (*.*)|*.*"
    $dlg.FileName = "VeilHunter_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $dlg.Title    = "Export Findings"
    if ($dlg.ShowDialog() -eq "OK") {
        Export-Findings $dlg.FileName
        $lblStatus.Text = "Exported: $(Split-Path $dlg.FileName -Leaf)"
        Write-Host "[+] Exported to: $($dlg.FileName)" -ForegroundColor Green
    }
})

Write-Host "VeilHunter v2 launcher open. Select modules and click Run Hunt." -ForegroundColor Cyan
Write-Host "Results will print here in the console." -ForegroundColor DarkGray
Write-Host ""

$form.Add_Shown({ $form.Activate() })
[void]$form.ShowDialog()
