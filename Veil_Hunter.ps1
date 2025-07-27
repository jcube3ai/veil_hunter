<#
.SYNOPSIS
  VeilHunter — Exotic persistence hunter with native‑only fallbacks (no Sysmon required).
.DESCRIPTION
  GUI toggles multiple exotic persistence hunts:
    • Scheduled Tasks via event log or folder scan
    • Service Path Tampering via System event or registry scan
    • WMI Event Subscriptions via event log or WMI query
    • BITS Jobs via event log or Get-BitsTransfer
    • Registry Run‑Keys & IFEO via registry audit or direct scan
    • AT Jobs via WMI class
    • DLL Hijacks via IFEO & COM registry paths
#>
Add-Type -AssemblyName System.Windows.Forms, System.Drawing

# Build Form
$form = New-Object System.Windows.Forms.Form
$form.Text            = 'VeilHuntPlusUI — Exotic Persistence Hunter'
$form.ClientSize      = New-Object System.Drawing.Size(600,520)
$form.StartPosition   = 'CenterScreen'
$form.FormBorderStyle = 'FixedDialog'; $form.MaximizeBox = $false

# Panel & Results Box
$panel = New-Object System.Windows.Forms.Panel
$panel.Size       = New-Object System.Drawing.Size(260,440)
$panel.Location   = New-Object System.Drawing.Point(10,10)
$panel.AutoScroll = $true
$form.Controls.Add($panel)

$ResultsBox = New-Object System.Windows.Forms.TextBox
$ResultsBox.Multiline    = $true
$ResultsBox.ScrollBars   = 'Vertical'
$ResultsBox.ReadOnly     = $true
$ResultsBox.WordWrap     = $true
$ResultsBox.Font         = New-Object System.Drawing.Font('Consolas',10)
$ResultsBox.Location     = New-Object System.Drawing.Point(280,10)
$ResultsBox.Size         = New-Object System.Drawing.Size(310,440)
$form.Controls.Add($ResultsBox)

# Helper
function Log { param($line) $ResultsBox.AppendText("$line`r`n"); Write-Host $line }

# 1. Scheduled Tasks (EventLog or folder fallback)
function Hunt-ScheduledTasks2 {
    Log "`n[Scheduled Tasks]"
    $useLog = Get-WinEvent -ListLog 'Microsoft-Windows-TaskScheduler/Operational' -ErrorAction SilentlyContinue
    if ($useLog) {
        $events = Get-WinEvent -LogName 'Microsoft-Windows-TaskScheduler/Operational' -MaxEvents 100 -ErrorAction SilentlyContinue |
                  Where-Object { $_.Id -in 106,140 }
        if ($events -and $events.Count -gt 0) {
            foreach ($e in $events) {
                $d = $e.TimeCreated
                $m = $e.Message -replace '\r?\n',' '
                Log "[$d] EVT#$($e.Id): $m"
            }
            return
        }
        Log "No scheduling events found, falling back to folder scan..."
    }
    # Fallback: scan task folder
    Get-ChildItem "$env:WINDIR\System32\Tasks" -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        Log "File: $($_.FullName) Modified: $($_.LastWriteTime)"
    }
}

# 2. Service Path Tampering
function Hunt-ServiceTampering {
    Log "`n[Service Tampering]"
    $useLog = Get-WinEvent -ListLog System -ErrorAction SilentlyContinue
    if ($useLog) {
        Get-WinEvent -LogName System -FilterXPath "*[System[(EventID=7045)]]" -MaxEvents 50 -ErrorAction SilentlyContinue |
          ForEach-Object { $msg=$_.Message -replace '\r?\n',' '; Log "[$($_.TimeCreated)] $msg" }
    } else {
        Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\*' -Name ImagePath -ErrorAction SilentlyContinue |
          ForEach-Object { Log "Service: $($_.PSChildName) -> $($_.ImagePath)" }
    }
}

# 3. WMI Event Subscriptions
function Hunt-WmiSubscriptions {
    Log "`n[WMI Event Subscriptions]"
    $useLog = Get-WinEvent -ListLog 'Microsoft-Windows-WMI-Activity/Operational' -ErrorAction SilentlyContinue
    if ($useLog) {
        $events = Get-WinEvent -LogName 'Microsoft-Windows-WMI-Activity/Operational' -MaxEvents 100 -ErrorAction SilentlyContinue |
                  Where-Object { $_.Id -in 5858,5859,5861 }
        if ($events) {
            foreach ($e in $events) {
                Log "[$($e.TimeCreated)] EVT#$($e.Id): $($e.Message -replace '\r?\n',' ')"
            }
            return
        }
        Log "No WMI subscription events, falling back to WMI query..."
    }
    Get-WmiObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue | ForEach-Object {
        Log "Filter: $($_.Name) => $($_.Query)"
    }
    Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue | ForEach-Object {
        Log "Binding: $($_.Filter) -> $($_.Consumer)"
    }
}

# 4. BITS Jobs
function Hunt-BitsJobs {
    Log "`n[BITS Jobs]"
    $useLog = Get-WinEvent -ListLog 'Microsoft-Windows-Bits-Client/Operational' -ErrorAction SilentlyContinue
    if ($useLog) {
        $events = Get-WinEvent -LogName 'Microsoft-Windows-Bits-Client/Operational' -MaxEvents 50 -ErrorAction SilentlyContinue
        if ($events) {
            foreach ($e in $events) {
                Log "[$($e.TimeCreated)] EVT#$($e.Id): $($e.Message -replace '\r?\n',' ')"
            }
            return
        }
        Log "No BITS client events, falling back to Get-BitsTransfer..."
    }
    Get-BitsTransfer -AllUsers | ForEach-Object {
        Log "Job: $($_.DisplayName) -> $($_.RemoteName) Status: $($_.JobState)"
    }
}

# 5. Registry Run‑Keys & IFEO
function Hunt-RegistryPersistence {
    Log "`n[Run‑Keys & IFEO]"
    $runPaths = @(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'
    )
    foreach ($p in $runPaths) {
        Get-ItemProperty -LiteralPath $p -ErrorAction SilentlyContinue | ForEach-Object {
            $_.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
                Log "RunKey $p\$($_.Name) = $($_.Value)"
            }
        }
    }
    $ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    Get-ChildItem -LiteralPath $ifeo -ErrorAction SilentlyContinue | ForEach-Object {
        $dbg = (Get-ItemProperty -LiteralPath $_.PSPath -Name Debugger -ErrorAction SilentlyContinue).Debugger
        if ($dbg) { Log "IFEO: $($_.PSChildName) -> Debugger: $dbg" }
    }
}

# 6. AT Jobs
function Hunt-AtJobs {
    Log "`n[AT Jobs]"
    Get-WmiObject -Class Win32_ScheduledJob -ErrorAction SilentlyContinue | ForEach-Object {
        Log "JobID $($_.JobId): Command= $($_.Command) StartTime= $($_.StartTime)"
    }
}

# 7. DLL Hijacks via COM/IFEO
function Hunt-DllHijacks2 {
    Log "`n[DLL Hijacks]"
    Get-ChildItem 'HKCR:\CLSID' -Recurse -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -match 'InprocServer32'
    } | ForEach-Object {
        $d = Get-ItemProperty -LiteralPath $_.PSPath -Name '(default)' -ErrorAction SilentlyContinue
        if ($d.'(default)' -and $d.'(default)' -notmatch 'System32') {
            Log "TypeLib Hijack: $($_.PSPath) -> $($d.'(default)')"
        }
    }
}

# UI Checkboxes
$techKeys = [ordered]@{
    'Scheduled Tasks'    = 'Hunt-ScheduledTasks2';
    'Service Tampering'  = 'Hunt-ServiceTampering';
    'WMI Subscriptions'  = 'Hunt-WmiSubscriptions';
    'BITS Jobs'          = 'Hunt-BitsJobs';
    'RunKeys & IFEO'     = 'Hunt-RegistryPersistence';
    'AT Jobs'            = 'Hunt-AtJobs';
    'DLL Hijacks'        = 'Hunt-DllHijacks2'
}
[int]$y = 10; $checkboxes=@{}
foreach ($label in $techKeys.Keys) {
    $cb = New-Object System.Windows.Forms.CheckBox -Property @{Text=$label;AutoSize=$true;Location=[System.Drawing.Point]::new(10,$y)}
    $panel.Controls.Add($cb); $checkboxes[$label]=$cb; $y+=30
}

# Buttons
$btnRun     = New-Object System.Windows.Forms.Button -Property @{Text='Run';Size=[System.Drawing.Size]::new(120,30);Location=[System.Drawing.Point]::new(10,460)}
$btnCleanup = New-Object System.Windows.Forms.Button -Property @{Text='Cleanup';Size=[System.Drawing.Size]::new(120,30);Location=[System.Drawing.Point]::new(140,460)}
$form.Controls.AddRange(@($btnRun,$btnCleanup))

# Button actions
$btnRun.Add_Click({ Clear-Host; $ResultsBox.Clear(); foreach ($t in $checkboxes.Keys) { if ($checkboxes[$t].Checked) { & $techKeys[$t] } } })
$btnCleanup.Add_Click({ Clear-Host; $ResultsBox.Clear() })

# Show UI
$form.Add_Shown({ $form.Activate() }); [void]$form.ShowDialog()