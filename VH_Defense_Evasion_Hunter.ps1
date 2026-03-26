#Requires -Version 5.1
<#
.SYNOPSIS  VeilHunter - Defense Evasion Hunter
           Hunts AMSI bypass artifacts, ETW patching, AV/FW disablement,
           log clearing, timestomping, masquerading, and process injection indicators.
           TTPs: T1562, T1070, T1036, T1055, T1497, T1027, T1112
.EXAMPLE   .\VH_Defense_Evasion_Hunter.ps1
           .\VH_Defense_Evasion_Hunter.ps1 -Headless -OutputPath C:\out.csv
#>
[CmdletBinding()]
param([switch]$Headless,[int]$LookbackHours=72,[string]$OutputPath="")
Set-StrictMode -Version Latest; $ErrorActionPreference="SilentlyContinue"
# VeilHunter Shared Helpers v2
$script:Findings = [System.Collections.Generic.List[pscustomobject]]::new()

function Add-Finding {
    param([ValidateSet("HIGH","MED","INFO")][string]$Severity,
          [string]$TechniqueID,[string]$Technique,
          [string]$Artifact,[string]$Detail,[string]$Path="")
    $f = [pscustomobject]@{
        Timestamp=(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        Severity=$Severity;TechniqueID=$TechniqueID;Technique=$Technique
        Artifact=$Artifact;Detail=$Detail;Path=$Path }
    $script:Findings.Add($f); return $f
}

function Print-Finding([pscustomobject]$f) {
    $color = switch ($f.Severity) { "HIGH"{"Red"} "MED"{"Yellow"} default{"Gray"} }
    $sev   = switch ($f.Severity) { "HIGH"{"[HIGH]"} "MED"{"[MED] "} default{"[INFO]"} }
    Write-Host "$sev [$($f.TechniqueID)] $($f.Technique)" -ForegroundColor $color
    Write-Host "       Artifact : $($f.Artifact)" -ForegroundColor $color
    if ($f.Detail) {
        $f.Detail -split '\|' | ForEach-Object {
            $l = $_.Trim(); if ($l) { Write-Host "       $l" -ForegroundColor $color }
        }
    }
    if ($f.Path) { Write-Host "       Path     : $($f.Path)" -ForegroundColor DarkGray }
    Write-Host ""
}
function Print-Banner([string]$Text) {
    Write-Host ""; Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor Cyan; Write-Host ("=" * 70) -ForegroundColor Cyan
}
function Print-Section([string]$Text) {
    Write-Host ""; Write-Host "-- $Text --" -ForegroundColor DarkCyan
}
function Print-AllFindings {
    $grouped = $script:Findings | Group-Object Severity | Sort-Object {
        switch ($_.Name) { "HIGH"{0} "MED"{1} default{2} } }
    foreach ($grp in $grouped) {
        Print-Section "$($grp.Name) ($($grp.Count) finding(s))"
        foreach ($f in $grp.Group) { Print-Finding $f }
    }
    $h=($script:Findings|Where-Object Severity -eq "HIGH").Count
    $m=($script:Findings|Where-Object Severity -eq "MED").Count
    Write-Host ""
    Write-Host "Total: $($script:Findings.Count)  HIGH: $h  MED: $m  INFO: $($script:Findings.Count-$h-$m)" -ForegroundColor Cyan
}
function Export-AllFindings([string]$Path) {
    if (-not $Path -or $script:Findings.Count -eq 0) { return }
    $script:Findings | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8 -Force
    Write-Host "[+] Exported $($script:Findings.Count) findings to: $Path" -ForegroundColor Green
}
function Get-SigStatus([string]$raw) {
    $p = $raw -replace '^"([^"]+)".*','$1' -replace '^(\S+).*','$1'; $p=$p.Trim()
    if (-not $p -or -not (Test-Path $p -EA SilentlyContinue)) { return "FILE_NOT_FOUND" }
    try { return (Get-AuthenticodeSignature $p -EA Stop).Status.ToString() } catch { return "UNKNOWN" }
}
$cutoff=(Get-Date).AddHours(-$LookbackHours)

function Hunt-AMSIBypass {
    # T1562.001 - AMSI bypass via registry
    $amsiKey='HKLM:\SOFTWARE\Microsoft\AMSI'
    $amsiProviders=Get-ChildItem $amsiKey -EA SilentlyContinue
    if ($amsiProviders) {
        foreach ($p in $amsiProviders) {
            $dll=(Get-ItemProperty $p.PSPath -Name "(default)" -EA SilentlyContinue)."(default)"
            if ($dll) {
                $sig=Get-SigStatus $dll
                $sev=if($sig -ne "Valid"){"HIGH"}else{"INFO"}
                Add-Finding -Severity $sev -TechniqueID "T1562.001" -Technique "AMSI Provider" `
                    -Artifact "Provider: $($p.PSChildName)" `
                    -Detail "DLL: $dll | Signature: $sig" -Path $dll | Out-Null
            }
        }
    }
    # ScriptBlock logging disabled (AMSI evasion via policy)
    $sbLog='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    if (Test-Path $sbLog -EA SilentlyContinue) {
        $enabled=(Get-ItemProperty $sbLog -Name EnableScriptBlockLogging -EA SilentlyContinue).EnableScriptBlockLogging
        if ($enabled -eq 0) {
            Add-Finding -Severity "HIGH" -TechniqueID "T1562.001" -Technique "ScriptBlock Logging Disabled" `
                -Artifact "EnableScriptBlockLogging = 0" `
                -Detail "PowerShell ScriptBlock logging has been disabled via policy" -Path $sbLog | Out-Null
        }
    }
    # Module logging disabled
    $modLog='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
    if (Test-Path $modLog -EA SilentlyContinue) {
        $enabled=(Get-ItemProperty $modLog -Name EnableModuleLogging -EA SilentlyContinue).EnableModuleLogging
        if ($enabled -eq 0) {
            Add-Finding -Severity "HIGH" -TechniqueID "T1562.001" -Technique "Module Logging Disabled" `
                -Artifact "EnableModuleLogging = 0" `
                -Detail "PowerShell Module logging has been disabled via policy" -Path $modLog | Out-Null
        }
    }
}

function Hunt-DefenderTampering {
    # T1562.001 - Windows Defender disabled or tampered
    $defKey='HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
    $dav=(Get-ItemProperty $defKey -Name DisableAntiSpyware -EA SilentlyContinue).DisableAntiSpyware
    if ($dav -eq 1) {
        Add-Finding -Severity "HIGH" -TechniqueID "T1562.001" -Technique "Defender Disabled" `
            -Artifact "DisableAntiSpyware = 1" `
            -Detail "Windows Defender has been disabled via policy registry key" -Path $defKey | Out-Null
    }
    $rtpKey="$defKey\Real-Time Protection"
    $rtp=(Get-ItemProperty $rtpKey -Name DisableRealtimeMonitoring -EA SilentlyContinue).DisableRealtimeMonitoring
    if ($rtp -eq 1) {
        Add-Finding -Severity "HIGH" -TechniqueID "T1562.001" -Technique "Defender Real-Time Protection Disabled" `
            -Artifact "DisableRealtimeMonitoring = 1" `
            -Detail "Defender real-time monitoring disabled via registry" -Path $rtpKey | Out-Null
    }
    # Defender exclusion paths (used to hide malware)
    $excKey="$defKey\Exclusions\Paths"
    if (Test-Path $excKey -EA SilentlyContinue) {
        Get-ItemProperty $excKey -EA SilentlyContinue | ForEach-Object {
            $_.PSObject.Properties | Where-Object {$_.Name -notmatch '^PS'} | ForEach-Object {
                $sev=if($_.Name -match '\\Temp\\|\\AppData\\|\\ProgramData\\|\\Users\\Public\\'){"HIGH"}else{"MED"}
                Add-Finding -Severity $sev -TechniqueID "T1562.001" -Technique "Defender Exclusion Path" `
                    -Artifact "Exclusion: $($_.Name)" `
                    -Detail "This path is excluded from Defender scanning" -Path $_.Name | Out-Null
            }
        }
    }
}

function Hunt-EventLogTampering {
    # T1070.001 - Event log cleared or audit policy disabled
    if (Get-WinEvent -ListLog Security -EA SilentlyContinue) {
        Get-WinEvent -LogName Security -MaxEvents 100 -EA SilentlyContinue |
            Where-Object {$_.Id -in 1100,1102,1104 -and $_.TimeCreated -ge $cutoff} |
            ForEach-Object {
                $e=$_
                $evtDesc=switch($e.Id){1100{"EventLog service shutdown"};1102{"Security audit log CLEARED"};1104{"Security log full"}}
                $user=""; if ($e.Message -match 'Subject.*?Account Name:\s*(.+?)[\r\n]') {$user=$Matches[1].Trim()}
                Add-Finding -Severity "HIGH" -TechniqueID "T1070.001" -Technique "Event Log Tampering" `
                    -Artifact "EventID $($e.Id) @ $($e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))" `
                    -Detail "$evtDesc | User: $user" | Out-Null
            }
    }
    # System log cleared (7)
    if (Get-WinEvent -ListLog System -EA SilentlyContinue) {
        Get-WinEvent -LogName System -MaxEvents 50 -EA SilentlyContinue |
            Where-Object {$_.Id -eq 104 -and $_.TimeCreated -ge $cutoff} |
            ForEach-Object {
                Add-Finding -Severity "HIGH" -TechniqueID "T1070.001" -Technique "Event Log Cleared" `
                    -Artifact "EventID 104 @ $($_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))" `
                    -Detail "System event log was cleared" | Out-Null
            }
    }
}

function Hunt-Masquerading {
    # T1036 - Processes/files masquerading as legitimate tools
    $suspLocations=@("$env:TEMP","$env:USERPROFILE\Downloads","C:\ProgramData","C:\Windows\Temp","C:\Users\Public")
    $legit=@('svchost','lsass','csrss','smss','wininit','winlogon','services','explorer','taskhost','dwm')
    foreach ($loc in $suspLocations) {
        if (-not (Test-Path $loc -EA SilentlyContinue)) {continue}
        Get-ChildItem $loc -File -EA SilentlyContinue | Where-Object {$_.LastWriteTime -ge $cutoff} |
            ForEach-Object {
                $name=[System.IO.Path]::GetFileNameWithoutExtension($_.Name).ToLower()
                if ($legit -contains $name) {
                    $sig=Get-SigStatus $_.FullName
                    Add-Finding -Severity "HIGH" -TechniqueID "T1036.005" -Technique "Masquerading - Legit Process Name" `
                        -Artifact $_.Name `
                        -Detail "Legit Windows process name in non-system location | Signature: $sig | Modified: $($_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))" `
                        -Path $_.FullName | Out-Null
                }
            }
    }
    # System32 lookalike paths
    $lookalikes=@('C:\Windows\System32s','C:\Windows\Sysyem32','C:\Windovvs')
    foreach ($l in $lookalikes) {
        if (Test-Path $l -EA SilentlyContinue) {
            Add-Finding -Severity "HIGH" -TechniqueID "T1036.005" -Technique "Masquerading - Lookalike System Dir" `
                -Artifact $l -Detail "Lookalike Windows system directory exists on disk" -Path $l | Out-Null
        }
    }
}

function Hunt-ProcessInjectionIndicators {
    # T1055 - Suspicious DLL loading and process injection artifacts
    $suspDLLPaths='\\Users\\|\\AppData\\|\\Temp\\|\\ProgramData\\'
    $sys32='C:\Windows\System32'; $syswow='C:\Windows\SysWOW64'
    # AppInit_DLLs (T1546.010) - common injection vector
    $appKey='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'
    $appInit=(Get-ItemProperty $appKey -Name AppInit_DLLs -EA SilentlyContinue).AppInit_DLLs
    if ($appInit -and $appInit.Trim()) {
        Add-Finding -Severity "HIGH" -TechniqueID "T1055.001" -Technique "AppInit_DLLs Injection" `
            -Artifact "AppInit_DLLs" `
            -Detail "Value: $appInit | These DLLs are loaded into every user-mode process" -Path $appKey | Out-Null
    }
    # Suspicious unsigned DLLs in System32 (DLL planting)
    Get-ChildItem $sys32 -Filter "*.dll" -File -EA SilentlyContinue |
        Where-Object {$_.LastWriteTime -ge $cutoff} |
        ForEach-Object {
            $sig=Get-SigStatus $_.FullName
            if ($sig -in "NotSigned","HashMismatch") {
                Add-Finding -Severity "HIGH" -TechniqueID "T1574.001" -Technique "Unsigned DLL in System32" `
                    -Artifact $_.Name `
                    -Detail "Unsigned DLL planted in System32 | Signature: $sig | Modified: $($_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))" `
                    -Path $_.FullName | Out-Null
            }
        }
}

function Hunt-Timestomping {
    # T1070.006 - Files with suspicious timestamp mismatches (compile time vs filesystem time)
    $suspPaths=@("$env:TEMP","$env:USERPROFILE\Downloads","C:\ProgramData","C:\Windows\Temp")
    foreach ($sp in $suspPaths) {
        if (-not (Test-Path $sp -EA SilentlyContinue)) {continue}
        Get-ChildItem $sp -File -Include "*.exe","*.dll" -EA SilentlyContinue |
            Where-Object {$_.LastWriteTime -ge $cutoff} |
            ForEach-Object {
                $f=$_
                try {
                    $bytes=[System.IO.File]::ReadAllBytes($f.FullName)
                    # PE header timestamp is at offset 0x3C (pointer) + 8 bytes
                    if ($bytes[0] -eq 0x4D -and $bytes[1] -eq 0x5A) { # MZ header
                        $peOffset=[BitConverter]::ToInt32($bytes,0x3C)
                        if ($peOffset -gt 0 -and ($peOffset+8) -lt $bytes.Length) {
                            $peTs=[BitConverter]::ToUInt32($bytes,$peOffset+8)
                            $peDate=[DateTimeOffset]::FromUnixTimeSeconds($peTs).DateTime
                            $fsDiff=($f.LastWriteTime - $peDate).TotalDays
                            # Large discrepancy between PE compile time and filesystem mtime = timestomping
                            if ([Math]::Abs($fsDiff) -gt 365 -and $peDate.Year -gt 1970) {
                                Add-Finding -Severity "HIGH" -TechniqueID "T1070.006" -Technique "Timestomping" `
                                    -Artifact $f.Name `
                                    -Detail "PE compile date: $($peDate.ToString('yyyy-MM-dd')) | Filesystem mtime: $($f.LastWriteTime.ToString('yyyy-MM-dd')) | Discrepancy: $([int]$fsDiff) days" `
                                    -Path $f.FullName | Out-Null
                            }
                        }
                    }
                } catch {}
            }
    }
}

if ($Headless) {
    Print-Banner "Defense Evasion Hunter -- $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Lookback: $LookbackHours h"
    Print-Section "AMSI Bypass (T1562.001)";         Hunt-AMSIBypass
    Print-Section "Defender Tampering (T1562.001)";  Hunt-DefenderTampering
    Print-Section "Event Log Tampering (T1070.001)"; Hunt-EventLogTampering
    Print-Section "Masquerading (T1036)";            Hunt-Masquerading
    Print-Section "Process Injection (T1055)";       Hunt-ProcessInjectionIndicators
    Print-Section "Timestomping (T1070.006)";        Hunt-Timestomping
    Print-Banner "RESULTS"; Print-AllFindings; Export-AllFindings $OutputPath; exit 0
}

Add-Type -AssemblyName System.Windows.Forms,System.Drawing
$mods=[ordered]@{
    "AMSI Bypass (T1562.001)"           ="Hunt-AMSIBypass"
    "Defender Tampering (T1562.001)"    ="Hunt-DefenderTampering"
    "Event Log Tampering (T1070.001)"   ="Hunt-EventLogTampering"
    "Masquerading (T1036)"              ="Hunt-Masquerading"
    "Process Injection (T1055)"         ="Hunt-ProcessInjectionIndicators"
    "Timestomping (T1070.006)"          ="Hunt-Timestomping"
}
$CB_X=12;$BTN_W=130;$BTN_H=32;$MAR=10;$FW=300
$frm=New-Object System.Windows.Forms.Form;$frm.Text="Defense Evasion Hunter"
$frm.StartPosition="Manual";$frm.FormBorderStyle="FixedToolWindow";$frm.TopMost=$true
$frm.MaximizeBox=$false;$frm.MinimizeBox=$false
$sc=[System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea
$frm.Location=New-Object System.Drawing.Point(($sc.Right-$FW-10),$sc.Top+10)
$cbY=12;$cbs=@{}
foreach ($lbl in $mods.Keys){$cb=New-Object System.Windows.Forms.CheckBox;$cb.Text=$lbl;$cb.AutoSize=$true
    $cb.Location=New-Object System.Drawing.Point($CB_X,$cbY);$frm.Controls.Add($cb);$cbs[$lbl]=$cb;$cbY+=28}
$cbAll=New-Object System.Windows.Forms.CheckBox;$cbAll.Text="Select All"
$cbAll.Font=New-Object System.Drawing.Font("Segoe UI",9,[System.Drawing.FontStyle]::Bold);$cbAll.AutoSize=$true
$cbAll.Location=New-Object System.Drawing.Point($CB_X,($cbY+4))
$cbAll.Add_CheckedChanged({foreach($c in $cbs.Values){$c.Checked=$cbAll.Checked}});$frm.Controls.Add($cbAll);$cbY+=36
$sep=New-Object System.Windows.Forms.Label;$sep.BorderStyle="Fixed3D"
$sep.Size=New-Object System.Drawing.Size(($FW-$CB_X*2),2);$sep.Location=New-Object System.Drawing.Point($CB_X,$cbY)
$frm.Controls.Add($sep);$cbY+=10
$btnR=New-Object System.Windows.Forms.Button;$btnR.Text="Run Hunt";$btnR.Size=New-Object System.Drawing.Size($BTN_W,$BTN_H)
$btnR.Location=New-Object System.Drawing.Point($CB_X,$cbY);$btnR.BackColor=[System.Drawing.Color]::FromArgb(0,120,215)
$btnR.ForeColor=[System.Drawing.Color]::White;$btnR.FlatStyle="Flat";$frm.Controls.Add($btnR)
$btnE=New-Object System.Windows.Forms.Button;$btnE.Text="Export CSV";$btnE.Size=New-Object System.Drawing.Size($BTN_W,$BTN_H)
$btnE.Location=New-Object System.Drawing.Point(($CB_X+$BTN_W+$MAR),$cbY);$btnE.FlatStyle="Flat";$frm.Controls.Add($btnE);$cbY+=$BTN_H+$MAR
$lbS=New-Object System.Windows.Forms.Label;$lbS.Text="Ready.";$lbS.AutoSize=$false
$lbS.Size=New-Object System.Drawing.Size(($FW-$CB_X*2),18);$lbS.Font=New-Object System.Drawing.Font("Segoe UI",8)
$lbS.ForeColor=[System.Drawing.Color]::DarkGray;$lbS.Location=New-Object System.Drawing.Point($CB_X,$cbY)
$frm.Controls.Add($lbS);$cbY+=24;$frm.ClientSize=New-Object System.Drawing.Size($FW,$cbY)
$btnR.Add_Click({
    $sel=$cbs.Keys|Where-Object{$cbs[$_].Checked}
    if(-not $sel){[System.Windows.Forms.MessageBox]::Show("Select at least one hunt.","Nothing Selected",
        [System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Warning)|Out-Null;return}
    $btnR.Enabled=$false;$btnE.Enabled=$false;$script:Findings.Clear()
    Print-Banner "Defense Evasion Hunter -- $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    foreach($l in $sel){$lbS.Text="Running: $l";[System.Windows.Forms.Application]::DoEvents()
        Print-Section $l;&$mods[$l];[System.Windows.Forms.Application]::DoEvents()}
    Print-Banner "RESULTS";Print-AllFindings
    $h=($script:Findings|Where-Object Severity -eq "HIGH").Count;$m=($script:Findings|Where-Object Severity -eq "MED").Count
    $lbS.Text="Done -- HIGH: $h  MED: $m  Total: $($script:Findings.Count)";$btnR.Enabled=$true;$btnE.Enabled=$true})
$btnE.Add_Click({
    if($script:Findings.Count -eq 0){[System.Windows.Forms.MessageBox]::Show("Run a hunt first.","No Findings",
        [System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Information)|Out-Null;return}
    $d=New-Object System.Windows.Forms.SaveFileDialog;$d.Filter="CSV Files (*.csv)|*.csv"
    $d.FileName="EvasionHunter_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    if($d.ShowDialog() -eq "OK"){Export-AllFindings $d.FileName;$lbS.Text="Exported: $(Split-Path $d.FileName -Leaf)"}})
Write-Host "Defense Evasion Hunter ready. Results print here." -ForegroundColor Cyan
$frm.Add_Shown({$frm.Activate()});[void]$frm.ShowDialog()
