#Requires -Version 5.1
<#
.SYNOPSIS  VeilHunter - Lateral Movement Hunter
           Hunts PSExec/SMB, WMI-based lateral movement, RDP anomalies,
           admin share access, Pass-the-Hash indicators, and token manipulation.
           TTPs: T1021, T1047, T1550, T1534, T1078, T1075
.EXAMPLE   .\VH_Lateral_Hunter.ps1
           .\VH_Lateral_Hunter.ps1 -Headless -OutputPath C:\out.csv
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

function Hunt-SMBLateralMovement {
    # T1021.002 - SMB/Windows Admin Share access
    # EventID 5140=share accessed, 5145=share object checked, 4648=explicit creds used
    if (Get-WinEvent -ListLog Security -EA SilentlyContinue) {
        Get-WinEvent -LogName Security -MaxEvents 1000 -EA SilentlyContinue |
            Where-Object {$_.Id -in 5140,5145,4648 -and $_.TimeCreated -ge $cutoff} |
            ForEach-Object {
                $e=$_
                $share=""; if ($e.Message -match 'Share Name:\s*(.+?)[\r\n]') {$share=$Matches[1].Trim()}
                $src="";   if ($e.Message -match 'Source Address:\s*(.+?)[\r\n]') {$src=$Matches[1].Trim()}
                $acct="";  if ($e.Message -match 'Account Name:\s*(.+?)[\r\n]') {$acct=$Matches[1].Trim()}
                $target="";if ($e.Message -match 'Target Server Name:\s*(.+?)[\r\n]') {$target=$Matches[1].Trim()}
                # Admin shares: C$, ADMIN$, IPC$
                $sev="INFO"
                if ($share -match 'C\$|ADMIN\$|IPC\$') {$sev="HIGH"}
                elseif ($e.Id -eq 4648) {$sev="MED"} # explicit creds = lateral movement signal
                if ($sev -eq "INFO" -and $e.Id -eq 5140) {return} # skip routine share access
                $detail="Time: $($e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')) | Account: $acct"
                if ($share)  {$detail+=" | Share: $share"}
                if ($src)    {$detail+=" | Source IP: $src"}
                if ($target) {$detail+=" | Target: $target"}
                Add-Finding -Severity $sev -TechniqueID "T1021.002" -Technique "SMB/Admin Share Access" `
                    -Artifact "EventID $($e.Id)" -Detail $detail | Out-Null
            }
    }
}

function Hunt-WMILateralMovement {
    # T1047 - WMI used for lateral movement (wmiprvse spawning shells)
    $wmiLog="Microsoft-Windows-WMI-Activity/Operational"
    if (Get-WinEvent -ListLog $wmiLog -EA SilentlyContinue) {
        Get-WinEvent -LogName $wmiLog -MaxEvents 500 -EA SilentlyContinue |
            Where-Object {$_.Id -in 5857,5858,5859,5861 -and $_.TimeCreated -ge $cutoff} |
            ForEach-Object {
                $e=$_
                $op=""; if ($e.Message -match 'Operation\s*=\s*([^;]+)') {$op=$Matches[1].Trim()}
                $user=""; if ($e.Message -match 'User\s*=\s*([^;]+)') {$user=$Matches[1].Trim()}
                # Highlight remote WMI execution patterns
                if ($op -match 'Win32_Process|Win32_Service|StdRegProv' -or $e.Id -in 5859,5861) {
                    $sev=if($op -match 'Win32_Process'){"HIGH"}else{"MED"}
                    Add-Finding -Severity $sev -TechniqueID "T1047" -Technique "WMI Lateral Movement" `
                        -Artifact "EventID $($e.Id) @ $($e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))" `
                        -Detail "User: $user | Operation: $($op.Substring(0,[Math]::Min(100,$op.Length)))" | Out-Null
                }
            }
    }
    # wmiprvse.exe spawning cmd/powershell = strong lateral movement signal
    Get-WinEvent -LogName Security -MaxEvents 1000 -EA SilentlyContinue |
        Where-Object {$_.Id -eq 4688 -and $_.TimeCreated -ge $cutoff} |
        ForEach-Object {
            $e=$_
            $parent=""; if ($e.Message -match 'Creator Process Name:\s*(.+?)[\r\n]') {$parent=$Matches[1].Trim()}
            $child="";  if ($e.Message -match 'New Process Name:\s*(.+?)[\r\n]') {$child=$Matches[1].Trim()}
            if ($parent -match 'wmiprvse' -and $child -match 'cmd\.exe|powershell|wscript|cscript|mshta') {
                Add-Finding -Severity "HIGH" -TechniqueID "T1047" -Technique "WMI Process Spawn" `
                    -Artifact "wmiprvse.exe -> $([System.IO.Path]::GetFileName($child))" `
                    -Detail "Time: $($e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')) | Parent: $parent | Child: $child" | Out-Null
            }
        }
}

function Hunt-RDPLateralMovement {
    # T1021.001 - Remote Desktop suspicious patterns
    $rdpLog="Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"
    if (Get-WinEvent -ListLog $rdpLog -EA SilentlyContinue) {
        Get-WinEvent -LogName $rdpLog -MaxEvents 200 -EA SilentlyContinue |
            Where-Object {$_.Id -in 1149,4625 -and $_.TimeCreated -ge $cutoff} |
            ForEach-Object {
                $e=$_
                $user=""; if ($e.Message -match 'User:\s*(.+?)[\r\n]|User Authentication:\s*(.+?)[\r\n]') {
                    $user=($Matches[1]+$Matches[2]).Trim() }
                $src=""; if ($e.Message -match 'Source Network Address:\s*(.+?)[\r\n]') {$src=$Matches[1].Trim()}
                $sev=if($e.Id -eq 4625){"HIGH"}else{"MED"} # 4625=failed logon
                Add-Finding -Severity $sev -TechniqueID "T1021.001" -Technique "RDP Connection" `
                    -Artifact "EventID $($e.Id) @ $($e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))" `
                    -Detail "User: $user | Source: $src" | Out-Null
            }
    }
    # Check if RDP is enabled unexpectedly
    $rdpKey='HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    $denied=(Get-ItemProperty $rdpKey -Name fDenyTSConnections -EA SilentlyContinue).fDenyTSConnections
    if ($denied -eq 0) {
        Add-Finding -Severity "MED" -TechniqueID "T1021.001" -Technique "RDP Enabled" `
            -Artifact "fDenyTSConnections = 0" `
            -Detail "RDP is currently enabled on this host" -Path $rdpKey | Out-Null
    }
}

function Hunt-PassTheHash {
    # T1550.002 - Pass-the-Hash: NTLM logon type 3 with empty or NTLM package
    if (Get-WinEvent -ListLog Security -EA SilentlyContinue) {
        Get-WinEvent -LogName Security -MaxEvents 1000 -EA SilentlyContinue |
            Where-Object {$_.Id -eq 4624 -and $_.TimeCreated -ge $cutoff} |
            ForEach-Object {
                $e=$_
                $logonType=""; if ($e.Message -match 'Logon Type:\s*(\d+)') {$logonType=$Matches[1].Trim()}
                $pkg=""; if ($e.Message -match 'Authentication Package:\s*(.+?)[\r\n]') {$pkg=$Matches[1].Trim()}
                $acct=""; if ($e.Message -match 'Account Name:\s*(.+?)[\r\n]') {$acct=$Matches[1].Trim()}
                $src=""; if ($e.Message -match 'Workstation Name:\s*(.+?)[\r\n]') {$src=$Matches[1].Trim()}
                $ip=""; if ($e.Message -match 'Source Network Address:\s*(.+?)[\r\n]') {$ip=$Matches[1].Trim()}
                # Type 3 + NTLM over network = PtH indicator (exclude machine accounts)
                if ($logonType -eq "3" -and $pkg -match "NTLM" -and $acct -notmatch '\$$' -and $ip -and $ip -ne "-" -and $ip -ne "127.0.0.1") {
                    Add-Finding -Severity "HIGH" -TechniqueID "T1550.002" -Technique "Pass-the-Hash (NTLM Network Logon)" `
                        -Artifact "EventID 4624 @ $($e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))" `
                        -Detail "Account: $acct | LogonType: $logonType (Network) | Package: $pkg | SourceIP: $ip | Workstation: $src" | Out-Null
                }
            }
    }
}

function Hunt-PSExecPatterns {
    # T1569.002 - PSExec and similar (PSEXESVC service + EventID 7045)
    $svcKey='HKLM:\SYSTEM\CurrentControlSet\Services'
    $psexecSvcs=@('PSEXESVC','paexec','remcom','csexec')
    foreach ($svc in $psexecSvcs) {
        $k=Join-Path $svcKey $svc
        if (Test-Path $k -EA SilentlyContinue) {
            $img=(Get-ItemProperty $k -Name ImagePath -EA SilentlyContinue).ImagePath
            Add-Finding -Severity "HIGH" -TechniqueID "T1569.002" -Technique "PSExec/Remote Exec Service" `
                -Artifact "Service: $svc" `
                -Detail "PSExec-style service found in registry | ImagePath: $img" -Path $k | Out-Null
        }
    }
    if (Get-WinEvent -ListLog System -EA SilentlyContinue) {
        Get-WinEvent -LogName System -MaxEvents 200 -EA SilentlyContinue |
            Where-Object {$_.Id -eq 7045 -and $_.TimeCreated -ge $cutoff `
                -and $_.Message -match 'PSEXE|paexec|remcom'} |
            ForEach-Object {
                $e=$_
                $svcName=($e.Message -split '\r?\n'|Where-Object{$_.Trim()}|Select-Object -First 1).Trim()
                Add-Finding -Severity "HIGH" -TechniqueID "T1569.002" -Technique "PSExec Service Install" `
                    -Artifact "EventID 7045 @ $($e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))" `
                    -Detail "PSExec-style service installed | Service: $svcName" | Out-Null
            }
    }
}

if ($Headless) {
    Print-Banner "Lateral Movement Hunter -- $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Lookback: $LookbackHours h"
    Print-Section "SMB/Admin Shares (T1021.002)";    Hunt-SMBLateralMovement
    Print-Section "WMI Lateral (T1047)";             Hunt-WMILateralMovement
    Print-Section "RDP (T1021.001)";                 Hunt-RDPLateralMovement
    Print-Section "Pass-the-Hash (T1550.002)";       Hunt-PassTheHash
    Print-Section "PSExec/Remote Exec (T1569.002)";  Hunt-PSExecPatterns
    Print-Banner "RESULTS"; Print-AllFindings; Export-AllFindings $OutputPath; exit 0
}

Add-Type -AssemblyName System.Windows.Forms,System.Drawing
$mods=[ordered]@{
    "SMB / Admin Shares (T1021.002)"    ="Hunt-SMBLateralMovement"
    "WMI Lateral Movement (T1047)"      ="Hunt-WMILateralMovement"
    "RDP Anomalies (T1021.001)"         ="Hunt-RDPLateralMovement"
    "Pass-the-Hash (T1550.002)"         ="Hunt-PassTheHash"
    "PSExec / Remote Exec (T1569.002)"  ="Hunt-PSExecPatterns"
}
$CB_X=12;$BTN_W=130;$BTN_H=32;$MAR=10;$FW=290
$frm=New-Object System.Windows.Forms.Form;$frm.Text="Lateral Movement Hunter"
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
    Print-Banner "Lateral Movement Hunter -- $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    foreach($l in $sel){$lbS.Text="Running: $l";[System.Windows.Forms.Application]::DoEvents()
        Print-Section $l;&$mods[$l];[System.Windows.Forms.Application]::DoEvents()}
    Print-Banner "RESULTS";Print-AllFindings
    $h=($script:Findings|Where-Object Severity -eq "HIGH").Count;$m=($script:Findings|Where-Object Severity -eq "MED").Count
    $lbS.Text="Done -- HIGH: $h  MED: $m  Total: $($script:Findings.Count)";$btnR.Enabled=$true;$btnE.Enabled=$true})
$btnE.Add_Click({
    if($script:Findings.Count -eq 0){[System.Windows.Forms.MessageBox]::Show("Run a hunt first.","No Findings",
        [System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Information)|Out-Null;return}
    $d=New-Object System.Windows.Forms.SaveFileDialog;$d.Filter="CSV Files (*.csv)|*.csv"
    $d.FileName="LateralHunter_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    if($d.ShowDialog() -eq "OK"){Export-AllFindings $d.FileName;$lbS.Text="Exported: $(Split-Path $d.FileName -Leaf)"}})
Write-Host "Lateral Movement Hunter ready. Results print here." -ForegroundColor Cyan
$frm.Add_Shown({$frm.Activate()});[void]$frm.ShowDialog()
