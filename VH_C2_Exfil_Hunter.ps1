#Requires -Version 5.1
<#
.SYNOPSIS  VeilHunter - C2 + Exfiltration Hunter
           Hunts DNS beaconing patterns, BITS transfer abuse, suspicious network
           connections, named pipe C2, protocol tunneling, and cloud exfil staging.
           TTPs: T1071, T1048, T1197, T1572, T1132, T1041
.EXAMPLE   .\VH_C2_Exfil_Hunter.ps1
           .\VH_C2_Exfil_Hunter.ps1 -Headless -OutputPath C:\out.csv
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

function Hunt-SuspiciousConnections {
    # T1071 - Active network connections to unusual destinations
    $conns=Get-NetTCPConnection -State Established,Listen -EA SilentlyContinue
    $suspPorts=@(4444,5555,1337,31337,8443,8080,9001,9002,6666,2222,1234)
    $suspProcs=@('powershell','cmd','wscript','cscript','mshta','rundll32','regsvr32','certutil','curl','wget')
    foreach ($c in $conns) {
        $proc="Unknown"; $pid=$c.OwningProcess
        try { $proc=(Get-Process -Id $pid -EA Stop).Name } catch {}
        $sev="INFO"
        if ($suspPorts -contains $c.LocalPort -or $suspPorts -contains $c.RemotePort) {$sev="HIGH"}
        if ($suspProcs -contains $proc.ToLower()) {$sev="HIGH"}
        if ($c.RemoteAddress -match '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)') {continue} # skip RFC1918
        if ($c.RemoteAddress -eq "0.0.0.0" -or $c.RemoteAddress -eq "::" -or $c.RemoteAddress -eq "127.0.0.1") {continue}
        if ($sev -eq "INFO") {continue}
        Add-Finding -Severity $sev -TechniqueID "T1071" -Technique "Suspicious Network Connection" `
            -Artifact "PID $pid ($proc)" `
            -Detail "State: $($c.State) | Local: $($c.LocalAddress):$($c.LocalPort) | Remote: $($c.RemoteAddress):$($c.RemotePort)" | Out-Null
    }
    # Listening on unusual ports by non-system processes
    foreach ($c in ($conns|Where-Object{$_.State -eq "Listen"})) {
        $pid=$c.OwningProcess; $proc="Unknown"
        try { $proc=(Get-Process -Id $pid -EA Stop).Name } catch {}
        if ($suspPorts -contains $c.LocalPort -or ($suspProcs -contains $proc.ToLower() -and $c.LocalPort -gt 1024)) {
            Add-Finding -Severity "HIGH" -TechniqueID "T1071" -Technique "Suspicious Listener" `
                -Artifact "PID $pid ($proc) listening on :$($c.LocalPort)" `
                -Detail "Process $proc has an unexpected network listener" | Out-Null
        }
    }
}

function Hunt-BITSAbuse {
    # T1197 - BITS transfer abuse for C2/exfil
    $bitsLog="Microsoft-Windows-Bits-Client/Operational"
    if (Get-WinEvent -ListLog $bitsLog -EA SilentlyContinue) {
        Get-WinEvent -LogName $bitsLog -MaxEvents 200 -EA SilentlyContinue |
            Where-Object {$_.TimeCreated -ge $cutoff} |
            ForEach-Object {
                $e=$_
                $url=""; if ($e.Message -match 'url\s*=\s*(.+?)[\r\n;]|URL\s*:\s*(.+?)[\r\n]') {
                    $url=($Matches[1]+$Matches[2]).Trim() }
                $job=""; if ($e.Message -match 'job\s*name\s*=\s*(.+?)[\r\n;]|Job Name:\s*(.+?)[\r\n]') {
                    $job=($Matches[1]+$Matches[2]).Trim() }
                if ($url -and $url -notmatch 'microsoft\.com|windows\.com|windowsupdate\.com') {
                    $sev=if($e.Id -in 3,59,60){"HIGH"}else{"MED"}
                    Add-Finding -Severity $sev -TechniqueID "T1197" -Technique "BITS Suspicious Transfer" `
                        -Artifact "EventID $($e.Id) @ $($e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))" `
                        -Detail "Job: $job | URL: $url" | Out-Null
                }
            }
    }
    Get-BitsTransfer -AllUsers -EA SilentlyContinue | ForEach-Object {
        if ($_.RemoteName -notmatch 'microsoft\.com|windows\.com|windowsupdate\.com') {
            $sev=if($_.JobState -in "Transferring","Connecting"){"HIGH"}else{"MED"}
            Add-Finding -Severity $sev -TechniqueID "T1197" -Technique "BITS Active Transfer" `
                -Artifact "Job: $($_.DisplayName)" `
                -Detail "State: $($_.JobState) | Remote: $($_.RemoteName) | Owner: $($_.OwnerAccount)" `
                -Path $_.LocalName | Out-Null
        }
    }
}

function Hunt-NamedPipes {
    # T1071.004 / T1572 - Named pipe C2 (common in Cobalt Strike, Meterpeter, etc.)
    $csPipes=@('msagent_','postex_','mojo\.','\\pipe\\MSSE-','\\pipe\\status_','\\pipe\\samr','\\pipe\\netlogon')
    try {
        $pipes=[System.IO.Directory]::GetFiles('\\.\pipe\')
        foreach ($p in $pipes) {
            $pname=[System.IO.Path]::GetFileName($p)
            $sev="INFO"
            foreach ($pat in $csPipes) { if ($pname -match $pat) {$sev="HIGH"; break} }
            if ($pname -match 'meterpreter|beacon|cobaltstrike|empire|havoc|sliver|brute') {$sev="HIGH"}
            if ($sev -eq "HIGH") {
                Add-Finding -Severity "HIGH" -TechniqueID "T1572" -Technique "Suspicious Named Pipe" `
                    -Artifact "Pipe: $pname" `
                    -Detail "Named pipe matches known C2 framework pattern (CobaltStrike/Meterpreter/Empire/Sliver)" | Out-Null
            }
        }
    } catch {}
}

function Hunt-DNSBeaconing {
    # T1071.004 - DNS query patterns (requires DNS debug log or PowerShell DNS cache)
    # Check DNS client cache for suspicious entries
    try {
        $dnsCache=Get-DnsClientCache -EA Stop | Where-Object {$_.TimeToLive -lt 60}
        $suspTLDs=@('.ru','.cn','.tk','.xyz','.top','.pw','.cc','.su','.biz','.info')
        foreach ($entry in $dnsCache) {
            foreach ($tld in $suspTLDs) {
                if ($entry.Name -like "*$tld") {
                    Add-Finding -Severity "MED" -TechniqueID "T1071.004" -Technique "Suspicious DNS Cache Entry" `
                        -Artifact $entry.Name `
                        -Detail "Low TTL ($($entry.TimeToLive)s) to suspicious TLD | Data: $($entry.Data)" | Out-Null
                    break
                }
            }
        }
    } catch {}
    # Check for DNS over HTTPS providers set by malware
    $dohKey='HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters'
    $doh=(Get-ItemProperty $dohKey -Name EnableAutoDoh -EA SilentlyContinue).EnableAutoDoh
    if ($doh -eq 2) {
        Add-Finding -Severity "MED" -TechniqueID "T1071.004" -Technique "DNS over HTTPS Enabled" `
            -Artifact "EnableAutoDoh = 2" `
            -Detail "DNS over HTTPS is enabled - may be used to tunnel C2 traffic past DNS monitoring" -Path $dohKey | Out-Null
    }
}

function Hunt-CloudExfilStaging {
    # T1048 - Exfiltration via cloud storage (files staged for upload)
    $cloudPaths=@{
        "OneDrive" = "$env:USERPROFILE\OneDrive"
        "Dropbox"  = "$env:USERPROFILE\Dropbox"
        "GoogleDrive" = "$env:USERPROFILE\Google Drive"
        "Box"      = "$env:USERPROFILE\Box"
        "iCloud"   = "$env:USERPROFILE\iCloudDrive"
    }
    $exfilExts='\.zip$|\.rar$|\.7z$|\.tar$|\.gz$|\.db$|\.sqlite$|\.mdb$|\.kdbx$|\.pst$|\.ost$'
    foreach ($cloud in $cloudPaths.Keys) {
        $p=$cloudPaths[$cloud]
        if (-not (Test-Path $p -EA SilentlyContinue)) {continue}
        Get-ChildItem $p -Recurse -File -EA SilentlyContinue |
            Where-Object {$_.LastWriteTime -ge $cutoff -and $_.Name -match $exfilExts} |
            ForEach-Object {
                Add-Finding -Severity "HIGH" -TechniqueID "T1048" -Technique "Cloud Exfil Staging" `
                    -Artifact "$cloud : $($_.Name)" `
                    -Detail "Archive/DB file in cloud sync folder | Size: $([math]::Round($_.Length/1MB,2))MB | Modified: $($_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))" `
                    -Path $_.FullName | Out-Null
            }
    }
}

if ($Headless) {
    Print-Banner "C2 + Exfil Hunter -- $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Lookback: $LookbackHours h"
    Print-Section "Suspicious Connections (T1071)";   Hunt-SuspiciousConnections
    Print-Section "BITS Abuse (T1197)";               Hunt-BITSAbuse
    Print-Section "Named Pipe C2 (T1572)";            Hunt-NamedPipes
    Print-Section "DNS Beaconing (T1071.004)";        Hunt-DNSBeaconing
    Print-Section "Cloud Exfil Staging (T1048)";      Hunt-CloudExfilStaging
    Print-Banner "RESULTS"; Print-AllFindings; Export-AllFindings $OutputPath; exit 0
}

Add-Type -AssemblyName System.Windows.Forms,System.Drawing
$mods=[ordered]@{
    "Suspicious Connections (T1071)"  ="Hunt-SuspiciousConnections"
    "BITS Abuse (T1197)"              ="Hunt-BITSAbuse"
    "Named Pipe C2 (T1572)"           ="Hunt-NamedPipes"
    "DNS Beaconing (T1071.004)"       ="Hunt-DNSBeaconing"
    "Cloud Exfil Staging (T1048)"     ="Hunt-CloudExfilStaging"
}
$CB_X=12;$BTN_W=130;$BTN_H=32;$MAR=10;$FW=300
$frm=New-Object System.Windows.Forms.Form;$frm.Text="C2 + Exfil Hunter"
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
    Print-Banner "C2 + Exfil Hunter -- $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    foreach($l in $sel){$lbS.Text="Running: $l";[System.Windows.Forms.Application]::DoEvents()
        Print-Section $l;&$mods[$l];[System.Windows.Forms.Application]::DoEvents()}
    Print-Banner "RESULTS";Print-AllFindings
    $h=($script:Findings|Where-Object Severity -eq "HIGH").Count;$m=($script:Findings|Where-Object Severity -eq "MED").Count
    $lbS.Text="Done -- HIGH: $h  MED: $m  Total: $($script:Findings.Count)";$btnR.Enabled=$true;$btnE.Enabled=$true})
$btnE.Add_Click({
    if($script:Findings.Count -eq 0){[System.Windows.Forms.MessageBox]::Show("Run a hunt first.","No Findings",
        [System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Information)|Out-Null;return}
    $d=New-Object System.Windows.Forms.SaveFileDialog;$d.Filter="CSV Files (*.csv)|*.csv"
    $d.FileName="C2ExfilHunter_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    if($d.ShowDialog() -eq "OK"){Export-AllFindings $d.FileName;$lbS.Text="Exported: $(Split-Path $d.FileName -Leaf)"}})
Write-Host "C2 + Exfil Hunter ready. Results print here." -ForegroundColor Cyan
$frm.Add_Shown({$frm.Activate()});[void]$frm.ShowDialog()
