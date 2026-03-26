#Requires -Version 5.1
<#
.SYNOPSIS  VeilHunter - Pre-Ransomware Indicators Hunter
           Hunts shadow copy enumeration/deletion, backup tampering,
           rapid file extension changes, ransom note drops, inhibit-recovery
           commands, and known ransomware staging behaviors.
           TTPs: T1490, T1489, T1486, T1485, T1562.001
.EXAMPLE   .\VH_PreRansom_Hunter.ps1
           .\VH_PreRansom_Hunter.ps1 -Headless -OutputPath C:\out.csv
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

function Hunt-ShadowCopyDeletion {
    # T1490 - vssadmin/wmic/bcdedit used to delete shadow copies
    if (Get-WinEvent -ListLog Security -EA SilentlyContinue) {
        Get-WinEvent -LogName Security -MaxEvents 1000 -EA SilentlyContinue |
            Where-Object {$_.Id -eq 4688 -and $_.TimeCreated -ge $cutoff} |
            ForEach-Object {
                $e=$_
                $cmd=""; if ($e.Message -match 'Process Command Line:\s*(.+?)[\r\n]') {$cmd=$Matches[1].Trim()}
                $proc=""; if ($e.Message -match 'New Process Name:\s*(.+?)[\r\n]') {$proc=$Matches[1].Trim()}
                $suspCmds='vssadmin.*delete|vssadmin.*resize|wmic.*shadowcopy.*delete|bcdedit.*(recoveryenabled|bootstatuspolicy|ignoreallfailures)|wbadmin.*delete.*catalog|schtasks.*/delete'
                if ($cmd -match $suspCmds -or ($proc -match 'vssadmin|wbadmin|bcdedit' -and $cmd -match 'delete|resize|no')) {
                    Add-Finding -Severity "HIGH" -TechniqueID "T1490" -Technique "Shadow Copy / Backup Deletion" `
                        -Artifact "EventID 4688 @ $($e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))" `
                        -Detail "Process: $([System.IO.Path]::GetFileName($proc)) | Command: $cmd" | Out-Null
                }
            }
    }
    # Check if shadow copies actually exist (absence = possible deletion)
    $shadows=Get-WmiObject Win32_ShadowCopy -EA SilentlyContinue
    if ($null -eq $shadows -or @($shadows).Count -eq 0) {
        Add-Finding -Severity "HIGH" -TechniqueID "T1490" -Technique "No Shadow Copies Present" `
            -Artifact "Win32_ShadowCopy" `
            -Detail "No Volume Shadow Copies found - may have been deleted. Normal on fresh systems but investigate in context." | Out-Null
    } else {
        Add-Finding -Severity "INFO" -TechniqueID "T1490" -Technique "Shadow Copies Present" `
            -Artifact "Win32_ShadowCopy" `
            -Detail "Found $(@($shadows).Count) shadow copy snapshot(s) - copies exist and were not deleted" | Out-Null
    }
}

function Hunt-BackupTampering {
    # T1490 - Backup service disablement (WBEM/VSS service stopped/disabled)
    $backupSvcs=@('wbengine','VSS','SDRSVC','swprv')
    foreach ($svc in $backupSvcs) {
        $s=Get-Service $svc -EA SilentlyContinue
        if ($s -and $s.StartType -eq "Disabled") {
            Add-Finding -Severity "HIGH" -TechniqueID "T1490" -Technique "Backup Service Disabled" `
                -Artifact "Service: $svc" `
                -Detail "Backup-related service has been disabled | Status: $($s.Status) | StartType: $($s.StartType)" | Out-Null
        }
    }
    # Windows Backup scheduled task removed or disabled
    Get-ScheduledTask -TaskPath '\Microsoft\Windows\WindowsBackup\' -EA SilentlyContinue |
        Where-Object {$_.State -eq "Disabled"} |
        ForEach-Object {
            Add-Finding -Severity "MED" -TechniqueID "T1490" -Technique "Backup Task Disabled" `
                -Artifact $_.TaskName `
                -Detail "Windows Backup scheduled task is disabled" | Out-Null
        }
}

function Hunt-RansomNoteDrops {
    # T1486 - Ransom note files in common directories
    $ransomNotePatterns='README.*\.txt$|HOW.*DECRYPT.*\.txt$|RECOVERY.*\.txt$|!RESTORE.*\.txt$|YOUR.*FILES.*\.txt$|DECRYPT.*INSTRUCTION.*|RANSOM.*NOTE|_READ_ME_'
    $searchRoots=@("$env:USERPROFILE\Desktop","$env:USERPROFILE\Documents",
                   "$env:USERPROFILE\Downloads","C:\Users\Public","C:\ProgramData")
    foreach ($root in $searchRoots) {
        if (-not (Test-Path $root -EA SilentlyContinue)) {continue}
        Get-ChildItem $root -Recurse -File -EA SilentlyContinue |
            Where-Object {$_.Name -match $ransomNotePatterns -and $_.LastWriteTime -ge $cutoff} |
            ForEach-Object {
                $preview=""
                try {$preview=(Get-Content $_.FullName -TotalCount 2 -EA Stop) -join " "} catch {}
                Add-Finding -Severity "HIGH" -TechniqueID "T1486" -Technique "Ransom Note Drop" `
                    -Artifact $_.Name `
                    -Detail "Ransom note pattern detected | Modified: $($_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')) | Preview: $($preview.Substring(0,[Math]::Min(100,$preview.Length)))" `
                    -Path $_.FullName | Out-Null
            }
    }
}

function Hunt-MassFileExtensionChange {
    # T1486 - Unusual file extensions appearing in bulk (encryption indicator)
    $knownRansomExts='\.locked$|\.encrypted$|\.enc$|\.crypted$|\.crypt$|\.cryp1$|\.zepto$|\.locky$|\.cerber$|\.lol$|\.pay2decrypt$|\.wncry$|\.wnry$|\.WNCRYPT$|\.ctbl$|\.ctb2$'
    $searchRoots=@("$env:USERPROFILE\Desktop","$env:USERPROFILE\Documents","$env:USERPROFILE\Downloads")
    foreach ($root in $searchRoots) {
        if (-not (Test-Path $root -EA SilentlyContinue)) {continue}
        $hits=Get-ChildItem $root -Recurse -File -EA SilentlyContinue |
            Where-Object {$_.Name -match $knownRansomExts -and $_.LastWriteTime -ge $cutoff}
        if (@($hits).Count -gt 0) {
            Add-Finding -Severity "HIGH" -TechniqueID "T1486" -Technique "Ransomware File Extension" `
                -Artifact "$(@($hits).Count) file(s) with ransomware extension" `
                -Detail "Known ransomware encrypted file extension(s) found in $root | Sample: $(@($hits)[0].Name)" `
                -Path $root | Out-Null
        }
    }
}

function Hunt-InhibitRecovery {
    # T1490 - Boot configuration modified to prevent recovery
    $bootStatus=""
    try {
        $bcdedit=& bcdedit /enum DEFAULT 2>&1 | Out-String
        if ($bcdedit -match 'recoveryenabled\s+No') {
            Add-Finding -Severity "HIGH" -TechniqueID "T1490" -Technique "Boot Recovery Disabled" `
                -Artifact "bcdedit recoveryenabled = No" `
                -Detail "Windows boot recovery has been disabled -- common ransomware pre-encryption step" | Out-Null
        }
        if ($bcdedit -match 'bootstatuspolicy\s+IgnoreAllFailures') {
            Add-Finding -Severity "HIGH" -TechniqueID "T1490" -Technique "Boot Status Policy Tampered" `
                -Artifact "bcdedit bootstatuspolicy = IgnoreAllFailures" `
                -Detail "Boot status policy set to ignore failures -- common ransomware pre-encryption step" | Out-Null
        }
    } catch {}
}

if ($Headless) {
    Print-Banner "Pre-Ransomware Hunter -- $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Lookback: $LookbackHours h"
    Print-Section "Shadow Copy Deletion (T1490)";   Hunt-ShadowCopyDeletion
    Print-Section "Backup Tampering (T1490)";        Hunt-BackupTampering
    Print-Section "Ransom Note Drops (T1486)";       Hunt-RansomNoteDrops
    Print-Section "Ransomware File Extensions (T1486)"; Hunt-MassFileExtensionChange
    Print-Section "Inhibit Recovery (T1490)";        Hunt-InhibitRecovery
    Print-Banner "RESULTS"; Print-AllFindings; Export-AllFindings $OutputPath; exit 0
}

Add-Type -AssemblyName System.Windows.Forms,System.Drawing
$mods=[ordered]@{
    "Shadow Copy Deletion (T1490)"         ="Hunt-ShadowCopyDeletion"
    "Backup Service Tampering (T1490)"     ="Hunt-BackupTampering"
    "Ransom Note Drops (T1486)"            ="Hunt-RansomNoteDrops"
    "Ransomware File Extensions (T1486)"   ="Hunt-MassFileExtensionChange"
    "Inhibit Recovery / bcdedit (T1490)"   ="Hunt-InhibitRecovery"
}
$CB_X=12;$BTN_W=130;$BTN_H=32;$MAR=10;$FW=320
$frm=New-Object System.Windows.Forms.Form;$frm.Text="Pre-Ransomware Hunter"
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
$btnR.Location=New-Object System.Drawing.Point($CB_X,$cbY);$btnR.BackColor=[System.Drawing.Color]::FromArgb(200,50,50)
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
    Print-Banner "Pre-Ransomware Hunter -- $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    foreach($l in $sel){$lbS.Text="Running: $l";[System.Windows.Forms.Application]::DoEvents()
        Print-Section $l;&$mods[$l];[System.Windows.Forms.Application]::DoEvents()}
    Print-Banner "RESULTS";Print-AllFindings
    $h=($script:Findings|Where-Object Severity -eq "HIGH").Count;$m=($script:Findings|Where-Object Severity -eq "MED").Count
    $lbS.Text="Done -- HIGH: $h  MED: $m  Total: $($script:Findings.Count)";$btnR.Enabled=$true;$btnE.Enabled=$true})
$btnE.Add_Click({
    if($script:Findings.Count -eq 0){[System.Windows.Forms.MessageBox]::Show("Run a hunt first.","No Findings",
        [System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Information)|Out-Null;return}
    $d=New-Object System.Windows.Forms.SaveFileDialog;$d.Filter="CSV Files (*.csv)|*.csv"
    $d.FileName="PreRansomHunter_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    if($d.ShowDialog() -eq "OK"){Export-AllFindings $d.FileName;$lbS.Text="Exported: $(Split-Path $d.FileName -Leaf)"}})
Write-Host "Pre-Ransomware Hunter ready. Results print here." -ForegroundColor Red
$frm.Add_Shown({$frm.Activate()});[void]$frm.ShowDialog()
