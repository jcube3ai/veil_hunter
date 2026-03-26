#Requires -Version 5.1
<#
.SYNOPSIS  VeilHunter - LOLBin Deep Dive Hunter
           Comprehensive living-off-the-land binary execution hunting.
           Covers 20+ LOLBins with parent/child chain analysis, unusual
           argument patterns, and execution from suspicious paths.
           TTPs: T1218, T1059, T1140, T1202, T1127
.EXAMPLE   .\VH_LOLBin_Hunter.ps1
           .\VH_LOLBin_Hunter.ps1 -Headless -OutputPath C:\out.csv
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

# Master LOLBin definitions: Name, TID, suspicious argument patterns
$LOLBINS=@(
    @{Name="mshta.exe";       TID="T1218.005"; Args='http|javascript:|vbscript:|\\Temp\\|\\AppData\\'}
    @{Name="wscript.exe";     TID="T1059.005"; Args='http|\.vbs|\.js|\\Temp\\|\\AppData\\|\\ProgramData\\'}
    @{Name="cscript.exe";     TID="T1059.005"; Args='http|\.vbs|\.js|\\Temp\\|\\AppData\\|\\ProgramData\\'}
    @{Name="rundll32.exe";    TID="T1218.011"; Args='javascript:|http|\\Temp\\|\\AppData\\|shell32.*Control_RunDLL|advpack.*LaunchINFSection'}
    @{Name="regsvr32.exe";    TID="T1218.010"; Args='/s|/u|http|scrobj|\\Temp\\|\\AppData\\'}
    @{Name="certutil.exe";    TID="T1140";     Args='-decode|-urlcache|-ping|http|\\Temp\\|\\AppData\\'}
    @{Name="bitsadmin.exe";   TID="T1197";     Args='/transfer|/create|/addfile|http|\\Temp\\|\\AppData\\'}
    @{Name="msiexec.exe";     TID="T1218.007"; Args='/i.*http|/q|\\Temp\\|\\AppData\\|\.msi.*http'}
    @{Name="installutil.exe"; TID="T1218.004"; Args='\\Temp\\|\\AppData\\|\\ProgramData\\'}
    @{Name="regasm.exe";      TID="T1218.009"; Args='\\Temp\\|\\AppData\\|\\ProgramData\\'}
    @{Name="regsvcs.exe";     TID="T1218.009"; Args='\\Temp\\|\\AppData\\|\\ProgramData\\'}
    @{Name="odbcconf.exe";    TID="T1218.008"; Args='/a.*regsvr|rsp|\\Temp\\|\\AppData\\'}
    @{Name="pcalua.exe";      TID="T1202";     Args='-m|-a|\\Temp\\|\\AppData\\'}
    @{Name="forfiles.exe";    TID="T1202";     Args='/p|/m|/c.*cmd|/c.*powershell'}
    @{Name="msconfig.exe";    TID="T1218";     Args='\\Temp\\|\\AppData\\|/general|/services'}
    @{Name="esentutl.exe";    TID="T1140";     Args='/y|/vss|NTDS\.dit|SAM|SYSTEM|SECURITY'}
    @{Name="expand.exe";      TID="T1140";     Args='\\Temp\\|\\AppData\\|\\ProgramData\\'}
    @{Name="extrac32.exe";    TID="T1140";     Args='\\Temp\\|\\AppData\\|/y|http'}
    @{Name="makecab.exe";     TID="T1560.001"; Args='NTDS|SAM|SYSTEM|\.dit|\\Temp\\'}
    @{Name="wmic.exe";        TID="T1047";     Args='process.*call.*create|os.*get|/node:.*process'}
    @{Name="netsh.exe";       TID="T1562.004"; Args='advfirewall.*set|portproxy.*add|firewall.*delete'}
    @{Name="schtasks.exe";    TID="T1053.005"; Args='/create|/change|/run.*\\Temp\\|/tr.*powershell|/tr.*cmd|/tr.*wscript'}
    @{Name="at.exe";          TID="T1053.002"; Args='\d{1,2}:\d{2}'}
    @{Name="reg.exe";         TID="T1112";     Args='save.*HKLM|export.*SAM|import.*\\Temp\\|add.*Run|delete.*Defender'}
    @{Name="sc.exe";          TID="T1543.003"; Args='create|config.*binpath|failure.*command'}
)

function Hunt-LOLBinExecution {
    if (-not (Get-WinEvent -ListLog Security -EA SilentlyContinue)) {return}
    Get-WinEvent -LogName Security -MaxEvents 2000 -EA SilentlyContinue |
        Where-Object {$_.Id -eq 4688 -and $_.TimeCreated -ge $cutoff} |
        ForEach-Object {
            $e=$_
            $newProc=""; if ($e.Message -match 'New Process Name:\s*(.+?)[\r\n]') {$newProc=$Matches[1].Trim()}
            $parent="";  if ($e.Message -match 'Creator Process Name:\s*(.+?)[\r\n]') {$parent=$Matches[1].Trim()}
            $cmdLine=""; if ($e.Message -match 'Process Command Line:\s*(.+?)[\r\n]') {$cmdLine=$Matches[1].Trim()}
            $user="";    if ($e.Message -match 'Subject.*?Account Name:\s*(.+?)[\r\n]') {$user=$Matches[1].Trim()}
            $procName=[System.IO.Path]::GetFileName($newProc).ToLower()
            foreach ($lb in $LOLBINS) {
                if ($procName -eq $lb.Name.ToLower()) {
                    # Check for suspicious args
                    $suspMatch=$cmdLine -match $lb.Args
                    # Check execution from non-standard path
                    $suspPath=$newProc -match '\\Temp\\|\\AppData\\|\\ProgramData\\|\\Users\\Public\\'
                    # Suspicious parent (document-to-LOLBin chain)
                    $suspParent=$parent -match 'winword|excel|powerpnt|outlook|chrome|firefox|edge|teams|slack|OUTLOOK|brave'
                    if ($suspMatch -or $suspPath -or $suspParent) {
                        $sev=if($suspParent -or ($suspMatch -and $suspPath)){"HIGH"}else{"MED"}
                        $flags=@()
                        if ($suspMatch)  {$flags+="SuspiciousArgs"}
                        if ($suspPath)   {$flags+="SuspiciousPath"}
                        if ($suspParent) {$flags+="OfficeParent"}
                        Add-Finding -Severity $sev -TechniqueID $lb.TID -Technique "LOLBin: $($lb.Name)" `
                            -Artifact "$([System.IO.Path]::GetFileName($parent)) -> $($lb.Name)" `
                            -Detail "Time: $($e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')) | User: $user | Flags: $($flags -join ',') | CommandLine: $($cmdLine.Substring(0,[Math]::Min(120,$cmdLine.Length)))" `
                            -Path $newProc | Out-Null
                    }
                }
            }
        }
}

function Hunt-EncodedCommands {
    # T1027.010 - Base64 encoded PowerShell commands in event logs
    if (-not (Get-WinEvent -ListLog Security -EA SilentlyContinue)) {return}
    Get-WinEvent -LogName Security -MaxEvents 2000 -EA SilentlyContinue |
        Where-Object {$_.Id -eq 4688 -and $_.TimeCreated -ge $cutoff} |
        ForEach-Object {
            $e=$_
            $cmd=""; if ($e.Message -match 'Process Command Line:\s*(.+?)[\r\n]') {$cmd=$Matches[1].Trim()}
            if ($cmd -match '-EncodedCommand|-Enc\s+|-e\s+[A-Za-z0-9+/]{20,}') {
                # Try to decode
                $decoded=""
                try {
                    $b64=([regex]'(?i)(?:-[Ee]nc(?:odedCommand)?\s+)([A-Za-z0-9+/=]+)').Match($cmd).Groups[1].Value
                    if ($b64) {$decoded=[System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($b64))}
                } catch {}
                $proc=""; if ($e.Message -match 'New Process Name:\s*(.+?)[\r\n]') {$proc=$Matches[1].Trim()}
                Add-Finding -Severity "HIGH" -TechniqueID "T1027.010" -Technique "Encoded PowerShell Command" `
                    -Artifact "$([System.IO.Path]::GetFileName($proc)) with -EncodedCommand" `
                    -Detail "Time: $($e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')) | Decoded: $($decoded.Substring(0,[Math]::Min(150,$decoded.Length)))" `
                    -Path $proc | Out-Null
            }
        }
}

function Hunt-LOLBinOnDisk {
    # Check suspicious paths for renamed/planted LOLBins
    $suspPaths=@("$env:TEMP","$env:USERPROFILE\Downloads","C:\ProgramData","C:\Windows\Temp","C:\Users\Public")
    foreach ($sp in $suspPaths) {
        if (-not (Test-Path $sp -EA SilentlyContinue)) {continue}
        Get-ChildItem $sp -File -EA SilentlyContinue | Where-Object {$_.LastWriteTime -ge $cutoff} |
            ForEach-Object {
                $f=$_; $sig=Get-SigStatus $f.FullName
                # Unsigned PE in suspicious path = planted binary
                if ($sig -in "NotSigned","HashMismatch") {
                    Add-Finding -Severity "HIGH" -TechniqueID "T1218" -Technique "Unsigned Binary in Suspicious Path" `
                        -Artifact $f.Name `
                        -Detail "Unsigned PE binary in staging path | Sig: $sig | Size: $([math]::Round($f.Length/1KB,1))KB | Modified: $($f.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))" `
                        -Path $f.FullName | Out-Null
                }
            }
    }
}

if ($Headless) {
    Print-Banner "LOLBin Hunter -- $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Lookback: $LookbackHours h"
    Print-Section "LOLBin Execution Chains (20+ LOLBins)"; Hunt-LOLBinExecution
    Print-Section "Encoded Command Detection";             Hunt-EncodedCommands
    Print-Section "Unsigned Binaries in Suspicious Paths"; Hunt-LOLBinOnDisk
    Print-Banner "RESULTS"; Print-AllFindings; Export-AllFindings $OutputPath; exit 0
}

Add-Type -AssemblyName System.Windows.Forms,System.Drawing
$mods=[ordered]@{
    "LOLBin Execution Chains (20+ LOLBins)" ="Hunt-LOLBinExecution"
    "Encoded Command Detection"              ="Hunt-EncodedCommands"
    "Unsigned Binaries in Staging Paths"     ="Hunt-LOLBinOnDisk"
}
$CB_X=12;$BTN_W=130;$BTN_H=32;$MAR=10;$FW=330
$frm=New-Object System.Windows.Forms.Form;$frm.Text="LOLBin Hunter"
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
    Print-Banner "LOLBin Hunter -- $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    foreach($l in $sel){$lbS.Text="Running: $l";[System.Windows.Forms.Application]::DoEvents()
        Print-Section $l;&$mods[$l];[System.Windows.Forms.Application]::DoEvents()}
    Print-Banner "RESULTS";Print-AllFindings
    $h=($script:Findings|Where-Object Severity -eq "HIGH").Count;$m=($script:Findings|Where-Object Severity -eq "MED").Count
    $lbS.Text="Done -- HIGH: $h  MED: $m  Total: $($script:Findings.Count)";$btnR.Enabled=$true;$btnE.Enabled=$true})
$btnE.Add_Click({
    if($script:Findings.Count -eq 0){[System.Windows.Forms.MessageBox]::Show("Run a hunt first.","No Findings",
        [System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Information)|Out-Null;return}
    $d=New-Object System.Windows.Forms.SaveFileDialog;$d.Filter="CSV Files (*.csv)|*.csv"
    $d.FileName="LOLBinHunter_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    if($d.ShowDialog() -eq "OK"){Export-AllFindings $d.FileName;$lbS.Text="Exported: $(Split-Path $d.FileName -Leaf)"}})
Write-Host "LOLBin Hunter ready. Results print here." -ForegroundColor Cyan
$frm.Add_Shown({$frm.Activate()});[void]$frm.ShowDialog()
