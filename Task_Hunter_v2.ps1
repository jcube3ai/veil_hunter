#Requires -Version 5.1
<#
.SYNOPSIS  Task Hunter v2 - Scheduled Task + AT Job Persistence Hunter
.EXAMPLE   .\Task_Hunter_v2.ps1
           .\Task_Hunter_v2.ps1 -Headless -LookbackHours 168 -OutputPath C:\out.csv
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
$script:Cutoff=(Get-Date).AddHours(-$LookbackHours)

function Hunt-ScheduledTasks {
    $log="Microsoft-Windows-TaskScheduler/Operational"
    if (Get-WinEvent -ListLog $log -EA SilentlyContinue) {
        $map=@{106=@{D="Task registered";S="MED"};140=@{D="Task updated";S="MED"};
               141=@{D="Task DELETED - possible track-covering";S="HIGH"};
               200=@{D="Task action launched";S="HIGH"};201=@{D="Action completed";S="INFO"}}
        Get-WinEvent -LogName $log -MaxEvents 500 -EA SilentlyContinue |
            Where-Object {$_.Id -in $map.Keys -and $_.TimeCreated -ge $script:Cutoff} |
            ForEach-Object {
                $e=$_; $m=$map[$e.Id]
                $name=($e.Message -split '\r?\n'|Where-Object{$_.Trim()}|Select-Object -First 1).Trim()
                Add-Finding -Severity $m.S -TechniqueID "T1053.005" -Technique "Scheduled Task" `
                    -Artifact "EventID $($e.Id) -- $($m.D)" `
                    -Detail "Time: $($e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')) | Task: $name"|Out-Null
            }
    }
    $susp='-EncodedCommand|-enc |mshta|wscript|cscript|rundll32|regsvr32|certutil|bitsadmin|\\Temp\\|\\AppData\\|\\ProgramData\\|\\Users\\Public\\|http[s]?://'
    Get-ScheduledTask -EA SilentlyContinue |
        Where-Object {$_.TaskPath -notmatch '^\\Microsoft\\Windows\\'} |
        ForEach-Object {
            $t=$_
            $act=($t.Actions|ForEach-Object{"$($_.Execute) $($_.Arguments)".Trim()})-join"; "
            $trg=($t.Triggers|ForEach-Object{$_.GetType().Name}|Select-Object -Unique)-join", "
            if ($act -notmatch $susp -and $t.Principal.RunLevel -ne "Highest") {return}
            $sev=if($act -match '-EncodedCommand|-enc |mshta|wscript|cscript|http'){"HIGH"}else{"MED"}
            Add-Finding -Severity $sev -TechniqueID "T1053.005" -Technique "Scheduled Task" `
                -Artifact $t.TaskName `
                -Detail "Path: $($t.TaskPath) | Author: $($t.Author) | RunAs: $($t.Principal.UserId) | RunLevel: $($t.Principal.RunLevel) | Triggers: $trg | Action: $act" `
                -Path "$env:WINDIR\System32\Tasks$($t.TaskPath)$($t.TaskName)"|Out-Null
        }
}

function Hunt-ATJobs {
    $jobs=Get-WmiObject -Class Win32_ScheduledJob -EA SilentlyContinue
    if ($jobs) {
        foreach ($j in $jobs) {
            Add-Finding -Severity "HIGH" -TechniqueID "T1053.002" -Technique "AT Job" `
                -Artifact "JobID $($j.JobId)" `
                -Detail "Command: $($j.Command) | StartTime: $($j.StartTime) | Days: $($j.DaysOfWeek)"|Out-Null
        }
    } else {
        Add-Finding -Severity "INFO" -TechniqueID "T1053.002" -Technique "AT Job" `
            -Artifact "AT Jobs" -Detail "No legacy AT jobs found (expected on modern systems)."|Out-Null
    }
}

function Hunt-TaskXML {
    $root="$env:WINDIR\System32\Tasks"
    $rex='rundll32|mshta|regsvr32|wscript|cscript|certutil|bitsadmin|powershell|forfiles|pcalua|odbcconf'
    if (-not (Test-Path $root)) {return}
    Get-ChildItem -Path $root -Recurse -File -EA SilentlyContinue |
        Where-Object {$_.LastWriteTime -ge $script:Cutoff} |
        ForEach-Object {
            $f=$_; try{$xml=[xml](Get-Content -Raw $f.FullName -EA Stop)}catch{return}
            foreach ($x in @($xml.Task.Actions.Exec)) {
                $cmd=("$($x.Command) $($x.Arguments)").Trim()
                if ($cmd -match $rex) {
                    $sev=if($cmd -match 'mshta|wscript|cscript|-Enc|http'){"HIGH"}else{"MED"}
                    Add-Finding -Severity $sev -TechniqueID "T1053.005" -Technique "Task XML LOLBin" `
                        -Artifact $f.Name `
                        -Detail "Modified: $($f.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')) | Command: $cmd" `
                        -Path $f.FullName|Out-Null
                }
            }
        }
}

if ($Headless) {
    Print-Banner "Task Hunter v2 -- $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Lookback: $LookbackHours h"
    Print-Section "Scheduled Tasks"; Hunt-ScheduledTasks
    Print-Section "AT Jobs";         Hunt-ATJobs
    Print-Section "Task XML LOLBin"; Hunt-TaskXML
    Print-Banner "RESULTS"; Print-AllFindings; Export-AllFindings $OutputPath; exit 0
}

Add-Type -AssemblyName System.Windows.Forms,System.Drawing
$mods=[ordered]@{"Scheduled Tasks (T1053.005)"="Hunt-ScheduledTasks";"AT Jobs (T1053.002)"="Hunt-ATJobs";"Task XML LOLBin Scan"="Hunt-TaskXML"}
$CB_X=12;$BTN_W=120;$BTN_H=32;$MAR=10;$FW=270
$frm=New-Object System.Windows.Forms.Form
$frm.Text="Task Hunter v2";$frm.StartPosition="Manual";$frm.FormBorderStyle="FixedToolWindow"
$frm.TopMost=$true;$frm.MaximizeBox=$false;$frm.MinimizeBox=$false
$sc=[System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea
$frm.Location=New-Object System.Drawing.Point(($sc.Right-$FW-10),$sc.Top+10)
$cbY=12;$cbs=@{}
foreach ($lbl in $mods.Keys) {
    $cb=New-Object System.Windows.Forms.CheckBox;$cb.Text=$lbl;$cb.AutoSize=$true
    $cb.Location=New-Object System.Drawing.Point($CB_X,$cbY);$frm.Controls.Add($cb);$cbs[$lbl]=$cb;$cbY+=28 }
$cbY+=8
$lbL=New-Object System.Windows.Forms.Label;$lbL.Text="Lookback (hours):";$lbL.AutoSize=$true
$lbL.Location=New-Object System.Drawing.Point($CB_X,$cbY);$frm.Controls.Add($lbL);$cbY+=22
$num=New-Object System.Windows.Forms.NumericUpDown;$num.Minimum=1;$num.Maximum=720;$num.Value=72
$num.Location=New-Object System.Drawing.Point($CB_X,$cbY);$num.Size=New-Object System.Drawing.Size(80,24)
$frm.Controls.Add($num);$cbY+=32
$sep=New-Object System.Windows.Forms.Label;$sep.BorderStyle="Fixed3D"
$sep.Size=New-Object System.Drawing.Size(($FW-$CB_X*2),2);$sep.Location=New-Object System.Drawing.Point($CB_X,$cbY)
$frm.Controls.Add($sep);$cbY+=10
$btnR=New-Object System.Windows.Forms.Button;$btnR.Text="Run Hunt"
$btnR.Size=New-Object System.Drawing.Size($BTN_W,$BTN_H);$btnR.Location=New-Object System.Drawing.Point($CB_X,$cbY)
$btnR.BackColor=[System.Drawing.Color]::FromArgb(0,120,215);$btnR.ForeColor=[System.Drawing.Color]::White
$btnR.FlatStyle="Flat";$frm.Controls.Add($btnR)
$btnE=New-Object System.Windows.Forms.Button;$btnE.Text="Export CSV"
$btnE.Size=New-Object System.Drawing.Size($BTN_W,$BTN_H);$btnE.Location=New-Object System.Drawing.Point(($CB_X+$BTN_W+$MAR),$cbY)
$btnE.FlatStyle="Flat";$frm.Controls.Add($btnE);$cbY+=$BTN_H+$MAR
$lbS=New-Object System.Windows.Forms.Label;$lbS.Text="Ready.";$lbS.AutoSize=$false
$lbS.Size=New-Object System.Drawing.Size(($FW-$CB_X*2),18);$lbS.Font=New-Object System.Drawing.Font("Segoe UI",8)
$lbS.ForeColor=[System.Drawing.Color]::DarkGray;$lbS.Location=New-Object System.Drawing.Point($CB_X,$cbY)
$frm.Controls.Add($lbS);$cbY+=24;$frm.ClientSize=New-Object System.Drawing.Size($FW,$cbY)
$btnR.Add_Click({
    $sel=$cbs.Keys|Where-Object{$cbs[$_].Checked}
    if (-not $sel){[System.Windows.Forms.MessageBox]::Show("Select at least one hunt.","Nothing Selected",
        [System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Warning)|Out-Null;return}
    $btnR.Enabled=$false;$btnE.Enabled=$false;$script:Findings.Clear()
    $script:Cutoff=(Get-Date).AddHours(-[int]$num.Value)
    Print-Banner "Task Hunter v2 -- $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Lookback: $($num.Value)h"
    foreach ($l in $sel){$lbS.Text="Running: $l";[System.Windows.Forms.Application]::DoEvents()
        Print-Section $l;&$mods[$l];[System.Windows.Forms.Application]::DoEvents()}
    Print-Banner "RESULTS";Print-AllFindings
    $h=($script:Findings|Where-Object Severity -eq "HIGH").Count;$m=($script:Findings|Where-Object Severity -eq "MED").Count
    $lbS.Text="Done -- HIGH: $h  MED: $m  Total: $($script:Findings.Count)";$btnR.Enabled=$true;$btnE.Enabled=$true })
$btnE.Add_Click({
    if ($script:Findings.Count -eq 0){[System.Windows.Forms.MessageBox]::Show("Run a hunt first.","No Findings",
        [System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Information)|Out-Null;return}
    $d=New-Object System.Windows.Forms.SaveFileDialog;$d.Filter="CSV Files (*.csv)|*.csv"
    $d.FileName="TaskHunter_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    if ($d.ShowDialog() -eq "OK"){Export-AllFindings $d.FileName;$lbS.Text="Exported: $(Split-Path $d.FileName -Leaf)"}})
Write-Host "Task Hunter v2 ready. Results print here." -ForegroundColor Cyan
$frm.Add_Shown({$frm.Activate()});[void]$frm.ShowDialog()
