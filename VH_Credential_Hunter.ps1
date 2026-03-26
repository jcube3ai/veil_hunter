#Requires -Version 5.1
<#
.SYNOPSIS  VeilHunter - Credential Theft Hunter
           Hunts LSASS access, SAM/NTDS dumps, DPAPI abuse, browser credential
           theft, Kerberoasting artifacts, and credential files in suspicious paths.
           TTPs: T1003, T1555, T1558, T1552, T1040 (credential-related)
.EXAMPLE   .\VH_Credential_Hunter.ps1
           .\VH_Credential_Hunter.ps1 -Headless -OutputPath C:\out.csv
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

function Hunt-LSASSAccess {
    # T1003.001 - Security event 4656/4663 on lsass.exe process
    if (Get-WinEvent -ListLog Security -EA SilentlyContinue) {
        $xp='*[System[(EventID=10)]] or *[System[(EventID=4656)]]'
        Get-WinEvent -LogName Security -MaxEvents 200 -EA SilentlyContinue |
            Where-Object {$_.Id -in 10,4656,4663 -and $_.TimeCreated -ge $cutoff} |
            ForEach-Object {
                $e=$_
                if ($e.Message -match 'lsass' -or $e.Message -match '\\Windows\\System32\\lsass.exe') {
                    $proc=""; $acc=""
                    if ($e.Message -match 'Process Name:\s*(.+?)[\r\n]') {$proc=$Matches[1].Trim()}
                    if ($e.Message -match 'Access:\s*(.+?)[\r\n]')       {$acc=$Matches[1].Trim()}
                    Add-Finding -Severity "HIGH" -TechniqueID "T1003.001" -Technique "LSASS Access" `
                        -Artifact "EventID $($e.Id) @ $($e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))" `
                        -Detail "LSASS process access detected | Accessor: $proc | Access: $acc" | Out-Null
                }
            }
    }
    # Check for common LSASS dumper tool artifacts on disk
    $dumpTools=@('mimikatz','mimilib','procdump','nanodump','handlekatz',
                 'safetykatz','dumpert','lsassy','pypykatz')
    $searchPaths=@("$env:TEMP","$env:USERPROFILE\Downloads","C:\ProgramData","C:\Windows\Temp")
    foreach ($path in $searchPaths) {
        if (-not (Test-Path $path -EA SilentlyContinue)) {continue}
        Get-ChildItem $path -File -Recurse -EA SilentlyContinue |
            Where-Object {$_.LastWriteTime -ge $cutoff} |
            ForEach-Object {
                if ($_.Name -match ($dumpTools -join '|')) {
                    Add-Finding -Severity "HIGH" -TechniqueID "T1003.001" -Technique "LSASS Dumper Tool" `
                        -Artifact $_.Name `
                        -Detail "Known LSASS dumper binary found | Modified: $($_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))" `
                        -Path $_.FullName | Out-Null
                }
            }
    }
}

function Hunt-SAMDump {
    # T1003.002 - reg.exe saves of SAM/SECURITY/SYSTEM hives
    if (Get-WinEvent -ListLog Security -EA SilentlyContinue) {
        Get-WinEvent -LogName Security -MaxEvents 500 -EA SilentlyContinue |
            Where-Object {$_.Id -in 4656,4663 -and $_.TimeCreated -ge $cutoff `
                -and $_.Message -match 'SAM|SECURITY|SYSTEM'} |
            ForEach-Object {
                $e=$_
                $obj=""; if ($e.Message -match 'Object Name:\s*(.+?)[\r\n]') {$obj=$Matches[1].Trim()}
                $proc=""; if ($e.Message -match 'Process Name:\s*(.+?)[\r\n]') {$proc=$Matches[1].Trim()}
                if ($proc -notmatch 'svchost|services|lsass|winlogon') {
                    Add-Finding -Severity "HIGH" -TechniqueID "T1003.002" -Technique "SAM/SECURITY Hive Access" `
                        -Artifact "EventID $($e.Id) @ $($e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))" `
                        -Detail "Hive: $obj | Process: $proc" | Out-Null
                }
            }
    }
    # Hive dump files on disk
    @("$env:TEMP","$env:USERPROFILE\Downloads","C:\Windows\Temp","C:\ProgramData") | ForEach-Object {
        Get-ChildItem $_ -File -EA SilentlyContinue -Filter "*.hive" |
            Where-Object {$_.LastWriteTime -ge $cutoff} |
            ForEach-Object {
                Add-Finding -Severity "HIGH" -TechniqueID "T1003.002" -Technique "Hive Dump File" `
                    -Artifact $_.Name `
                    -Detail "Registry hive dump file found | Size: $([math]::Round($_.Length/1KB,1))KB | Modified: $($_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))" `
                    -Path $_.FullName | Out-Null
            }
    }
}

function Hunt-DPAPIAbuse {
    # T1555.004 - DPAPI master key enumeration (path recon)
    $dpPath="$env:APPDATA\Microsoft\Protect"
    if (Test-Path $dpPath) {
        $keys=Get-ChildItem $dpPath -Recurse -File -EA SilentlyContinue
        if ($keys.Count -gt 0) {
            Add-Finding -Severity "INFO" -TechniqueID "T1555.004" -Technique "DPAPI Master Keys" `
                -Artifact "DPAPI Protect directory" `
                -Detail "Found $($keys.Count) master key file(s) - note if unexpected processes accessed these recently" `
                -Path $dpPath | Out-Null
        }
    }
    # Chrome/Edge/Firefox credential databases
    $credDBs=@{
        "Chrome"    ="$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"
        "Edge"      ="$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data"
        "Firefox"   ="$env:APPDATA\Mozilla\Firefox\Profiles"
    }
    foreach ($browser in $credDBs.Keys) {
        $p=$credDBs[$browser]
        if (Test-Path $p -EA SilentlyContinue) {
            Add-Finding -Severity "MED" -TechniqueID "T1555.003" -Technique "Browser Credential Store" `
                -Artifact "$browser credential database" `
                -Detail "Credential store exists and may be targeted | Path present on disk" `
                -Path $p | Out-Null
        }
    }
    # Windows Credential Manager vault
    $vault="$env:LOCALAPPDATA\Microsoft\Credentials"
    if (Test-Path $vault) {
        $vFiles=Get-ChildItem $vault -File -EA SilentlyContinue
        foreach ($vf in $vFiles) {
            Add-Finding -Severity "MED" -TechniqueID "T1555.004" -Technique "Credential Manager Vault" `
                -Artifact $vf.Name `
                -Detail "Credential Manager vault entry | Size: $($vf.Length) bytes | Modified: $($vf.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))" `
                -Path $vf.FullName | Out-Null
        }
    }
}

function Hunt-CredentialFiles {
    # T1552.001 - credentials in plaintext files
    $suspPaths=@("$env:USERPROFILE\Desktop","$env:USERPROFILE\Documents",
                 "$env:USERPROFILE\Downloads","$env:TEMP","C:\ProgramData")
    $suspNames='password|passwd|creds|credentials|secret|apikey|api_key|token|\.kdbx$|\.pfx$|id_rsa|id_dsa|\.pem$|\.ppk$'
    foreach ($sp in $suspPaths) {
        if (-not (Test-Path $sp -EA SilentlyContinue)) {continue}
        Get-ChildItem $sp -File -EA SilentlyContinue |
            Where-Object {$_.Name -match $suspNames -and $_.LastWriteTime -ge $cutoff} |
            ForEach-Object {
                $sev=if($_.Name -match '\.kdbx$|\.pfx$|id_rsa|id_dsa|\.pem$|\.ppk$'){"HIGH"}else{"MED"}
                Add-Finding -Severity $sev -TechniqueID "T1552.001" -Technique "Credential File" `
                    -Artifact $_.Name `
                    -Detail "Suspicious credential filename | Size: $([math]::Round($_.Length/1KB,1))KB | Modified: $($_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))" `
                    -Path $_.FullName | Out-Null
            }
    }
}

function Hunt-KerberosArtifacts {
    # T1558 - Kerberoasting / AS-REP roasting indicators in Security log
    if (Get-WinEvent -ListLog Security -EA SilentlyContinue) {
        # 4769 = Kerberos service ticket request (Kerberoasting signal when RC4 encryption used)
        Get-WinEvent -LogName Security -MaxEvents 500 -EA SilentlyContinue |
            Where-Object {$_.Id -eq 4769 -and $_.TimeCreated -ge $cutoff} |
            ForEach-Object {
                $e=$_
                $svc=""; if ($e.Message -match 'Service Name:\s*(.+?)[\r\n]') {$svc=$Matches[1].Trim()}
                $enc=""; if ($e.Message -match 'Ticket Encryption Type:\s*(.+?)[\r\n]') {$enc=$Matches[1].Trim()}
                $acct=""; if ($e.Message -match 'Account Name:\s*(.+?)[\r\n]') {$acct=$Matches[1].Trim()}
                # RC4 (0x17/0x18) requests for non-system SPNs = Kerberoasting signal
                if ($enc -match '0x17|0x18' -and $svc -notmatch '\$$' -and $svc -notmatch 'krbtgt') {
                    Add-Finding -Severity "HIGH" -TechniqueID "T1558.003" -Technique "Kerberoasting (RC4 SPN Request)" `
                        -Artifact "EventID 4769 @ $($e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))" `
                        -Detail "Account: $acct | Service SPN: $svc | EncType: $enc (RC4 -- downgrade indicator)" | Out-Null
                }
            }
        # 4768 = AS-REP roasting (pre-auth not required)
        Get-WinEvent -LogName Security -MaxEvents 200 -EA SilentlyContinue |
            Where-Object {$_.Id -eq 4768 -and $_.TimeCreated -ge $cutoff} |
            ForEach-Object {
                $e=$_
                $result=""; if ($e.Message -match 'Result Code:\s*(.+?)[\r\n]') {$result=$Matches[1].Trim()}
                $acct=""; if ($e.Message -match 'Account Name:\s*(.+?)[\r\n]') {$acct=$Matches[1].Trim()}
                $pre=""; if ($e.Message -match 'Pre-Authentication Type:\s*(.+?)[\r\n]') {$pre=$Matches[1].Trim()}
                if ($pre -eq "0" -or $pre -eq "0x0") {
                    Add-Finding -Severity "HIGH" -TechniqueID "T1558.004" -Technique "AS-REP Roasting (No Pre-Auth)" `
                        -Artifact "EventID 4768 @ $($e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))" `
                        -Detail "Account: $acct | Pre-Auth Type: $pre (0 = pre-auth disabled) | Result: $result" | Out-Null
                }
            }
    }
}

if ($Headless) {
    Print-Banner "Credential Hunter -- $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Lookback: $LookbackHours h"
    Print-Section "LSASS Access (T1003.001)";          Hunt-LSASSAccess
    Print-Section "SAM/Hive Dumps (T1003.002)";         Hunt-SAMDump
    Print-Section "DPAPI + Browser Creds (T1555)";      Hunt-DPAPIAbuse
    Print-Section "Credential Files (T1552.001)";       Hunt-CredentialFiles
    Print-Section "Kerberos Abuse (T1558)";             Hunt-KerberosArtifacts
    Print-Banner "RESULTS"; Print-AllFindings; Export-AllFindings $OutputPath; exit 0
}

Add-Type -AssemblyName System.Windows.Forms,System.Drawing
$mods=[ordered]@{
    "LSASS Access (T1003.001)"          ="Hunt-LSASSAccess"
    "SAM/Hive Dumps (T1003.002)"        ="Hunt-SAMDump"
    "DPAPI + Browser Creds (T1555)"     ="Hunt-DPAPIAbuse"
    "Credential Files (T1552.001)"      ="Hunt-CredentialFiles"
    "Kerberos Abuse (T1558)"            ="Hunt-KerberosArtifacts"
}
$CB_X=12;$BTN_W=130;$BTN_H=32;$MAR=10;$FW=290
$frm=New-Object System.Windows.Forms.Form;$frm.Text="Credential Hunter"
$frm.StartPosition="Manual";$frm.FormBorderStyle="FixedToolWindow";$frm.TopMost=$true
$frm.MaximizeBox=$false;$frm.MinimizeBox=$false
$sc=[System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea
$frm.Location=New-Object System.Drawing.Point(($sc.Right-$FW-10),$sc.Top+10)
$cbY=12;$cbs=@{}
foreach ($lbl in $mods.Keys) {
    $cb=New-Object System.Windows.Forms.CheckBox;$cb.Text=$lbl;$cb.AutoSize=$true
    $cb.Location=New-Object System.Drawing.Point($CB_X,$cbY);$frm.Controls.Add($cb);$cbs[$lbl]=$cb;$cbY+=28 }
$cbAll=New-Object System.Windows.Forms.CheckBox;$cbAll.Text="Select All"
$cbAll.Font=New-Object System.Drawing.Font("Segoe UI",9,[System.Drawing.FontStyle]::Bold)
$cbAll.AutoSize=$true;$cbAll.Location=New-Object System.Drawing.Point($CB_X,($cbY+4))
$cbAll.Add_CheckedChanged({foreach($c in $cbs.Values){$c.Checked=$cbAll.Checked}})
$frm.Controls.Add($cbAll);$cbY+=36
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
    if(-not $sel){[System.Windows.Forms.MessageBox]::Show("Select at least one hunt.","Nothing Selected",
        [System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Warning)|Out-Null;return}
    $btnR.Enabled=$false;$btnE.Enabled=$false;$script:Findings.Clear()
    Print-Banner "Credential Hunter -- $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    foreach($l in $sel){$lbS.Text="Running: $l";[System.Windows.Forms.Application]::DoEvents()
        Print-Section $l;&$mods[$l];[System.Windows.Forms.Application]::DoEvents()}
    Print-Banner "RESULTS";Print-AllFindings
    $h=($script:Findings|Where-Object Severity -eq "HIGH").Count;$m=($script:Findings|Where-Object Severity -eq "MED").Count
    $lbS.Text="Done -- HIGH: $h  MED: $m  Total: $($script:Findings.Count)";$btnR.Enabled=$true;$btnE.Enabled=$true })
$btnE.Add_Click({
    if($script:Findings.Count -eq 0){[System.Windows.Forms.MessageBox]::Show("Run a hunt first.","No Findings",
        [System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Information)|Out-Null;return}
    $d=New-Object System.Windows.Forms.SaveFileDialog;$d.Filter="CSV Files (*.csv)|*.csv"
    $d.FileName="CredHunter_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    if($d.ShowDialog() -eq "OK"){Export-AllFindings $d.FileName;$lbS.Text="Exported: $(Split-Path $d.FileName -Leaf)"}})
Write-Host "Credential Hunter ready. Results print here." -ForegroundColor Cyan
$frm.Add_Shown({$frm.Activate()});[void]$frm.ShowDialog()
