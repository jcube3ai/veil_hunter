#Requires -Version 5.1
<#
.SYNOPSIS  Service Installs Hunter v2 - Malicious Service Detection
.EXAMPLE   .\service_installs_v2.ps1
           .\service_installs_v2.ps1 -LookbackHours 168 -OutputPath C:\out.csv
#>
[CmdletBinding()]
param([int]$LookbackHours=72,[string]$OutputPath="")
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

function Get-StartLabel([int]$v){switch($v){0{"Boot(0)"}1{"System(1)"}2{"Auto(2)"}3{"Manual(3)"}4{"Disabled(4)"}default{"Unknown($v)"}}}
function Get-TypeLabel([int]$v){switch($v){1{"KernelDriver"}2{"FSDriver"}16{"OwnProcess"}32{"SharedProcess"}default{"Type$v"}}}

Print-Banner "Service Installs Hunter v2 -- Lookback: $LookbackHours h"

Print-Section "Event Log (7045/7040/7036/7034/7031)"
$evtMap=@{
    7045=@{D="New service INSTALLED";S="HIGH"}
    7040=@{D="Service start type changed";S="MED"}
    7036=@{D="Service state changed";S="INFO"}
    7034=@{D="Service crashed unexpectedly";S="MED"}
    7031=@{D="Service terminated unexpectedly";S="MED"}
}
if (Get-WinEvent -ListLog "System" -EA SilentlyContinue) {
    $xp="*[System[($( $evtMap.Keys|ForEach-Object{"EventID=$_"}|Join-String -Separator ' or '))]]"
    Get-WinEvent -LogName System -FilterXPath $xp -MaxEvents 500 -EA SilentlyContinue |
        Where-Object {$_.TimeCreated -ge $cutoff} |
        ForEach-Object {
            $e=$_; $m=$evtMap[$e.Id]; $sev=$m.S
            # Extract service name cleanly from first meaningful line
            $svcName=($e.Message -split '\r?\n'|Where-Object{$_.Trim() -and $_-notmatch '^\s*$'}|Select-Object -First 1).Trim()
            $imgPath=""; if ($e.Message -match 'inary Path.*?:\s*(.+?)[\r\n]') {$imgPath=$Matches[1].Trim()}
            if ($e.Id -eq 7040 -and $e.Message -match 'auto start|automatic') {$sev="HIGH"}
            $detail="Time: $($e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')) | $($m.D)"
            if ($svcName) {$detail+=" | Service: $svcName"}
            if ($imgPath) {$detail+=" | ImagePath: $imgPath"}
            Add-Finding -Severity $sev -TechniqueID "T1543.003" -Technique "Service Event" `
                -Artifact "EventID $($e.Id)" -Detail $detail | Out-Null
            Print-Finding ($script:Findings[-1])
        }
}

Print-Section "Registry Scan (HKLM Services)"
$suspPaths='\\Users\\|\\AppData\\|\\Temp\\|\\ProgramData\\|\\Downloads\\'
$trustedPfx=@('C:\Windows\system32\','C:\Windows\SysWOW64\','C:\Windows\System32\drivers\',
               'C:\Program Files\','C:\Program Files (x86)\')
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' -EA SilentlyContinue | ForEach-Object {
    $k=$_; $p=Get-ItemProperty -LiteralPath $k.PSPath -EA SilentlyContinue
    if (-not $p -or -not $p.ImagePath) {return}
    $img=[string]$p.ImagePath; $type=[int]($p.Type); $start=[int]($p.Start)
    $sig=Get-SigStatus $img; $reasons=@(); $sev="INFO"
    if ($img -match $suspPaths) {$reasons+="Suspicious ImagePath location"; $sev="HIGH"}
    if ($sig -in "NotSigned","HashMismatch","FILE_NOT_FOUND") {$reasons+="Signature: $sig"; if($sev-ne"HIGH"){$sev="MED"}}
    if ($type -in 1,2) {
        $std=($trustedPfx|Where-Object{$img -like "$_*"}).Count -gt 0
        if (-not $std) {$reasons+="Kernel/FS driver outside Windows path"; $sev="HIGH"}
    }
    if ($start -eq 2 -and $sig -ne "Valid") {
        $std=($trustedPfx|Where-Object{$img -like "$_*"}).Count -gt 0
        if (-not $std) {$reasons+="Auto-start unsigned binary"; if($sev-ne"HIGH"){$sev="MED"}}
    }
    if (-not $reasons) {return}
    Add-Finding -Severity $sev -TechniqueID "T1543.003" -Technique "Service Registry" `
        -Artifact "Service: $($k.PSChildName)" `
        -Detail "Type: $(Get-TypeLabel $type) | Start: $(Get-StartLabel $start) | Signature: $sig | Reasons: $($reasons -join '; ')" `
        -Path $img | Out-Null
    Print-Finding ($script:Findings[-1])
}

Print-Banner "RESULTS"; Print-AllFindings; Export-AllFindings $OutputPath
