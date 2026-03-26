#Requires -Version 5.1
<#
.SYNOPSIS  Malvertising Payload Hunter v2 - Internet-Sourced File + RMM Footprint Detection
.EXAMPLE   .\malvertising_payload_hunter_v2.ps1
           .\malvertising_payload_hunter_v2.ps1 -LookbackDays 14 -OutputPath C:\out.csv
#>
[CmdletBinding()]
param([int]$LookbackDays=7,[string]$OutputPath="",[string[]]$ScanPaths=@())
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
$cutoff=(Get-Date).AddDays(-$LookbackDays)

function Get-ZoneId([string]$p) {
    $ads="$p`:Zone.Identifier"
    if (Test-Path $ads -EA SilentlyContinue) {
        try { $c=Get-Content $ads -Raw -EA Stop; if ($c -match 'ZoneId=(\d+)'){return [int]$Matches[1]} } catch {}
    }; return $null
}
function Get-ZoneLabel([int]$id) {
    switch ($id) {0{"Local Machine"}1{"Local Intranet"}2{"Trusted Sites"}3{"Internet (untrusted)"}4{"Restricted Sites"}default{"Zone $id"}}
}

$exts=@('*.msi','*.exe','*.dll','*.iso','*.img','*.lnk','*.js','*.jse','*.vbs','*.vbe',
        '*.hta','*.ps1','*.psm1','*.bat','*.cmd','*.zip','*.rar','*.7z','*.cab',
        '*.cpl','*.scr','*.pif','*.jar','*.reg','*.msp')

$roots=@("$env:USERPROFILE\Downloads","$env:USERPROFILE\Desktop","$env:TEMP",
         "$env:LOCALAPPDATA\Temp","$env:APPDATA","C:\Users\Public","C:\Users\Public\Downloads",
         "C:\ProgramData","C:\Windows\Temp") + $ScanPaths

$rmmTools=@('AnyDesk','ScreenConnect','Atera','Splashtop','RustDesk','TeamViewer','ZohoAssist',
            'N-able','N-sight','NinjaRMM','NinjaOne','ConnectWise','Automate','Bomgar',
            'BeyondTrust','LogMeIn','GoToAssist','GoToResolve','Kaseya','VSA','Datto',
            'MeshCentral','MeshAgent','Pulseway','SuperOps','Action1','Syncro',
            'SimpleHelp','Supremo','Ammyy','FleetDeck')
$rmmPat=($rmmTools|ForEach-Object{[regex]::Escape($_)})-join'|'

Print-Banner "Malvertising Payload Hunter v2 -- Lookback: $LookbackDays day(s)"

Print-Section "Internet-Sourced Files (ZoneId >= 3)"
foreach ($root in $roots) {
    if (-not (Test-Path $root -EA SilentlyContinue)) {continue}
    Get-ChildItem -Path $root -Recurse -Include $exts -EA SilentlyContinue |
        Where-Object {$_.LastWriteTime -ge $cutoff} |
        ForEach-Object {
            $file=$_; $zoneId=Get-ZoneId $file.FullName; if ($zoneId -eq $null) {return}
            $sha256=""; try{$sha256=(Get-FileHash $file.FullName -Algorithm SHA256 -EA Stop).Hash}catch{}
            $sig="N/A"; try{$sig=(Get-AuthenticodeSignature $file.FullName -EA Stop).Status}catch{}
            $sev=if($zoneId -ge 3){"HIGH"}elseif($zoneId -ge 2){"MED"}else{"INFO"}
            Add-Finding -Severity $sev -TechniqueID "T1105" -Technique "Internet-Sourced File" `
                -Artifact $file.Name `
                -Detail "Zone: $(Get-ZoneLabel $zoneId) (ZoneId=$zoneId) | Modified: $($file.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')) | Size: $([math]::Round($file.Length/1KB,1))KB | Sig: $sig | SHA256: $sha256" `
                -Path $file.FullName | Out-Null
            Print-Finding ($script:Findings[-1])
        }
}

Print-Section "RMM Tool Footprints (T1219)"
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\*' -EA SilentlyContinue |
    Where-Object {$_.PSChildName -match $rmmPat -or ($_.ImagePath -and $_.ImagePath -match $rmmPat)} |
    ForEach-Object {
        $sev=if($_.ImagePath -match '\\Temp\\|\\AppData\\|\\Users\\Public\\'){"HIGH"}else{"MED"}
        Add-Finding -Severity $sev -TechniqueID "T1219" -Technique "RMM Service" `
            -Artifact "Service: $($_.PSChildName)" `
            -Detail "ImagePath: $($_.ImagePath) | Start: $($_.Start)" -Path $_.ImagePath | Out-Null
        Print-Finding ($script:Findings[-1])
    }
@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
  'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*') | ForEach-Object {
    Get-ItemProperty $_ -EA SilentlyContinue |
        Where-Object {$_.DisplayName -match $rmmPat} |
        ForEach-Object {
            Add-Finding -Severity "MED" -TechniqueID "T1219" -Technique "RMM Installed Software" `
                -Artifact "App: $($_.DisplayName)" `
                -Detail "Version: $($_.DisplayVersion) | Publisher: $($_.Publisher) | InstallDate: $($_.InstallDate)" `
                -Path $_.InstallLocation | Out-Null
            Print-Finding ($script:Findings[-1])
        }
}

Print-Section "Suspicious Task XML LOLBin References"
$taskRoot="$env:WINDIR\System32\Tasks"
$lolRex='rundll32\.exe|mshta\.exe|regsvr32\.exe|wscript\.exe|cscript\.exe|certutil\.exe|bitsadmin\.exe|forfiles\.exe'
if (Test-Path $taskRoot) {
    Get-ChildItem -Path $taskRoot -Recurse -File -EA SilentlyContinue |
        Where-Object {$_.LastWriteTime -ge $cutoff} | ForEach-Object {
            $f=$_; try{$xml=[xml](Get-Content -Raw $f.FullName -EA Stop)}catch{return}
            foreach ($x in @($xml.Task.Actions.Exec)) {
                $cmd=("$($x.Command) $($x.Arguments)").Trim()
                if ($cmd -match $lolRex) {
                    $sev=if($cmd -match 'mshta|wscript|cscript|-Enc|http'){"HIGH"}else{"MED"}
                    Add-Finding -Severity $sev -TechniqueID "T1053.005" -Technique "Task LOLBin" `
                        -Artifact $f.Name `
                        -Detail "Modified: $($f.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')) | Command: $cmd" `
                        -Path $f.FullName | Out-Null
                    Print-Finding ($script:Findings[-1])
                }
            }
        }
}

Print-Banner "RESULTS"; Print-AllFindings; Export-AllFindings $OutputPath
