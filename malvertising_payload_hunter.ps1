param([int]$LookbackDays=7)
$cut=(Get-Date).AddDays(-$LookbackDays)
$ext=@('*.msi','*.exe','*.dll','*.iso','*.lnk','*.js','*.vbs','*.hta','*.ps1','*.zip')
$roots = @("$env:USERPROFILE\Downloads","$env:USERPROFILE\Desktop","$env:TEMP")
function Get-ZoneId([string]$p){
  $ads="$p:Zone.Identifier"; if(Test-Path $ads){ try{ (Get-Content $ads -Raw) -match 'ZoneId=(\d+)' | Out-Null; return [int]$Matches[1] }catch{}}; return $null
}
"== Recent internet-sourced files (ZoneId=3) =="
foreach($r in $roots){
  if(-not (Test-Path $r)) { continue }
  Get-ChildItem $r -Recurse -Include $ext -ErrorAction SilentlyContinue |
    Where-Object LastWriteTime -ge $cut |
    ForEach-Object {
      $z = Get-ZoneId $_.FullName
      if($z -eq 3){
        $sha = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
        [pscustomobject]@{When=$_.LastWriteTime; File=$_.FullName; SHA256=$sha}
      }
    } | Sort-Object When -Descending | Format-Table -Auto
}

"== RMM footprint (services) =="
$Rmm='AnyDesk','ScreenConnect','Atera','Splashtop','RustDesk','TeamViewer','ZohoAssist'
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\*' -ErrorAction SilentlyContinue |
  ? { $_.PSChildName -match ($Rmm -join '|') -or ($_.ImagePath -match ($Rmm -join '|')) } |
  Select PSChildName, ImagePath | Format-Table -Auto

"== Suspicious Scheduled Tasks updated recently =="
$tasks="$env:WINDIR\System32\Tasks"
if(Test-Path $tasks){
  Get-ChildItem $tasks -Recurse -ErrorAction SilentlyContinue |
    ? LastWriteTime -ge $cut |
    ForEach-Object {
      try{ $xml=[xml](Get-Content -Raw $_.FullName) }catch{ $xml=$null }
      if($xml){
        $cmd=($xml.Task.Actions.Exec.Command + ' ' + $xml.Task.Actions.Exec.Arguments).Trim()
        if($cmd -match 'rundll32\.exe|mshta\.exe|powershell\.exe|wscript\.exe|cscript\.exe'){
          [pscustomobject]@{Task=$_.FullName; Modified=$_.LastWriteTime; Command=$cmd}
        }
      }
    } | Format-Table -Auto
}
