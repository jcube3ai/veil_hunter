try{
  Get-WinEvent -LogName System -FilterXPath "*[System[(EventID=7045)]]" -MaxEvents 400 |
    Select TimeCreated, Id, @{n='Message';e={$_.Message -replace '\r?\n',' '}} | Format-Table -Auto
}catch{}
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\*' -Name ImagePath -ErrorAction SilentlyContinue |
  Where-Object { $_.ImagePath -match '\\Users\\|\\AppData\\|\\ProgramData\\|\\Temp\\' } |
  Select PSChildName, ImagePath | Format-Table -Auto
