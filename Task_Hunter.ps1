Add-Type -AssemblyName System.Windows.Forms, System.Drawing

# Build form
$form = New-Object System.Windows.Forms.Form
$form.Text            = 'VeilHuntUI TruePositive Hunter'
$form.ClientSize      = New-Object System.Drawing.Size(620,520)
$form.StartPosition   = 'CenterScreen'
$form.FormBorderStyle = 'FixedDialog'
$form.MaximizeBox     = $false

# Panel for checkboxes
$panel = New-Object System.Windows.Forms.Panel
$panel.Size       = New-Object System.Drawing.Size(280,440)
$panel.Location   = New-Object System.Drawing.Point(10,10)
$panel.AutoScroll = $true
$form.Controls.Add($panel)

# Results text box
$ResultsBox = New-Object System.Windows.Forms.TextBox
$ResultsBox.Multiline  = $true
$ResultsBox.ScrollBars = 'Vertical'
$ResultsBox.ReadOnly   = $true
$ResultsBox.WordWrap   = $true
$ResultsBox.Font       = New-Object System.Drawing.Font('Consolas',10)
$ResultsBox.Location   = New-Object System.Drawing.Point(300,10)
$ResultsBox.Size       = New-Object System.Drawing.Size(310,440)
$form.Controls.Add($ResultsBox)

# Technique mapping
$techniques = [ordered]@{
    'Scheduled Tasks (T1053.005)' = 'Hunt-ScheduledTasks'
}

# Whitelist pattern
$trustedTaskPaths = '\\Microsoft\\Windows\\'
  
# Helper to log
function Log {
    param($line)
    $ResultsBox.AppendText("$line`r`n")
    Write-Host $line
}

# Tuned Scheduled‑Tasks hunt
function Hunt-ScheduledTasks {
    Log "`n[Scheduled Tasks — Tuned for Evil]"

    try {
        schtasks.exe /Query /V /FO CSV |
        ConvertFrom-Csv |
        Where-Object {
            $folder = $_.'Folder'
            $action = $_.'Task To Run'
            $author = $_.'Author'
            # Exclude Microsoft OS tasks
            $folder -notlike "$trustedTaskPaths*" -and
            # Encoded PowerShell or odd install paths
            ($action -match '-EncodedCommand' -or $action -match '\\Users\\|\\Temp\\|\\AppData\\') -and
            # Not authored by system/admin
            ($author -notmatch 'SYSTEM|Administrators|TrustedInstaller')
        } |
        ForEach-Object {
            $name    = $_.'TaskName'
            $folder  = $_.'Folder'
            $nextRun = $_.'Next Run Time'
            $author  = $_.'Author'
            $action  = $_.'Task To Run'
            Log "Task: $folder$name | NextRun: $nextRun | Author: $author | Action: $action"
        }
    } catch {
        Log 'Failed to enumerate scheduled tasks'
    }
}

# Add checkbox and button
$cb = New-Object System.Windows.Forms.CheckBox -Property @{
    Text     = 'Scheduled Tasks (T1053.005)'
    AutoSize = $true
    Location = New-Object System.Drawing.Point(10,10)
}
$panel.Controls.Add($cb)

$btnRun     = New-Object System.Windows.Forms.Button -Property @{
    Text     = 'Run'
    Size     = New-Object System.Drawing.Size(120,30)
    Location = New-Object System.Drawing.Point(10,460)
}
$form.Controls.Add($btnRun)

$btnRun.Add_Click({
    Clear-Host; $ResultsBox.Clear()
    if ($cb.Checked) { Hunt-ScheduledTasks }
})

# Show UI
$form.Add_Shown({ $form.Activate() })
[void]$form.ShowDialog()
