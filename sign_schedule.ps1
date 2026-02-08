# Check if running with administrator privileges
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script requires administrator privileges to register a scheduled task. Please run PowerShell as an administrator."
    return
}

$ScriptPath = Join-Path $PSScriptRoot "sign.ps1"

$PowerShellExe = if (Get-Command "pwsh.exe" -ErrorAction SilentlyContinue) { "pwsh.exe" } else { "powershell.exe" }

$actions = New-ScheduledTaskAction `
    -Execute $PowerShellExe `
    -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$ScriptPath`"" `
    -WorkingDirectory $PSScriptRoot

$Utc16 = [DateTime]::UtcNow.Date.AddHours(16) # 00:00 UTC+8
$LocalTime = $Utc16.ToLocalTime()
$AtTime = $LocalTime.ToString("HH:mm")

$triggers = @(
    (New-ScheduledTaskTrigger -Daily -At $AtTime),
    (New-ScheduledTaskTrigger -AtStartup)
)

$principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -RunLevel Limited

$settings = New-ScheduledTaskSettingsSet `
    -RunOnlyIfNetworkAvailable `
    -WakeToRun `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries

$task = New-ScheduledTask -Action $actions -Trigger $triggers -Settings $settings

Register-ScheduledTask 'AnimeAttendance' -InputObject $task -Force
