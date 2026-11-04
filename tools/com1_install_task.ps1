# Start the COM1 keepalive at boot, not at logon.
#
# The AtLogOn trigger never fired: this machine has AutoAdminLogon disabled, so
# there is no interactive logon for Task Scheduler to hook. The task sat at
# lastTaskResult=0x41303 ("has not yet run") forever.
#
# A boot trigger with S4U (run whether the user is logged on or not) starts the
# helper early and does not need a stored password. COM1 is a machine-wide
# device, not a per-session one, so opening it from a non-interactive session
# works fine.
$script = Join-Path $env:USERPROFILE 'com1_keepalive.ps1'
$user = $env:USERNAME
Write-Output ("script=" + $script + " exists=" + (Test-Path $script))
Write-Output ("user=" + $user)

$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument ('-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "' + $script + '"')

$trigger = New-ScheduledTaskTrigger -AtStartup
$trigger.Delay = 'PT15S'

$principal = New-ScheduledTaskPrincipal -UserId $user -LogonType S4U -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 5 -RestartInterval (New-TimeSpan -Minutes 1) `
    -StartWhenAvailable -MultipleInstances IgnoreNew

Unregister-ScheduledTask -TaskName 'Com1KeepAlive' -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName 'Com1KeepAlive' -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings -Force | Out-Null

$t = Get-ScheduledTask -TaskName 'Com1KeepAlive'
Write-Output ("registered=" + $t.State + " logon=" + $t.Principal.LogonType)
Write-Output ("trigger=" + $t.Triggers[0].CimClass.CimClassName + " delay=" + $t.Triggers[0].Delay)
