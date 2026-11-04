# Diagnose why the Com1KeepAlive scheduled task did not run.
$t = Get-ScheduledTask -TaskName 'Com1KeepAlive' -ErrorAction SilentlyContinue
if (-not $t) { Write-Output "task MISSING"; exit }
$i = $t | Get-ScheduledTaskInfo
Write-Output ("state=" + $t.State)
Write-Output ("lastRunTime=" + $i.LastRunTime)
Write-Output ("lastTaskResult=" + $i.LastTaskResult + " (0x" + ('{0:X}' -f $i.LastTaskResult) + ")")
Write-Output ("numberOfMissedRuns=" + $i.NumberOfMissedRuns)
Write-Output ("principal=" + $t.Principal.UserId + " logonType=" + $t.Principal.LogonType)

Write-Output "=== sessions ==="
query user 2>&1 | Select-Object -First 10

Write-Output "=== keepalive procs ==="
$p = Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -like '*com1_keepalive*' }
Write-Output ("count=" + (@($p).Count))
