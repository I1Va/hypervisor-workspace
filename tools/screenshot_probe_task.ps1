# Probe: identity, then whether schtasks /it lands in the desktop session.
$ErrorActionPreference = 'Continue'

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$pr = New-Object Security.Principal.WindowsPrincipal $id
"user=" + $id.Name
"elevated=" + $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$body = Join-Path $env:USERPROFILE 'screenshot_task_body.ps1'
"body exists=" + (Test-Path $body)

$log = Join-Path $env:USERPROFILE 'shot_task.log'
if (Test-Path $log) { Remove-Item $log -Force }

$tr = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "' + $body + '" -Out "' + (Join-Path $env:USERPROFILE 'shot.png') + '"'
"creating task"
$out = & schtasks /create /tn DtbShotProbe /tr $tr /sc once /st 00:00 /ru $env:USERNAME /it /f 2>&1
"create rc=$LASTEXITCODE :: " + ($out -join ' | ')

$out = & schtasks /run /tn DtbShotProbe 2>&1
"run rc=$LASTEXITCODE :: " + ($out -join ' | ')

$deadline = (Get-Date).AddSeconds(25)
while ((Get-Date) -lt $deadline -and -not (Test-Path $log)) { Start-Sleep -Milliseconds 500 }

$t = Get-ScheduledTaskInfo -TaskName DtbShotProbe -ErrorAction SilentlyContinue
"lastResult=0x" + ('{0:X}' -f $t.LastTaskResult)

if (Test-Path $log) { Get-Content $log | ForEach-Object { "BODY: $_" } } else { "BODY: no log" }

& schtasks /delete /tn DtbShotProbe /f 2>&1 | Out-Null
