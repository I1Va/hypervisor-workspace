# Capture the desktop of the logged-on DTB session and print it as a PNG.
#
# Why this is not a one-liner: SSH logins on the DTB land in session 0, and
# CopyFromScreen there fails with "The handle is invalid" because session 0 has
# no desktop. The interactive desktop lives in session 1 (explorer.exe). So the
# capture is delegated to a one-shot scheduled task created with /IT, which
# Windows runs inside the logged-on session.
#
# The image is streamed back over HTTP rather than through SSH stdout or scp:
# scp -O and sftp both fail against this guest ("invalid user name" /
# "Permission denied"), and base64 through stdout is far slower than a single
# POST. The host side is tools/screenshot.sh, which starts a one-shot receiver.
#
# Usage:
#   powershell -File screenshot.ps1 -Url http://192.168.3.13:8099/shot.png
#   powershell -File screenshot.ps1 -Out C:\Users\me\shot.png      (file only)

param(
    [string]$Url = '',
    [string]$Out = (Join-Path $env:USERPROFILE 'shot.png'),
    [int]$WaitSeconds = 25
)

$log = Join-Path $env:USERPROFILE 'screenshot.log'
function Log([string]$m) {
    Add-Content -Path $log -Value ((Get-Date -Format 'HH:mm:ss') + ' ' + $m)
}

# The task body does the actual grab; it is uploaded next to this script.
$body = Join-Path (Split-Path -Parent $PSCommandPath) 'screenshot_task_body.ps1'
if (-not (Test-Path $body)) {
    Write-Output ('FAIL missing ' + $body)
    exit 1
}

$me = Get-Process -Id $PID
Log ('start session=' + $me.SessionId + ' out=' + $Out)

if (Test-Path $Out) { Remove-Item $Out -Force }

# One task per capture keeps concurrent runs from fighting over one task name.
$taskName = 'DtbShot' + (Get-Random -Maximum 100000)

$tr = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "' + $body + '" -Out "' + $Out + '"'
& schtasks /create /tn $taskName /tr $tr /sc once /st 00:00 /ru $env:USERNAME /it /f 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Log 'schtasks create failed'
    Write-Output 'FAIL schtasks create failed (need an admin session and a logged-on user)'
    exit 1
}
& schtasks /run /tn $taskName 2>&1 | Out-Null

# The task body writes the PNG last, so existence means the file is complete.
$deadline = (Get-Date).AddSeconds($WaitSeconds)
while ((Get-Date) -lt $deadline -and -not (Test-Path $Out)) { Start-Sleep -Milliseconds 250 }

& schtasks /delete /tn $taskName /f 2>&1 | Out-Null

if (-not (Test-Path $Out)) {
    Log 'no file produced'
    Write-Output ('FAIL no file after ' + $WaitSeconds + 's; see ' + (Join-Path $env:USERPROFILE 'shot_task.log'))
    exit 1
}

$bytes = (Get-Item $Out).Length
Log ('captured bytes=' + $bytes)

if (-not $Url) {
    Write-Output ('SHOT ' + $Out + ' ' + $bytes)
    exit 0
}

# --data-binary keeps curl from doing any form encoding on a binary file.
$curl = Join-Path $env:SystemRoot 'System32\curl.exe'
$res = & $curl -s -S --max-time 120 -X POST --data-binary "@$Out" -H 'Content-Type: application/octet-stream' $Url 2>&1
if ($LASTEXITCODE -ne 0) {
    Log ('curl failed: ' + ($res -join ' '))
    Write-Output ('FAIL upload: ' + ($res -join ' '))
    exit 1
}

Log ('uploaded ' + $bytes)
Write-Output ('SHOT ' + $Out + ' ' + $bytes + ' uploaded')
