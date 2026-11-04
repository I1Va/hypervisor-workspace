param([Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{32}$')][string]$RunId)
# Launch run_full_suite.ps1 outside the SSH job object so it survives the
# session dying while a slow technique runs.
$script = Join-Path $env:USERPROFILE 'Desktop\run_full_suite.ps1'
if (-not (Test-Path $script)) { Write-Output "missing=$script"; exit 1 }
$cmd = 'powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "' + $script + '" -RunId ' + $RunId
$r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = $cmd }
Write-Output ("returnValue=" + $r.ReturnValue + " pid=" + $r.ProcessId)
