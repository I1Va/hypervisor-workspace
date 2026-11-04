# Launch the COM1 keepalive so it survives the SSH session closing.
#
# Start-Process from an SSH command inherits the session's job object, so the
# child is killed when the session ends. WMI's Win32_Process::Create starts the
# process outside that job, which is what we need for a background helper.
$script = Join-Path $env:USERPROFILE 'com1_keepalive.ps1'
Write-Output ("script=" + $script + " exists=" + (Test-Path $script))

$cmd = 'powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "' + $script + '"'
$r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = $cmd }
Write-Output ("returnValue=" + $r.ReturnValue + " pid=" + $r.ProcessId)

Start-Sleep -Seconds 5
$procs = Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -like '*com1_keepalive*' }
Write-Output ("keepalive running=" + (@($procs).Count))
