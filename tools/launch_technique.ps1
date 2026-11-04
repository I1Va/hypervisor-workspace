param([string]$Disable)
# Start run_technique.ps1 outside the SSH job object, so the run survives the
# session dying (which it does, for the slow techniques).
$script = Join-Path $env:USERPROFILE 'Desktop\run_technique.ps1'
if (-not (Test-Path $script)) {
    Write-Output "missing=$script"
    exit 1
}
$cmd = 'powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "' +
       $script + '" -Disable "' + $Disable + '"'
$r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = $cmd }
Write-Output ("returnValue=" + $r.ReturnValue + " pid=" + $r.ProcessId)
