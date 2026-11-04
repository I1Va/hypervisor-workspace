# Verify the COM1 keepalive is alive and holding the port.
$procs = Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -like '*com1_keepalive*' }
Write-Output ("keepalive processes=" + (@($procs).Count))

foreach ($p in @($procs)) {
    Write-Output ("  pid=" + $p.ProcessId)
}

# A successful second open means nothing holds the port, so the keepalive is
# not doing its job.
$result = 'unknown'
try {
    $sp = New-Object System.IO.Ports.SerialPort 'COM1', 115200, 'None', 8, 'One'
    $sp.Open()
    $result = 'FREE (keepalive not holding)'
    $sp.Close()
} catch {
    $result = 'HELD (' + $_.Exception.Message.Trim() + ')'
}
Write-Output ("port state=" + $result)
