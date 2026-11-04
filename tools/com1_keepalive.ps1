# Keep COM1 powered on for the whole session.
#
# Windows power-gates the legacy serial port when it is idle. Once that
# happens every COM1 register reads 0xFF and the hypervisor's debug log goes
# silent, exactly when it is most useful. Holding a handle open keeps the
# device in D0.
#
# It never reads or writes the port, so it cannot disturb the hypervisor's
# output.
#
# Every step is written to a log file next to this script, because this runs
# detached and there is no console to read: without the log, a silent failure
# looks exactly like "the fix did not work".
$log = Join-Path $env:USERPROFILE 'com1_keepalive.log'

function Write-Log([string]$Message) {
    $line = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + ' ' + $Message
    Add-Content -Path $log -Value $line
}

Write-Log 'starting'
Write-Log ('user=' + $env:USERNAME + ' pid=' + $PID)

try {
    # Plain strings, not [System.IO.Ports.Parity]::None: passing the enum text
    # through the constructor is taken literally and the cast fails, so the
    # port never opens and the device stays powered down.
    $port = New-Object System.IO.Ports.SerialPort 'COM1', 115200, 'None', 8, 'One'
    $port.Open()
    Write-Log ('opened isOpen=' + $port.IsOpen)
} catch {
    Write-Log ('open failed: ' + $_.Exception.Message)
    exit 1
}

# Hold the handle indefinitely. Nothing is ever read from the port.
while ($true) {
    Start-Sleep -Seconds 10
    if (-not $port.IsOpen) {
        Write-Log 'port closed; reopening'
        try {
            $port.Open()
            Write-Log 'reopened'
        } catch {
            Write-Log ('reopen failed: ' + $_.Exception.Message)
        }
    }
}
