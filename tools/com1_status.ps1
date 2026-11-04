# Report COM1 device state and power-management settings.
Write-Output "=== devices ==="
Get-PnpDevice -Class Ports -ErrorAction SilentlyContinue |
    ForEach-Object { Write-Output ($_.Status + " | " + $_.InstanceId + " | " + $_.ProblemDescription) }

Write-Output "=== registry ==="
foreach ($id in @('ACPI\PNP0501\0', 'ACPI\PNP0501\1')) {
    $p = "HKLM:\SYSTEM\CurrentControlSet\Enum\$id\Device Parameters"
    if (Test-Path $p) {
        $caps = (Get-ItemProperty -Path $p -Name PnPCapabilities -ErrorAction SilentlyContinue).PnPCapabilities
        Write-Output "$id PnPCapabilities=$caps"
    } else {
        Write-Output "$id MISSING"
    }
}

Write-Output "=== open test ==="
try {
    $p = New-Object System.IO.Ports.SerialPort COM1, 115200, [System.IO.Ports.Parity]::None, 8, [System.IO.Ports.StopBits]::One
    $p.Open()
    Write-Output "open=OK"
    Start-Sleep -Seconds 3
    $p.Close()
} catch {
    Write-Output ("open=FAIL " + $_.Exception.Message)
}

Write-Output "=== power requests ==="
powercfg /requests 2>&1 | Select-Object -First 20
