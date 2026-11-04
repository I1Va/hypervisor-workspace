# Stop Windows from power-gating COM1.
#
# Diagnosis: once Windows owns the machine, every COM1 register reads 0xFF,
# which is what an undecoded I/O port returns. The UART is not misprogrammed,
# it is powered down (D3). Holding a handle open brings it back to D0 and the
# hypervisor's log resumes immediately.
#
# PnPCapabilities = 0x18 clears the D0/D3 power-management bits for the device,
# so the PnP manager stops suspending it when idle.
foreach ($id in @('ACPI\PNP0501\0', 'ACPI\PNP0501\1')) {
    $path = "HKLM:\SYSTEM\CurrentControlSet\Enum\$id\Device Parameters"
    if (Test-Path $path) {
        $old = (Get-ItemProperty -Path $path -Name PnPCapabilities -ErrorAction SilentlyContinue).PnPCapabilities
        Set-ItemProperty -Path $path -Name PnPCapabilities -Value 0x18 -Type DWord -ErrorAction SilentlyContinue
        $new = (Get-ItemProperty -Path $path -Name PnPCapabilities -ErrorAction SilentlyContinue).PnPCapabilities
        Write-Output "$id old=$old new=$new"
    } else {
        Write-Output "$id MISSING"
    }
}
