param([Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{32}$')][string]$RunId)
# Run the full VMAware suite and capture every line of output.
#
# The isolated "--disable <everything else>" runs are unreliable here: a bad or
# unsupported token makes VMAware exit immediately, which looks like a clean
# result. Capture may be incomplete without an interactive console, so the host
# treats a run with no captured detections as inconclusive.
$ErrorActionPreference = 'Stop'
Set-Location "$env:USERPROFILE\Desktop"
$result = "fullres-$RunId.txt"
$start = Get-Date
try {
    if (-not (Test-Path -LiteralPath '.\vmaware.exe')) { throw 'vmaware.exe is missing' }
    $out = & .\vmaware.exe 2>&1
    $exitCode = $LASTEXITCODE
    if ($null -eq $exitCode) { $exitCode = 1 }
} catch {
    $out = "suite failed: $_"
    $exitCode = 1
}
$end = Get-Date
$secs = [math]::Round(($end - $start).TotalSeconds, 1)
$out | Out-File -Encoding ascii $result
"=== seconds=$secs" | Out-File -Append -Encoding ascii $result
"=== complete=$RunId exit=$exitCode" | Out-File -Append -Encoding ascii $result
