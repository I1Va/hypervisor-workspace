param()
# Run the full VMAware suite and capture every line of output.
#
# The isolated "--disable <everything else>" runs are unreliable here: a bad or
# unsupported token makes VMAware exit immediately, which looks like a clean
# result. Running the whole suite matches what a person actually does and gives
# the authoritative per-technique verdicts.
$ErrorActionPreference = 'Continue'
Set-Location "$env:USERPROFILE\Desktop"
Remove-Item -Force -ErrorAction SilentlyContinue fullres.txt
$start = Get-Date
$out = & .\vmaware.exe 2>&1
$end = Get-Date
$secs = [math]::Round(($end - $start).TotalSeconds, 1)
$out | Out-File -Encoding ascii fullres.txt
"=== seconds=$secs" | Out-File -Append -Encoding ascii fullres.txt
