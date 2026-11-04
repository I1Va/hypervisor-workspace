param([string]$Disable)
$ErrorActionPreference = 'Continue'
Set-Location "$env:USERPROFILE\Desktop"
Remove-Item -Force -ErrorAction SilentlyContinue hhres.txt
$start = Get-Date
try {
    $out = & .\vmaware.exe -d --disable $Disable 2>&1
} catch {
    $out = "launch-error: $($_.Exception.Message)"
}
$end = Get-Date
$secs = [math]::Round(($end - $start).TotalSeconds, 1)
$text = ($out | Out-String).Trim()
"result=$text" | Out-File -Encoding ascii hhres.txt
"seconds=$secs" | Out-File -Append -Encoding ascii hhres.txt
