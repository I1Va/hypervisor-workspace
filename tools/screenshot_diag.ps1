# One-shot diagnostics: who is logged on, which sessions exist, can we reach a desktop.
$ErrorActionPreference = 'Continue'

"pid=$PID session=" + (Get-Process -Id $PID).SessionId

"--- explorer ---"
$ex = @(Get-Process explorer -ErrorAction SilentlyContinue)
if ($ex.Count -eq 0) { "none" } else { $ex | ForEach-Object { "explorer pid=" + $_.Id + " session=" + $_.SessionId } }

"--- logged on user ---"
"computer.UserName=" + (Get-CimInstance Win32_ComputerSystem).UserName

"--- sessions (query.exe) ---"
$q = Join-Path $env:SystemRoot 'System32\query.exe'
"exists=" + (Test-Path $q)
if (Test-Path $q) { & $q session 2>&1 | Out-String }

"--- logon sessions type 2/10 ---"
Get-CimInstance Win32_LogonSession -ErrorAction SilentlyContinue |
    Where-Object { $_.LogonType -eq 2 -or $_.LogonType -eq 10 } |
    ForEach-Object { "logonid=" + $_.LogonId + " type=" + $_.LogonType + " start=" + $_.StartTime }

"--- autologon ---"
$k = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
$v = Get-ItemProperty $k
"AutoAdminLogon=" + $v.AutoAdminLogon + " DefaultUserName=" + $v.DefaultUserName + " DefaultDomainName=" + $v.DefaultDomainName

"--- screen metrics in this session ---"
Add-Type -AssemblyName System.Windows.Forms
try {
    $b = [System.Windows.Forms.SystemInformation]::VirtualScreen
    "virtualscreen=" + $b.Width + "x" + $b.Height
} catch { "metrics failed: " + $_.Exception.Message }

"--- done ---"
