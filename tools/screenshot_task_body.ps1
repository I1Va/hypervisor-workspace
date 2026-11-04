# Runs inside the scheduled task (session 1) and grabs the desktop to a PNG.
#
# Kept separate from screenshot.ps1 because the task must invoke a script file
# with a simple command line: the Cyrillic profile path breaks anything that
# needs nested quoting through schtasks /tr.
param(
    [string]$Out = (Join-Path $env:USERPROFILE 'shot.png')
)

$log = Join-Path $env:USERPROFILE 'shot_task.log'
$lines = @()
$lines += 'pid=' + $PID + ' session=' + (Get-Process -Id $PID).SessionId + ' user=' + $env:USERNAME

try {
    Add-Type -AssemblyName System.Drawing
    Add-Type -AssemblyName System.Windows.Forms
    $b = [System.Windows.Forms.SystemInformation]::VirtualScreen
    $lines += 'virtualscreen=' + $b.Width + 'x' + $b.Height

    $bmp = New-Object System.Drawing.Bitmap $b.Width, $b.Height
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    try {
        $g.CopyFromScreen($b.Left, $b.Top, 0, 0, $b.Size)
    } finally {
        $g.Dispose()
    }

    # Write to a temp name and rename, so the caller never sees a partial PNG.
    $tmp = $Out + '.part'
    $bmp.Save($tmp, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Move-Item -Path $tmp -Destination $Out -Force
    $lines += 'capture=OK bytes=' + (Get-Item $Out).Length
} catch {
    $lines += 'capture=FAIL ' + $_.Exception.Message
}

Set-Content -Path $log -Value $lines
