#!/bin/sh
# Build hv_trace.exe on the DTB and put it next to vmaware.exe.
#
# The guest has no C compiler, so the tool is compiled in place with the C#
# compiler that ships in the .NET Framework directory. Uploading the source and
# invoking csc.exe directly avoids the quoting problems that nested SSH plus the
# Cyrillic profile path create.
#
# Usage: tools/deploy_hv_trace.sh
set -e

HOST="192.168.3.67"
USER="Арсений"
PASS="user"
SRC="tools/hv_trace.cs"

SSH="sshpass -p $PASS ssh -p 22 -o ConnectTimeout=8 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $USER@$HOST"

echo "uploading $SRC"
sshpass -p "$PASS" scp -P 22 -o ConnectTimeout=8 -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null "$SRC" "$USER@$HOST:Desktop/hv_trace.cs"

echo "compiling on guest"
$SSH 'cmd /c "cd /d %USERPROFILE%\Desktop && %WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe /nologo /target:exe /out:hv_trace.exe hv_trace.cs"' 2>&1 | grep -v "Warning: Permanently added" || true

echo "verifying"
$SSH 'cmd /c "cd /d %USERPROFILE%\Desktop && hv_trace.exe 0"' 2>&1 | grep -v "Warning: Permanently added"
