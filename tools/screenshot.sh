#!/usr/bin/env bash
# Grab a screenshot of the DTB's desktop and save it locally.
#
#   tools/screenshot.sh [output.png]
#
# Why this is a script and not one ssh line: SSH logins on the DTB run in
# session 0, where CopyFromScreen fails with "The handle is invalid" because
# session 0 has no desktop. The desktop lives in session 1 (explorer.exe), so
# the capture is done by a one-shot scheduled task created with /IT.
#
# The image comes back over HTTP: scp -O and sftp both fail against this guest
# ("invalid user name" / "Permission denied"), and base64 through stdout took
# ~30 s for 2 MB. One POST is a single transfer and is checked by size.
set -u

HOST="192.168.3.67"
USER_NAME="Арсений"
PASS="user"
HOST_IP="192.168.3.13"
PORT="${SCREENSHOT_PORT:-8099}"

SSH_OPTS=(-p 22 -o ConnectTimeout=15 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null)
SCP_OPTS=(-P 22 -o ConnectTimeout=15 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null)

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${1:-/tmp/opencode/shots/shot-$(date +%Y%m%d-%H%M%S).png}"
mkdir -p "$(dirname "$OUT")"

REMOTE_DIR="C:/Users/$USER_NAME"
URL="http://$HOST_IP:$PORT/$(basename "$OUT")"
RECV_DIR="$(mktemp -d /tmp/opencode/recv.XXXXXX)"

cleanup() { [ -n "${SRV_PID:-}" ] && kill "$SRV_PID" 2>/dev/null; }
trap cleanup EXIT

# One-shot receiver: takes exactly one POST, writes it under its basename, exits.
python3 - "$PORT" "$RECV_DIR" <<'PY' &
import http.server, os, sys

port, out_dir = int(sys.argv[1]), sys.argv[2]

class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        name = os.path.basename(self.path.lstrip("/")) or "upload.bin"
        data = self.rfile.read(n)
        with open(os.path.join(out_dir, name), "wb") as fh:
            fh.write(data)
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")
        # Single transfer: nothing else is expected.
        self.server.done = True

    def log_message(self, *args):
        pass

srv = http.server.HTTPServer(("0.0.0.0", port), Handler)
srv.done = False
while not srv.done:
    srv.handle_request()
PY
SRV_PID=$!
sleep 0.5

echo "pushing capture scripts"
sshpass -p "$PASS" scp "${SCP_OPTS[@]}" \
    "$HERE/screenshot.ps1" "$HERE/screenshot_task_body.ps1" \
    "$USER_NAME@$HOST:$REMOTE_DIR/" >/dev/null 2>&1 || {
    echo "FAIL upload of capture scripts" >&2
    exit 1
}

echo "capturing to $URL"
sshpass -p "$PASS" ssh -T "${SSH_OPTS[@]}" "$USER_NAME@$HOST" \
    "powershell -NoProfile -ExecutionPolicy Bypass -File C:\\Users\\$USER_NAME\\screenshot.ps1 -Url $URL -Out C:\\Users\\$USER_NAME\\shot.png" \
    2>/dev/null | tr -d '\r'

# The remote side only returns after curl finished, but allow the write to land.
for _ in $(seq 1 40); do
    if [ -s "$RECV_DIR/$(basename "$OUT")" ]; then break; fi
    sleep 0.25
done

GOT="$RECV_DIR/$(basename "$OUT")"
if [ ! -s "$GOT" ]; then
    echo "FAIL no image received (is $HOST_IP reachable from the DTB, port $PORT open?)" >&2
    exit 1
fi

mv "$GOT" "$OUT"
echo "saved $OUT ($(stat -c %s "$OUT") bytes)"
