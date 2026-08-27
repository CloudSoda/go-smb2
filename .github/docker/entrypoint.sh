#!/bin/sh
# Create the test user, then run smbd in the foreground so the container
# lives exactly as long as the server does.
set -eu

addgroup -S smbgroup 2>/dev/null || true
adduser -S -D -H -G smbgroup "$SMB_USER" 2>/dev/null || true

printf '%s\n%s\n' "$SMB_PASSWORD" "$SMB_PASSWORD" | smbpasswd -a -s "$SMB_USER"
smbpasswd -e "$SMB_USER"

mkdir -p /share
chmod 0777 /share

exec smbd --foreground --no-process-group --debug-stdout
