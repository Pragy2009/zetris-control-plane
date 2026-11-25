#!/bin/sh
set -eu
netbird status --check ready >/dev/null 2>&1
address="$(netbird status --ipv4)"
printf '%s\n' "$address" | awk -F. 'NF != 4 || $1 != 100 || $2 < 64 || $2 > 127 || $3 < 0 || $3 > 255 || $4 < 0 || $4 > 255 { exit 1 }'
umask 077
printf '%s\n' "$address" > /run/netbird/mesh-ip.new
mv /run/netbird/mesh-ip.new /run/netbird/mesh-ip
