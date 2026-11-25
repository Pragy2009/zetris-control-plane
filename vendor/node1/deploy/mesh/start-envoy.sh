#!/bin/sh
set -eu
address="$(cat /run/netbird/mesh-ip)"
printf '%s\n' "$address" | awk -F. 'NF != 4 || $1 != 100 || $2 < 64 || $2 > 127 || $3 < 0 || $3 > 255 || $4 < 0 || $4 > 255 { exit 1 }'
umask 077
sed "s/__MESH_IP__/$address/g" /config/envoy.json > /tmp/envoy.json
exec envoy -c /tmp/envoy.json --log-level warning
