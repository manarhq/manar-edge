#!/bin/sh
# Fails unless the docker-archive image tarball $1 holds usr/local/bin/manar-edge-gateway with a
# security.capability xattr (cap_net_admin+ep, set in the Dockerfile). Without it the gateway runs
# but cannot configure wg0, so a lost xattr must fail the build, not ship a signed image.
# busybox sh/tar/gzip only (runs in the buildkit image).
set -eu
d="$(mktemp -d)"
trap 'rm -rf "$d"' EXIT
tar -xf "$1" -C "$d"
for f in $(find "$d" -type f ! -name '*.json'); do
  { gzip -dc "$f" 2>/dev/null || cat "$f"; } >"$d/layer"
  if grep -aq 'usr/local/bin/manar-edge-gateway' "$d/layer" \
    && grep -aq 'SCHILY.xattr.security.capability=' "$d/layer"; then
    echo "file capability present on /usr/local/bin/manar-edge-gateway"
    exit 0
  fi
done
echo "no security.capability xattr on /usr/local/bin/manar-edge-gateway in $1" >&2
exit 1
