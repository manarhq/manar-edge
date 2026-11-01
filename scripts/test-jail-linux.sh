#!/bin/sh
# Runs the Linux egress filter integration test in a throwaway privileged container: its own
# network namespace (the host's rules are untouched), the host's real cgroup hierarchy.
# Needs docker. Usage: scripts/test-jail-linux.sh
set -eu
cd "$(dirname "$0")/.."
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
CGO_ENABLED=0 go test -c -tags jail -o "$out/jail.test" ./internal/jail
docker run --rm --privileged --cgroupns=host -v "$out:/t:ro" ubuntu:24.04 sh -c \
  'apt-get update -qq >/dev/null && apt-get install -y -qq nftables iproute2 >/dev/null && cp /t/jail.test /jail.test && /jail.test -test.v'
# The exec-event watcher only listens, but the kernel's proc connector serves the initial network and pid namespaces.
docker run --rm --privileged --network host --pid host -e JAIL_HOSTNS=1 -v "$out:/t:ro" ubuntu:24.04 \
  sh -c 'cp /t/jail.test /jail.test && /jail.test -test.v -test.run TestWatchExec'
