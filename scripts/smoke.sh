#!/bin/sh
# Smoke-test a server binary over loopback: health, the page, its headers
# and the www redirect. With COMMIT, /trace must also report that build.
# Usage: scripts/smoke.sh BINARY [COMMIT]
set -eu

bin=${1:?usage: scripts/smoke.sh BINARY [COMMIT]}
want=${2:-}
port=18080
base="http://127.0.0.1:$port"
log=$(mktemp)

LISTEN="127.0.0.1:$port" DOH_URL= "$bin" >"$log" 2>&1 &
pid=$!
trap 'kill "$pid" 2>/dev/null || true; rm -f "$log"' EXIT

fail() {
	echo "smoke: $*" >&2
	cat "$log" >&2
	exit 1
}

tries=0
until LISTEN="127.0.0.1:$port" "$bin" -healthcheck 2>/dev/null; do
	tries=$((tries + 1))
	[ "$tries" -le 30 ] || fail "not healthy after 30s"
	sleep 1
done

[ "$(curl -fsS -H 'Host: vinpatel.org' "$base/healthz")" = ok ] || fail "/healthz did not return ok"

page=$(curl -fsS -H 'Host: vinpatel.org' \
	-H 'CF-Ray: 8c1f2a3b4d5e6f70-SJC' -H 'X-Edge-Proto: HTTP/3' -H 'X-Edge-Tls: TLSv1.3' \
	"$base/")
echo "$page" | grep -q 'SJC · ray 8c1f2a3b4d5e6f70-SJC' || fail "page does not reflect CF-Ray"
echo "$page" | grep -q 'HTTP/3 · TLSv1.3' || fail "page does not reflect the protocol"

headers=$(curl -fsS -o /dev/null -D - -H 'Host: vinpatel.org' "$base/")
for h in strict-transport-security content-security-policy x-content-type-options \
	x-frame-options referrer-policy permissions-policy \
	cross-origin-opener-policy cross-origin-resource-policy; do
	echo "$headers" | grep -qi "^$h:" || fail "missing header $h"
done
if echo "$headers" | grep -qi '^server:'; then
	fail "Server header present"
fi

[ "$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: www.vinpatel.org' "$base/")" = 308 ] ||
	fail "www does not redirect"

if [ -n "$want" ]; then
	got=$(curl -fsS -H 'Host: vinpatel.org' "$base/trace" | jq -er .build.version) ||
		fail "/trace has no build.version"
	[ "$got" = "$want" ] || fail "/trace reports build $got, want $want"
fi

echo "smoke: ok"
