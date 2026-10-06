#!/bin/sh
# Smoke-test an image the way Compose runs it: read-only, no capabilities,
# unprivileged. Usage: scripts/smoke.sh IMAGE
set -eu

image=${1:?usage: scripts/smoke.sh IMAGE}
name="vinpatel-org-smoke-$$"
port=18080
base="http://127.0.0.1:$port"

fail() {
	echo "smoke: $*" >&2
	docker logs "$name" >&2 2>&1 || true
	exit 1
}

user=$(docker image inspect -f '{{.Config.User}}' "$image")
[ "$user" = "65534:65534" ] || fail "image user is '$user', want 65534:65534"

docker run -d --rm --name "$name" \
	-p "127.0.0.1:$port:8080" \
	-e DOH_URL= \
	--read-only --cap-drop ALL --security-opt no-new-privileges:true \
	"$image" >/dev/null
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT

tries=0
until [ "$(docker inspect -f '{{.State.Health.Status}}' "$name" 2>/dev/null)" = healthy ]; do
	tries=$((tries + 1))
	[ "$tries" -le 30 ] || fail "container not healthy after 30s"
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

curl -fsS -H 'Host: mta-sts.vinpatel.org' "$base/.well-known/mta-sts.txt" | grep -q '^mode: testing' ||
	fail "MTA-STS policy missing"

[ "$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: www.vinpatel.org' "$base/")" = 308 ] ||
	fail "www does not redirect"

echo "smoke: ok"
