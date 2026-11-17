#!/bin/sh
# Check the live site the way a mail server or an uptime check sees it: the
# page, /trace and the MTA-STS policy answer 200 with no Cloudflare
# challenge, and the page's own mail checks all match the declaration.
# Run from a datacenter, as the probe workflow does, it sees what those
# clients see. Prints each failure and exits 1 if there was any.
# Usage: scripts/probe.sh [DOMAIN]
set -eu

domain=${1:-vinpatel.org}
agent="vinpatel-org-probe (+https://github.com/vinpate/vinpatel-org)"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
failures=0

fail() {
	echo "probe: $*" >&2
	failures=$((failures + 1))
}

# expect_ok URL NAME: URL answers 200 with no challenge; the body is kept
# as $tmp/NAME.
expect_ok() {
	status=$(curl -sS -m 15 -A "$agent" -o "$tmp/$2" -D "$tmp/$2.headers" \
		-w '%{http_code}' "$1") || status=000
	[ "$status" = 200 ] || fail "$1 answered $status, want 200"
	if grep -qi '^cf-mitigated:' "$tmp/$2.headers" 2>/dev/null; then
		fail "$1 was challenged by Cloudflare"
	fi
}

expect_ok "https://$domain/" page
expect_ok "https://$domain/trace" trace
expect_ok "https://mta-sts.$domain/.well-known/mta-sts.txt" policy

head -n 1 "$tmp/policy" 2>/dev/null | grep -q '^version: STSv1' ||
	fail "the MTA-STS policy does not start with version: STSv1"

# The page compares live DNS with the mail posture it was built from. A
# verdict short of confirmed, or any check that does not match, is drift.
if ! jq -e '.mail.verdict == "confirmed" and ([.mail.checks[].match] | all)' \
	"$tmp/trace" >/dev/null 2>&1; then
	fail "/trace reports mail drift: $(jq -c '{verdict: .mail.verdict,
		unmatched: [.mail.checks | to_entries[] | select(.value.match != true) | .key]}' \
		"$tmp/trace" 2>/dev/null || echo 'no JSON')"
fi

[ "$failures" -eq 0 ] || exit 1
echo "probe: ok, build $(jq -r .build.version "$tmp/trace")"
