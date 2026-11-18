#!/bin/sh
# Tell Honeybadger how a CI run on main ended. A pass reports the check-in,
# so a check-in that stops reporting alerts once its grace period is over.
# Anything else sends an error notice, which alerts at once. One fingerprint
# per check-in groups repeated failures into one error until it is resolved.
# Needs only the project's ingestion key, from HONEYBADGER_API_KEY.
# Usage: scripts/report.sh OUTCOME CHECK_IN_SLUG MESSAGE
set -eu

usage="usage: scripts/report.sh OUTCOME CHECK_IN_SLUG MESSAGE"
outcome=${1:?$usage}
slug=${2:?$usage}
message=${3:?$usage}
key=${HONEYBADGER_API_KEY:?HONEYBADGER_API_KEY is empty; add the repository secret}
api=https://api.honeybadger.io/v1

if [ "$outcome" = success ]; then
	curl -fsS -m 10 --retry 5 -o /dev/null "$api/check_in/$key/$slug"
	exit 0
fi

jq -n --arg slug "$slug" --arg message "$message" '{
	notifier: {name: "vinpatel-org report.sh", url: "https://github.com/vinpate/vinpatel-org", version: "1"},
	error: {
		class: "CI failure",
		message: $message,
		fingerprint: $slug,
		backtrace: [{file: "scripts/report.sh", number: "1", method: $slug}]
	},
	server: {environment_name: "production"}
}' | curl -fsS -m 10 --retry 5 -o /dev/null --data-binary @- \
	-H "X-API-Key: $key" -H "Content-Type: application/json" -H "Accept: application/json" \
	"$api/notices"
