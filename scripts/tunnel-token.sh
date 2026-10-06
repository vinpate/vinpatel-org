#!/bin/sh
# Copies the connector token of the tunnel declared in infra/ from the
# Cloudflare API into 1Password, so it never passes through Terraform state.
# "rotate" first sets a new tunnel secret; running connectors stay up until
# they restart.
# Usage: op run --env-file infra/op.env -- scripts/tunnel-token.sh [rotate]
set -eu

case "${1:-}" in
"" | rotate) ;;
*)
	echo "usage: $0 [rotate]" >&2
	exit 2
	;;
esac

: "${CLOUDFLARE_API_TOKEN:?run under op run --env-file infra/op.env}"
: "${TF_VAR_account_id:?run under op run --env-file infra/op.env}"

tunnel_id=$(terraform -chdir="$(dirname "$0")/../infra" output -raw tunnel_id)
api="https://api.cloudflare.com/client/v4/accounts/$TF_VAR_account_id/cfd_tunnel/$tunnel_id"

call() {
	curl -fsS -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" "$@"
}

if [ "${1:-}" = rotate ]; then
	printf '{"tunnel_secret":"%s"}' "$(openssl rand -base64 32)" |
		call -X PATCH -H "Content-Type: application/json" --data-binary @- "$api" >/dev/null
fi

response=$(call "$api/token")
token=$(printf '%s' "$response" | node -e 'process.stdout.write(JSON.parse(require("fs").readFileSync(0, "utf8")).result)')
op item edit tunnel-token --vault vinpatel-org "credential=$token" >/dev/null
echo "tunnel-token updated for tunnel $tunnel_id"
