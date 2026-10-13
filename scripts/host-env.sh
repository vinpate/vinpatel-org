#!/bin/sh
# Delivers the secrets cloud-init leaves out, so they never enter Terraform
# state or instance metadata: the rendered .env and a GHCR login for the
# private image. Then runs the first update instead of waiting for the
# hourly timer. Rerun after Terraform replaces the instance.
# Usage: scripts/host-env.sh HOST
set -eu

host=${1:?usage: scripts/host-env.sh HOST}
target="ubuntu@$host"

# Captured first: sh has no pipefail, and a failed op must not leave an
# empty .env on the host.
env=$(op inject -i "$(dirname "$0")/../.env.tpl")
ghcr_token=$(op read op://vinpatel-org/ghcr-read-token/credential)

ssh "$target" cloud-init status --wait >/dev/null
printf '%s\n' "$env" | ssh "$target" 'sudo install -m 600 /dev/stdin /opt/vinpatel-org/.env'
printf '%s\n' "$ghcr_token" | ssh "$target" 'sudo docker login ghcr.io -u vinpate --password-stdin'
ssh "$target" 'sudo systemctl start vinpatel-org-update.service'
echo "host-env: $host is up to date"
