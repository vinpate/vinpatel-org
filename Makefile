ifeq ($(filter oneshell,$(.FEATURES)),)
$(error GNU make 3.82 or later is required)
endif

SHELL := bash
.SHELLFLAGS := -euo pipefail -c
.ONESHELL:
.DEFAULT_GOAL := help

TF         := terraform -chdir=infra
OP_RUN     := op run --env-file infra/op.env --
VAULT      := vinpatel-org
PLAN_ITEM  := terraform-plan
STATE_ITEM := terraform-state
STATE      := infra/terraform.tfstate
BACKUP     := op document edit "$(STATE_ITEM)" "$(STATE)" --vault "$(VAULT)"

.PHONY: help init check-state backup plan show apply

help: ## list the targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F ':.*## ' '{ printf "  %-12s %s\n", $$1, $$2 }'

init: ## install the providers
	$(TF) init

check-state: ## stop unless the 1Password backup matches the local state
	@tmp=$$(mktemp -d); trap 'rm -rf "$$tmp"' EXIT
	op document get "$(STATE_ITEM)" --vault "$(VAULT)" --out-file "$$tmp/backup.tfstate" >/dev/null
	if ! cmp -s "$(STATE)" "$$tmp/backup.tfstate"; then
		describe() { jq -r '"serial \(.serial), lineage \(.lineage)"' "$$1"; }
		echo "$(STATE) ($$(describe "$(STATE)")) differs from the $(STATE_ITEM) backup ($$(describe "$$tmp/backup.tfstate"))." >&2
		echo "If the local state is the newer one, run 'make backup'." >&2
		exit 1
	fi

backup: ## save the local state as the 1Password backup
	@$(BACKUP)

plan: check-state ## plan, and keep the plan in 1Password for apply
	@tmp=$$(mktemp -d); trap 'rm -rf "$$tmp"' EXIT
	$(OP_RUN) $(TF) plan -input=false -out="$$tmp/infra.tfplan"
	if op item get "$(PLAN_ITEM)" --vault "$(VAULT)" >/dev/null 2>&1; then
		op document edit "$(PLAN_ITEM)" "$$tmp/infra.tfplan" --vault "$(VAULT)"
	else
		op document create "$$tmp/infra.tfplan" --title "$(PLAN_ITEM)" --vault "$(VAULT)" >/dev/null
	fi
	echo "Kept as '$(PLAN_ITEM)' in the $(VAULT) vault; the file above is deleted on exit. 'make apply' applies exactly this plan."

show: ## print the plan kept in 1Password
	@tmp=$$(mktemp -d); trap 'rm -rf "$$tmp"' EXIT
	op document get "$(PLAN_ITEM)" --vault "$(VAULT)" --out-file "$$tmp/infra.tfplan" >/dev/null
	$(TF) show "$$tmp/infra.tfplan"

# A failed apply can still have changed the state, so the backup follows
# every apply; only a successful one retires the plan.
apply: ## apply the plan kept in 1Password, back up the state, then archive the plan
	@tmp=$$(mktemp -d); trap 'rm -rf "$$tmp"' EXIT
	op document get "$(PLAN_ITEM)" --vault "$(VAULT)" --out-file "$$tmp/infra.tfplan" >/dev/null
	status=0
	$(OP_RUN) $(TF) apply -input=false "$$tmp/infra.tfplan" || status=$$?
	$(BACKUP)
	if [ "$$status" -ne 0 ]; then exit "$$status"; fi
	op document delete "$(PLAN_ITEM)" --vault "$(VAULT)" --archive
