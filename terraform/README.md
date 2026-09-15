# Terraform — cloud-detection-lab

Deploys the same environment documented in `/docs`: resource group, Log
Analytics workspace, Sentinel, three log sources (AzureActivity, Entra
sign-in/audit logs, StorageBlobLogs), and all 5 analytics rules currently
in `/detections`.

Written retroactively from the actual ARM template exports already
committed to `/detections` — the queries, severities, and entity mappings
here are copied verbatim from those files, not rewritten. This closes the
gap between the CV/README claim ("provisioned with Terraform") and what
was actually in the repo, which — as of 14 Sept 2026 — was nothing.

## Before you run this

1. `az login`, then either `az account set --subscription <student-subscription-id>`
   or `export AZURE_SUBSCRIPTION_ID=<student-subscription-id>` (same variable
   Stratus Red Team needs — worth exporting it once and keeping it set for
   the rest of the session).
2. Confirm you're pointed at the **Azure for Students** subscription, not
   the old free-trial one: `az account show --query id -o tsv`.
3. `terraform init`

## Running it

```
terraform plan
terraform apply
```

Nothing here needs variable overrides to match the original lab — the
defaults in `variables.tf` reproduce the same names (`rg-detection-lab`,
`law-detection-lab`, uksouth). If the old lab is still live in the same
tenant when you run this, that's fine: resource group and workspace names
only need to be unique within the target subscription, and the Entra
diagnostic setting is deliberately named `entra-to-law-students-lab` so it
doesn't collide with the original `entra-to-law`.

## Two things to check once it's up, not assumed

- **Sentinel's own 31-day free-ingestion trial.** Whether a brand-new
  workspace under a different subscription gets a fresh one wasn't
  something I could confirm from documentation — check the Sentinel
  pricing/cost blade in the portal after `apply` finishes rather than
  assuming either way.
- **Entra P1/P2 licensing for SigninLogs.** Unresolved in the original lab
  and not fixed by this move — Azure for Students credit explicitly
  excludes Entra ID Premium. `AzureActivity`/`AuditLogs` remain the
  reliable fallback if `SigninLogs` stops exporting.

## Re-validating the rules

The rules deploy already `enabled = true`, but only rule 1 (SAS token) and
rule 5 (unusual-region sign-in) can be re-validated safely without a real
account-risk action:

- Rule 1: re-run Stratus Red Team's `azure.exfiltration.storage-sas-export`
  against the `testdata` container in the new storage account (see
  `storage_account_name` output).
- Rule 5 stays schema-built, same as before — don't try to attack-validate
  it against a live personal account.

Rules 2–4 (RBAC elevate access, service principal credential, diagnostic
setting deletion) can be re-detonated the same way as the original lab
(Stratus Red Team for 2 and 3, manual portal delete/recreate for 4) if you
want fresh incident screenshots from this subscription specifically —
optional, since the existing Day 06–08 evidence in the repo remains valid
regardless of which subscription is currently live.

## Once this is committed

Update the CV/README Terraform claim from aspirational to real, and add a
line to `claude/JOB_SEARCH_STATE.md`'s progress log noting the migration
and the date.
