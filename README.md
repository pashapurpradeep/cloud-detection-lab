# Cloud Detection Lab

A hands-on cloud security and detection engineering portfolio, built to demonstrate practical skills across Azure security tooling, Kubernetes runtime security, IaC policy-as-code, and applied AI security research. Work in progress, target complete by 1 November 2026.

## Status: 5 detections live (Azure / Sentinel)

Every rule below was built by reading a real Microsoft Sentinel detection template first and stealing its structure — field choices, severity, MITRE mapping — before writing anything from scratch. Each was validated against a real emulated attack (Stratus Red Team) where that was safe to do, and each write-up states its false-positive profile honestly, including where a rule is lab-proof-of-concept rather than production-ready.

| # | Detection | MITRE ATT&CK | Write-up |
|---|---|---|---|
| 1 | SAS token blob read | T1530 | [`docs/day06-sas-exfiltration.md`](docs/day06-sas-exfiltration.md) |
| 2 | Azure RBAC Elevate Access | T1078 | [`docs/day07-privilege-escalation-and-persistence.md`](docs/day07-privilege-escalation-and-persistence.md) |
| 3 | Service principal credential added | T1098.001 | [`docs/day07-privilege-escalation-and-persistence.md`](docs/day07-privilege-escalation-and-persistence.md) |
| 4 | Diagnostic setting deleted | T1562.008 | [`docs/day08-disabled-diagnostic-logging.md`](docs/day08-disabled-diagnostic-logging.md) |
| 5 | Unusual-region sign-in, legacy auth | T1078 | [`docs/day08-disabled-diagnostic-logging.md`](docs/day08-disabled-diagnostic-logging.md) |

See [`attacks/README.md`](attacks/README.md) for the full technique-to-detection mapping, including which detections were attack-validated versus schema-built.

## Repo structure

    /detections   Sentinel Analytics Rule ARM templates (KQL + rule config), one per detection
    /attacks      Techniques used, MITRE mapping, and how each detection was validated
    /docs         Full write-up per day: what was tested, what was found, what it demonstrates

## What this will contain (planned)

- **Cloud security**: Azure resources provisioned with Terraform, Entra ID and Azure activity logging piped to a Log Analytics workspace, reviewed against the Azure Threat Research Matrix.
- **Kubernetes / container runtime security**: a local `kind` cluster running Kubernetes Goat, with Falco/Tetragon runtime detections against known container-escape and lateral-movement TTPs.
- **IaC and policy-as-code**: Checkov and Trivy scanning on the Terraform in this repo, with OPA/Rego policies enforced via Conftest.
- **AI security research**: applied research (not production experience) on LLM attack surfaces, referencing the OWASP Top 10 for LLM Applications and MITRE ATLAS, using tools such as garak and promptfoo.

## Note

This is independent lab work for portfolio purposes — no employer, client, or NDA-covered material appears here.
