# Cloud Detection Lab

A hands-on cloud security and detection engineering portfolio, built to demonstrate
practical skills across Azure security tooling, Kubernetes runtime security, IaC
policy-as-code, and applied AI security research. Work in progress, target complete
by 1 November 2026.

## What this will contain

- **Detection engineering**: KQL detection rules in Microsoft Sentinel, mapped to
  MITRE ATT&CK, tested against attacks emulated with Stratus Red Team and Atomic Red Team.
- **Cloud security**: Azure resources provisioned with Terraform, Entra ID and
  Azure activity logging piped to a Log Analytics workspace, reviewed against the
  Azure Threat Research Matrix.
- **Kubernetes / container runtime security**: a local `kind` cluster running
  Kubernetes Goat, with Falco/Tetragon runtime detections against known
  container-escape and lateral-movement TTPs.
- **IaC and policy-as-code**: Checkov and Trivy scanning on the Terraform in this
  repo, with OPA/Rego policies enforced via Conftest.
- **AI security research**: applied research (not production experience) on LLM
  attack surfaces, referencing the OWASP Top 10 for LLM Applications and MITRE
  ATLAS, using tools such as garak and promptfoo.

## Status

Early build. See commit history for progress. Each component ships with its own
README covering what was tested, what was found, and what it demonstrates.

## Note

This is independent lab work for portfolio purposes — no employer, client, or
NDA-covered material appears here.
