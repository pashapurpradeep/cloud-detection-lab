# Attacks

Every detection in `/detections` was built against a real emulated attack (Stratus Red Team) or, where detonating the real technique carried unacceptable account risk, against the documented schema and explicitly labelled as such. No technique here was run against anything but this lab's own subscription.

| Technique | Tool | MITRE ATT&CK | Detection | Data source | Validated by |
|---|---|---|---|---|---|
| SAS token blob export | Stratus Red Team: `azure.exfiltration.storage-sas-export` | T1530 — Data from Cloud Storage | [`sas-token-blob-read.json`](../detections/sas-token-blob-read.json) | `StorageBlobLogs` | Re-detonation, Incident #1 |
| Elevate Access (root-scope privilege escalation) | Stratus Red Team: `azure.privilege-escalation.root-user-access-administrator` | T1078 — Valid Accounts | [`azure-rbac-elevate-access.json`](../detections/azure-rbac-elevate-access.json) | `AuditLogs` | Re-detonation, Incident #2 |
| Service principal credential backdoor | Stratus Red Team: `entra-id.persistence.backdoor-application-sp` | T1098.001 — Additional Cloud Credentials | [`sp-credential-added.json`](../detections/sp-credential-added.json) | `AuditLogs` | Re-detonation, Incident #3 |
| Diagnostic setting deletion | Manual (delete/recreate `activity-to-law` via Azure Portal) | T1562.008 — Impair Defenses: Disable Cloud Logs | [`diagnostic-setting-deleted.json`](../detections/diagnostic-setting-deleted.json) | `AzureActivity` | Manual recreation, Incident #4 |
| Unusual-region sign-in with legacy auth | Not detonated — schema-built | T1078 — Valid Accounts | [`unusual-region-signin-legacy-auth.json`](../detections/unusual-region-signin-legacy-auth.json) | `SigninLogs` | Syntax-validated against real data only; **not** attack-validated |

## Notes

- The diagnostic-setting-deletion technique was tested manually rather than via Stratus Red Team, by directly deleting and recreating the subscription's own Activity Log export. Two rounds of testing this produced a genuinely surprising result — deleting the export did not create the blind spot expected, at gap durations up to ~2.5 minutes — documented honestly in [`docs/day08-disabled-diagnostic-logging.md`](../docs/day08-disabled-diagnostic-logging.md) rather than forced into a "gap found and closed" narrative that the evidence didn't support.
- The legacy-auth detection was deliberately not attack-validated: reproducing it needs a real foreign-IP, legacy-protocol sign-in against a live personal account, which risks real account lockout or fraud flags. Built from `SigninLogs`' documented schema and validated for correctness against real sign-in data instead. Its false-positive profile in the write-up is stated as unverified for exactly this reason.
- Two of the five rules (service principal credential, unusual-region sign-in) are explicitly documented as too noisy for production as written — see each write-up's False-Positive Profile section. Every rule here proves detection logic works against a specific technique; not every rule is production-ready, and the write-ups say which is which.
