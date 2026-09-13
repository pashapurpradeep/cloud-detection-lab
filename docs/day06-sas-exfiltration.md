# Detection Gap: SAS Token Blob Exfiltration

**Technique:** `azure.exfiltration.storage-sas-export` (Stratus Red Team)
**Reference:** [Azure Threat Research Matrix AZT701.2](https://microsoft.github.io/Azure-Threat-Research-Matrix/Impact/AZT701/AZT701-2/)
**MITRE ATT&CK:** T1530 — Data from Cloud Storage (Collection)
**Environment:** `law-detection-lab` (Azure Sentinel, Log Analytics), provisioned with Terraform

## Objective

Run a cloud-native exfiltration technique against a hardened storage account (anonymous blob access disabled) and confirm what a defender would actually see in Sentinel, then measure how quickly it appears.

## Finding 1: the technique is invisible by default

Detonating the technique generates two categories of Azure API call: an ARM/control-plane call (`Microsoft.Storage/storageAccounts/listkeys/action`, needed to mint the SAS token) and a data-plane call against the Storage Blob REST API (the actual `GetBlob` download via the SAS URL).

With only a subscription-level `AzureActivity` diagnostic setting in place, only the control-plane call was visible:

| TimeGenerated (UTC) | OperationNameValue | ActivityStatusValue |
|---|---|---|
| 2026-09-11T10:01:51.56Z | `MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION` | Start |
| 2026-09-11T10:01:51.62Z | `MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION` | Success |

Action-to-log lag on that control-plane event: ~2 seconds (detonation ran at 10:01:49 UTC).

The actual exfiltration — the SAS-authenticated blob read — never appeared. `AzureActivity` only records ARM/control-plane operations; it has no visibility into data-plane calls against a storage account's blob endpoint. **A subscription wired only for `AzureActivity` cannot detect this technique at all**, regardless of retention or query design — the data simply isn't collected.

## Remediation

Enabled a `StorageBlobLogs` diagnostic setting (`blob-to-law`) on the storage account's blob service, forwarding `StorageRead` / `StorageWrite` / `StorageDelete` categories to `law-detection-lab`.

## Finding 2: closing the gap

Re-ran the technique after wiring the diagnostic setting. The blob read was captured:

| TimeGenerated (UTC) | AccountName | OperationName | AuthenticationType | RequesterObjectId | UserAgentHeader | CallerIpAddress |
|---|---|---|---|---|---|---|
| 2026-09-11T10:37:09.41Z | stratusredteamy2ut | GetBlob | SAS | *(empty)* | Go-http-client/1.1 | *(redacted)* |
| 2026-09-11T11:32:02.44Z | stratusredteamy2ut | GetBlob | SAS | *(empty)* | Go-http-client/1.1 | *(redacted)* |

Action-to-log lag once the diagnostic pipe was live: ~1.4 seconds (detonation at 10:37:08 UTC, log at 10:37:09.41 UTC). Note: the diagnostic setting itself took several minutes to become active after creation — a fresh setting does not retroactively capture events, and the first detonation immediately after creating it produced no results.

Key signal in the schema: SAS-authenticated access leaves no AAD identity (`RequesterObjectId` and `RequesterUpn` both empty) — the entire point of the technique is that it bypasses identity-based audit trails. Combined with a non-browser `UserAgentHeader`, this is a workable, if narrow, detection surface.

## Detection rule

```kql
StorageBlobLogs
| where OperationName in ("GetBlob", "GetBlobProperties")
| where AuthenticationType == "SAS"
| where isempty(RequesterObjectId)
| project TimeGenerated, AccountName, OperationName, CallerIpAddress, UserAgentHeader, Uri
```

Deployed as a Sentinel Scheduled Analytics Rule ("SAS Token Blob Read - Detection Lab", Medium severity, MITRE T1530, 5-minute schedule/lookback, threshold > 0). ARM template: `sentinel-rule-sas-token-blob-read.json` (exported from the rule, alongside this write-up).

**Result:** Incident #1 fired in Sentinel on re-detonation, generated entirely by traffic this lab produced.

## False-positive profile

`AuthenticationType == "SAS"` with an empty `RequesterObjectId` is not inherently malicious — legitimate SAS use (sharing a file with an external partner, a backup job, a CDN origin pull) produces the identical signature. Before this rule could run against a production account, it would need an IP/ASN or geography allow-list layered on top, or scoping to specific storage accounts/containers that have no legitimate SAS-sharing use case. As written, it is a lab-scale proof of detection logic, not a production-ready rule.

## Data sources

- `AzureActivity` (subscription-level diagnostic setting `activity-to-law`)
- `StorageBlobLogs` (resource-level diagnostic setting `blob-to-law` on the storage account's blob service)
