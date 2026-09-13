# Detection: Disabled Diagnostic Logging

Day 08 target: detect an attacker disabling the subscription's Activity Log export — MITRE T1562.008 (Impair Defenses: Disable Cloud Logs) — and characterise what a real "logging blackout" attack actually achieves against this environment.

**MITRE ATT&CK:** T1562.008 — Impair Defenses: Disable Cloud Logs
**Data source:** `AzureActivity` (subscription-level diagnostic setting `activity-to-law`)

## Hypothesis and what actually happened

The obvious attacker move against a monitored subscription is to delete the diagnostic setting that exports `AzureActivity` to Log Analytics, do something during the resulting gap, then quietly recreate it — expecting the interval in between to be a genuine blind spot.

Tested this directly rather than assuming it: deleted and recreated `activity-to-law` twice, at increasing gap lengths, and checked what landed in Log Analytics.

**Round 1** — 48-second gap (delete 11:24:23 BST → recreate 11:25:11 BST). Both the delete and the recreate of the diagnostic setting itself appeared in `AzureActivity`, with the same ~1.5-2s ingestion lag seen throughout this project. The deletion action did not hide itself.

**Round 2** — deliberately longer gap to test whether an *unrelated* action performed strictly inside the deleted window would be lost, not just the deletion event itself. Sequence: deleted `activity-to-law` (11:35:47 BST) → added a tag to `rg-detection-lab` ~70 seconds later, while the setting was still deleted (11:36:57 BST) → recreated the setting 2m37s after the delete (11:38:24 BST). The tag-write landed in `AzureActivity` in `law-detection-lab` regardless — despite occurring squarely inside a window where no diagnostic setting existed at all. Confirmed the query was run against the correct workspace before treating this as real (a workspace mix-up was caught and corrected mid-investigation — see below).

Notably, the recreate step in round 2 was accidentally pointed at a different, unrelated Log Analytics workspace rather than `law-detection-lab` — yet the earlier tag-write (which happened before that misconfigured recreate) still landed correctly in `law-detection-lab`. That rules out "recreating the setting backfills recent events to wherever it currently points" as the explanation, since if that were the mechanism the tag-write would have gone to the wrong workspace instead.

**Conclusion:** across two independent tests, deleting the subscription's Activity Log diagnostic setting for up to ~2.5 minutes did not produce an observable blind spot for either the deletion event itself or an unrelated action performed during the gap. The underlying mechanism is not confirmed — Azure's activity-log pipeline appears to hold or route data independently of the diagnostic setting's live state at the moment of the event, but that is an observation, not a documented, sourced explanation, and it isn't asserted as one here. This is a genuinely more useful finding than a clean "gap found and closed" story: it shows the original attacker-model assumption didn't survive testing, at these gap durations, in this environment.

This does not mean disabling logging is harmless — a longer-duration, sustained deletion (hours, not minutes) was not tested, and a sufficiently patient attacker who leaves the setting deleted rather than restoring it quickly still achieves a real, permanent loss of everything that would have been captured while it stayed off. What was disproven is the narrower "quick delete/restore leaves no trace" theory.

## Detection: alert on the deletion itself

Regardless of whether a gap materialises, deleting a diagnostic setting is rare, deliberate, and worth alerting on in its own right — including as a leading indicator, since a defender wants to know the moment logging coverage changes, not after confirming whether an attacker got lucky with timing.

```kql
AzureActivity
| where OperationNameValue =~ "MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/DELETE"
| where ActivityStatusValue == "Success"
| extend Actor = tostring(Caller)
| extend IPAddress = tostring(CallerIpAddress)
| project TimeGenerated, Actor, IPAddress, OperationNameValue, ActivityStatusValue
```

Deployed as a Sentinel Scheduled Analytics Rule ("Diagnostic Setting Deleted - Detection Lab", Medium severity, Defense Evasion/T1562.008, 5-minute schedule/lookback, threshold > 0, Account/IP entity mapping). Re-triggered by deleting `activity-to-law` again — **Incident #4** fired, entities correctly attached.

## False-positive profile

Legitimate diagnostic setting deletions do happen — and this investigation produced two real examples of exactly that: workspace migrations, retention policy changes, or (as happened here) correcting a misconfigured destination all involve deleting and recreating a diagnostic setting as routine admin work. A production version of this rule needs either a change-ticket correlation or a short allow-list window around planned infrastructure changes; as written, every firing should still be checked, but "an admin was doing legitimate workspace maintenance" is a real, expected cause, not just a theoretical one.

## Data sources

- `AzureActivity` (subscription-level diagnostic setting `activity-to-law`) — deletion/recreation events and the gap tests
- Confirmed **not** a source of a real blind spot at the gap durations tested (≤2.5 minutes) — a documented negative result

## Operational note

During this investigation, `activity-to-law` was briefly and accidentally pointed at an unrelated Log Analytics workspace during a recreate step (caused by a workspace-name collision with unrelated concurrent work, not by this technique). Caught and corrected before validating the detection rule. Worth flagging as a real risk in any environment where multiple people or automation touch diagnostic settings: a recreate action silently succeeding against the wrong destination is easy to miss without spot-checking the target workspace.

---

# Detection: Unusual-Region Sign-In with Legacy Auth

**MITRE ATT&CK:** T1078 — Valid Accounts (Initial Access)
**Data source:** `SigninLogs` (Entra ID)

## Approach: schema-built, not attack-validated

Unlike Detections 1-4, this one was **not** validated by detonating a real attack. Simulating this technique means either a real sign-in from a foreign IP using a legacy protocol (VPN/proxy plus scripted IMAP/SMTP auth) or a compromised-looking event against a real personal Microsoft Entra tenant — both carry real account-risk (conditional access lockout, fraud flags, or genuinely alarming the tenant's own security signals) that isn't worth it for a lab detection. Built the query directly from `SigninLogs`' documented schema instead, and validated it against real sign-in data for syntax correctness only.

Legacy authentication protocols (`IMAP4`, `POP3`, `Exchange ActiveSync`, `Authenticated SMTP`, `MAPI over HTTP`, etc.) predate modern auth and cannot enforce MFA — a well-documented initial-access path once a credential is phished or leaked, since MFA never gets a chance to block it. Pairing that with a country outside the account's expected range narrows it from "legacy protocol used" (which can be legitimate for old integrations) to "legacy protocol used somewhere it shouldn't be."

Confirmed the account's own schema first:

```kql
SigninLogs
| take 20
| project TimeGenerated, UserPrincipalName, AppDisplayName, ClientAppUsed, ResultType, LocationDetails, AuthenticationRequirement
```

All real sign-ins so far: `ClientAppUsed = "Browser"`, `LocationDetails.countryOrRegion = "GB"`, `AuthenticationRequirement = "singleFactorAuthentication"` (worth a separate note: this tenant currently has no MFA enforced on the account — a real finding, unrelated to this detection, worth acting on outside this lab).

## Limitation: static allow-list, not a real baseline

"Unusual region" here means "not GB" — a hardcoded allow-list, not a UEBA-style learned baseline. That's an honest simplification for a single-user lab tenant with no travel history to learn from. In production this would need either Entra ID Protection's own risk signals (which already model this) or a proper historical baseline per user rather than a static country list.

## Detection

```kql
SigninLogs
| where ResultType == "0"
| where ClientAppUsed in ("Exchange ActiveSync", "Authenticated SMTP", "IMAP4", "IMAP", "MAPI Over HTTP", "Offline Address Book", "Outlook Anywhere (RPC over HTTP)", "POP3", "POP", "Reporting Web Services", "Exchange Web Services", "Other clients")
| extend Country = tostring(LocationDetails.countryOrRegion)
| where Country != "GB"
| project TimeGenerated, UserPrincipalName, AppDisplayName, ClientAppUsed, Country, IPAddress, ResultType
```

Deployed as a Sentinel Scheduled Analytics Rule ("Unusual Region Sign-In with Legacy Auth - Detection Lab", Medium severity, Initial Access/T1078, 5-minute schedule/lookback, threshold > 0, Account/IP entity mapping). Query returns zero rows against current real data, as expected — confirms syntax and schema correctness, not detection efficacy against a real attack.

## False-positive profile

Cannot be assessed empirically here since the rule has never fired against real attacker behaviour. On paper: legitimate legacy-auth use (an old scanner/printer using SMTP auth, a third-party integration still on IMAP, an admin travelling) would both trigger this. A production deployment needs a real allow-list of known legacy-auth integrations and their expected source IPs/countries before this is usable, not just a country check.

## Data sources

- `SigninLogs` (Entra ID, tenant-level diagnostic setting `entra-to-law` — same pipe used for Detections 1-2)
