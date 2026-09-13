# Detections: Privileged Role Assignment & Service Principal Credential Added

Day 07 target: three detections — privileged role assignment, service principal credential added, storage exfiltration — each with a documented FP profile, built by reading a real Microsoft rule first and stealing its structure.

Storage exfiltration is [Day 06](../day06-sas-exfiltration/README.md) — this doc covers the other two.

---

## Detection 1: Azure RBAC Elevate Access

**Technique:** `azure.privilege-escalation.root-user-access-administrator` (Stratus Red Team)
**Reference:** [Azure Threat Research Matrix AZT402](https://microsoft.github.io/Azure-Threat-Research-Matrix/PrivilegeEscalation/AZT402/AZT402/), [Permiso: Azure's Apex Permissions](https://permiso.io/blog/azures-apex-permissions-elevate-access-the-logs-security-teams-overlook), [Invictus-IR](https://www.invictus-ir.com/nieuws/the-azure-log-you-probably-didnt-know-existed)
**MITRE ATT&CK:** T1078 — Valid Accounts (Privilege Escalation)

### What it does

A Global Administrator can call the `elevateAccess` REST API to grant themselves the User Access Administrator role at the tenant **root scope (`/`)** — control over every subscription and management group in the tenant, not just the one they're working in. It's a legitimate Microsoft "break glass" mechanism (documented [here](https://learn.microsoft.com/en-us/azure/role-based-access-control/elevate-access-global-admin)), but also a well-known privilege escalation path if a Global Admin account is compromised.

### Finding: invisible to `AzureActivity`, visible in `AuditLogs`

Detonating the technique confirmed the reference articles' whole point: this action produces **zero events in `AzureActivity`**, even unfiltered, even at the subscription level where the diagnostic setting is wired. The action operates at the tenant root scope, above any single subscription, so a subscription-scoped `AzureActivity` diagnostic setting never sees it — a gap that would be easy to miss if you only monitor subscription activity logs.

It does show up in Entra ID's `AuditLogs` (already flowing via `entra-to-law`):

| TimeGenerated (UTC) | Category | OperationName | Result |
|---|---|---|---|
| 2026-09-12T09:10:00.28Z | `AzureRBACRoleManagementElevateAccess` | User has elevated their access to User Access Administrator for their Azure Resources | success |

Action-to-log lag: ~1.3 seconds (detonation completed 09:09:59 UTC).

Notable field: `InitiatedBy.user.agentType` was `"notAgentic"` — a relatively new Entra schema field distinguishing human-initiated actions from AI-agent-initiated ones. Worth watching as agentic identity becomes its own audit dimension.

### Stolen structure

Read Microsoft's own built-in Sentinel template for this exact technique (`Azure RBAC (Elevate Access)`, rule ID `132fdff4-c044-4855-a390-c1b71e0f833b`) before writing anything. Adopted directly from it:
- Filtering on the stable `Category == "AzureRBACRoleManagementElevateAccess"` field rather than only the display string (display strings can change; category is a stable enum-like field)
- Severity **High** — Microsoft treats this as a break-glass action, not routine
- MITRE mapping **T1078** (Valid Accounts) — not T1548.005 as guessed before checking; Microsoft's own template is the sourced answer here, not a guess

### Detection

```kql
AuditLogs
| where Category =~ "AzureRBACRoleManagementElevateAccess"
| where OperationName =~ "User has elevated their access to User Access Administrator for their Azure Resources"
| extend Actor = tostring(InitiatedBy.user.userPrincipalName)
| extend IPAddress = tostring(InitiatedBy.user.ipAddress)
| project TimeGenerated, Actor, OperationName, IPAddress, Result
```

Deployed as a Sentinel Scheduled Analytics Rule with Account/IP entity mapping. ARM template: `sentinel-rule-azure-rbac-elevate-access.json`. Re-detonated to validate — **Incident #2** fired, High severity, entities correctly attached to both the account and IP.

### False-positive profile

Genuinely low. Elevating to User Access Administrator at root scope is Microsoft's documented emergency-access mechanism for a true admin lockout — not something done as part of routine operations. A real deployment should treat every firing as requiring immediate justification (a change ticket, an incident, a support case), and pair the alert with a follow-up check that the role assignment is removed promptly (as our own `stratus revert` does). The only expected legitimate trigger is a genuine break-glass event, which should be rare enough that any occurrence merits investigation regardless.

---

## Detection 2: Service Principal Credential Added

**Technique:** `entra-id.persistence.backdoor-application-sp` (Stratus Red Team)
**Reference:** [Microsoft: Threat actors misuse OAuth applications](https://www.microsoft.com/en-us/security/blog/2023/12/12/threat-actors-misuse-oauth-applications-to-automate-financially-driven-attacks/), [SpecterOps: Azure Privilege Escalation via Service Principal Abuse](https://posts.specterops.io/azure-privilege-escalation-via-service-principal-abuse-210ae2be2a5)
**MITRE ATT&CK:** T1098.001 — Account Manipulation: Additional Cloud Credentials (Persistence)

### What it does

Backdoors an existing Entra ID application by adding a new client secret to its associated service principal — giving an attacker a standing, re-usable credential to authenticate as that application via `client_credentials` grant, independent of any user session.

### Finding

Detonation produced a clean, single-line audit event distinct from the warm-up noise (app/SP creation, owner assignment):

| TimeGenerated (UTC) | Category | OperationName | Result |
|---|---|---|---|
| 2026-09-13T08:34:43.57Z | `ApplicationManagement` | Add service principal credentials | success |

Action-to-log lag: ~2 seconds (detonation completed 08:34:45 UTC).

### Detection

```kql
AuditLogs
| where Category == "ApplicationManagement"
| where OperationName == "Add service principal credentials"
| extend Actor = tostring(InitiatedBy.user.userPrincipalName)
| extend IPAddress = tostring(InitiatedBy.user.ipAddress)
| project TimeGenerated, Actor, OperationName, IPAddress, Result
```

Deployed as a Sentinel Scheduled Analytics Rule, Medium severity, Account/IP entity mapping. ARM template: `sentinel-rule-sp-credential-added.json`. Re-detonated to validate — **Incident #3** fired.

### False-positive profile

This is the weak rule of the three, and worth saying so plainly rather than dressing it up. Unlike elevate-access, adding a credential to a service principal is a **routine, frequent action** in any real tenant — CI/CD pipelines rotate secrets, DevOps teams renew client secrets, third-party app admins do this as part of normal operations. As written, this rule would generate significant noise in production. It's honest evidence that the detection logic works against the specific technique, not a production-ready rule.

To make it usable in production, it would need additional context this lab doesn't have: correlating against a known allowlist of service accounts that legitimately rotate credentials, flagging credentials added by a principal who isn't a registered owner of that app, or flagging when credential-add happens unusually soon after the app/SP's own creation (the pattern our own attack incidentally produced — SP created, then backdoored ~70 seconds later — though that's an artifact of the lab's warm-up needing to create a fresh app, not necessarily how a real attacker would time it against an existing app).

---

## Data sources

- `AuditLogs` (Entra ID Directory Audit Logs, tenant-level diagnostic setting `entra-to-law`) — both detections in this doc
- `AzureActivity` — confirmed **not** a viable data source for Detection 1; included here as a documented negative result, not an oversight
